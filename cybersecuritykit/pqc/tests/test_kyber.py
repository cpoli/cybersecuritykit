"""A Kyber-like KEM (Bos et al. 2018; FIPS 203, 2024), through the public API.

The FIPS 203 known-answer tests fix n = 256 and the NTT domain, so they cannot
check a toy ring of degree 16; these tests check the KEM's behavior instead:
agreement, compression bounds, determinism and implicit rejection.
"""

import dataclasses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pq = csk.pqc


def test_keys_have_the_module_shape():
    keys = pq.kyber_keygen(3, 16, seed=1)
    assert keys == pq.kyber_keygen(3, 16, seed=1)
    assert keys != pq.kyber_keygen(3, 16, seed=2)
    public = keys.public
    assert (public.k, public.n, len(public.rho)) == (3, 16, 32)
    assert len(public.t) == len(keys.s) == 3
    assert all(len(p) == 16 and all(0 <= c < 3329 for c in p) for p in public.t)
    # eta_1 = 2 for k = 3: secret coefficients lie in [-2, 2].
    assert all(-2 <= c <= 2 for p in keys.s for c in p)


@pytest.mark.parametrize(("k", "du", "dv"), [(2, 10, 4), (3, 10, 4), (4, 11, 5)])
def test_ciphertexts_are_compressed_to_du_and_dv_bits(k, du, dv):
    keys = pq.kyber_keygen(k, 16, seed=k)
    ciphertext = pq.kyber_encapsulate(keys.public, seed=0).ciphertext
    assert len(ciphertext.u) == k
    assert all(0 <= c < 2**du for p in ciphertext.u for c in p)
    assert all(0 <= c < 2**dv for c in ciphertext.v)


@settings(max_examples=25, deadline=None)
@given(st.sampled_from([2, 3, 4]), st.sampled_from([8, 16, 32]), st.integers(0, 10_000))
def test_both_sides_agree_on_a_32_byte_key(k, n, seed):
    keys = pq.kyber_keygen(k, n, seed=seed)
    sent = pq.kyber_encapsulate(keys.public, seed=seed + 1)
    assert len(sent.shared_key) == 32
    assert pq.kyber_decapsulate(keys, sent.ciphertext) == sent.shared_key


def test_tampered_ciphertexts_get_a_pseudorandom_key():
    keys = pq.kyber_keygen(2, 16, seed=5)
    sent = pq.kyber_encapsulate(keys.public, seed=6)
    u0 = sent.ciphertext.u[0]
    # One unit in the low bits of u still decrypts to the same message; the
    # Fujisaki-Okamoto re-encryption check rejects it anyway.
    bumped = ((u0[0] + 1) % 1024,) + u0[1:]
    forged = dataclasses.replace(sent.ciphertext, u=(bumped,) + sent.ciphertext.u[1:])
    other = dataclasses.replace(
        sent.ciphertext, v=((sent.ciphertext.v[0] + 1) % 16,) + sent.ciphertext.v[1:]
    )
    rejected = pq.kyber_decapsulate(keys, forged)
    assert rejected != sent.shared_key
    assert rejected == pq.kyber_decapsulate(keys, forged)
    assert pq.kyber_decapsulate(keys, other) not in (rejected, sent.shared_key)
    # The rejection key depends on the secret z; the honest key does not.
    swapped = dataclasses.replace(keys, z=bytes(32))
    assert pq.kyber_decapsulate(swapped, forged) != rejected
    assert pq.kyber_decapsulate(swapped, sent.ciphertext) == sent.shared_key


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pq.kyber_keygen(1, 16), ValueError),
        (lambda: pq.kyber_keygen(5, 16), ValueError),
        (lambda: pq.kyber_keygen(2, 4), ValueError),
        (lambda: pq.kyber_keygen(2, 24), ValueError),
        (lambda: pq.kyber_keygen(2, 16, seed=True), TypeError),
        (lambda: pq.kyber_encapsulate("key"), TypeError),
        (lambda: pq.kyber_encapsulate(pq.kyber_keygen(2, 16).public, seed="x"), TypeError),
        (lambda: pq.kyber_decapsulate("keys", None), TypeError),
        (lambda: pq.kyber_decapsulate(pq.kyber_keygen(2, 16), "ct"), TypeError),
        (
            lambda: pq.kyber_decapsulate(
                pq.kyber_keygen(2, 16), pq.KyberCiphertext(((0,) * 16,), (0,) * 16)
            ),
            ValueError,
        ),
        (
            lambda: pq.kyber_decapsulate(
                pq.kyber_keygen(2, 16), pq.KyberCiphertext(((0,) * 16, (0,) * 16), (0,) * 8)
            ),
            ValueError,
        ),
    ],
)
def test_kyber_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
