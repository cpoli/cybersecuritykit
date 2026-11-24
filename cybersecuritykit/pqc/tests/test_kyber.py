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

pqc = csk.pqc


def test_keys_have_the_module_shape():
    keys = pqc.kyber_keygen(3, 16, seed=1)
    assert keys == pqc.kyber_keygen(3, 16, seed=1)
    assert keys != pqc.kyber_keygen(3, 16, seed=2)
    public = keys.public
    assert (public.k, public.n, len(public.rho)) == (3, 16, 32)
    assert len(public.t) == len(keys.s) == 3
    assert all(len(p) == 16 and all(0 <= c < 3329 for c in p) for p in public.t)
    # eta_1 = 2 for k = 3: secret coefficients lie in [-2, 2].
    assert all(-2 <= c <= 2 for p in keys.s for c in p)


@pytest.mark.parametrize(("k", "du", "dv"), [(2, 10, 4), (3, 10, 4), (4, 11, 5)])
def test_ciphertexts_are_compressed_to_du_and_dv_bits(k, du, dv):
    keys = pqc.kyber_keygen(k, 16, seed=k)
    ciphertext = pqc.kyber_encapsulate(keys.public, seed=0).ciphertext
    assert len(ciphertext.u) == k
    assert all(0 <= c < 2**du for p in ciphertext.u for c in p)
    assert all(0 <= c < 2**dv for c in ciphertext.v)


@settings(max_examples=25, deadline=None)
@given(st.sampled_from([2, 3, 4]), st.sampled_from([8, 16, 32]), st.integers(0, 10_000))
def test_both_sides_agree_on_a_32_byte_key(k, n, seed):
    keys = pqc.kyber_keygen(k, n, seed=seed)
    sent = pqc.kyber_encapsulate(keys.public, seed=seed + 1)
    assert len(sent.shared_key) == 32
    assert pqc.kyber_decapsulate(keys, sent.ciphertext) == sent.shared_key


def test_tampered_ciphertexts_get_a_pseudorandom_key():
    keys = pqc.kyber_keygen(2, 16, seed=5)
    sent = pqc.kyber_encapsulate(keys.public, seed=6)
    u0 = sent.ciphertext.u[0]
    # One unit in the low bits of u still decrypts to the same message; the
    # Fujisaki-Okamoto re-encryption check rejects it anyway.
    bumped = ((u0[0] + 1) % 1024,) + u0[1:]
    forged = dataclasses.replace(sent.ciphertext, u=(bumped,) + sent.ciphertext.u[1:])
    other = dataclasses.replace(
        sent.ciphertext, v=((sent.ciphertext.v[0] + 1) % 16,) + sent.ciphertext.v[1:]
    )
    rejected = pqc.kyber_decapsulate(keys, forged)
    assert rejected != sent.shared_key
    assert rejected == pqc.kyber_decapsulate(keys, forged)
    assert pqc.kyber_decapsulate(keys, other) not in (rejected, sent.shared_key)
    # The rejection key depends on the secret z; the honest key does not.
    swapped = dataclasses.replace(keys, z=bytes(32))
    assert pqc.kyber_decapsulate(swapped, forged) != rejected
    assert pqc.kyber_decapsulate(swapped, sent.ciphertext) == sent.shared_key


def test_standard_noise_never_fails_in_a_simulation():
    # The noise stays far below q/4 = 832, so no bit flips (FIPS 203 bounds it by 2^-139).
    result = pqc.kyber_failure_rate(2, 16, trials=40, seed=3)
    assert (result.eta1, result.eta2, result.du, result.dv) == (3, 2, 10, 4)
    assert result.failures == result.bit_errors == 0
    assert result.rate == 0.0
    assert result.largest_noise < 3329 // 4


def test_wider_noise_makes_failures_measurable():
    result = pqc.kyber_failure_rate(2, 64, eta=32, trials=50, seed=1)
    assert (result.eta1, result.eta2) == (32, 32)
    assert 0 < result.failures <= result.bit_errors
    assert abs(result.rate - result.failures / 50) < 1e-10
    assert abs(result.bit_rate - result.bit_errors / (50 * 64)) < 1e-10
    # A bit flips only once its noise passes q/4.
    assert result.largest_noise > 3329 // 4
    assert result == pqc.kyber_failure_rate(2, 64, eta=32, trials=50, seed=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.failures = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pqc.kyber_keygen(1, 16), ValueError),
        (lambda: pqc.kyber_keygen(5, 16), ValueError),
        (lambda: pqc.kyber_keygen(2, 4), ValueError),
        (lambda: pqc.kyber_keygen(2, 24), ValueError),
        (lambda: pqc.kyber_keygen(2, 16, seed=True), TypeError),
        (lambda: pqc.kyber_encapsulate("key"), TypeError),
        (lambda: pqc.kyber_encapsulate(pqc.kyber_keygen(2, 16).public, seed="x"), TypeError),
        (lambda: pqc.kyber_decapsulate("keys", None), TypeError),
        (lambda: pqc.kyber_failure_rate(5), ValueError),
        (lambda: pqc.kyber_failure_rate(eta=0), ValueError),
        (lambda: pqc.kyber_failure_rate(trials=0), ValueError),
        (lambda: pqc.kyber_failure_rate(seed=True), TypeError),
        (lambda: pqc.kyber_decapsulate(pqc.kyber_keygen(2, 16), "ct"), TypeError),
        (
            lambda: pqc.kyber_decapsulate(
                pqc.kyber_keygen(2, 16), pqc.KyberCiphertext(((0,) * 16,), (0,) * 16)
            ),
            ValueError,
        ),
        (
            lambda: pqc.kyber_decapsulate(
                pqc.kyber_keygen(2, 16), pqc.KyberCiphertext(((0,) * 16, (0,) * 16), (0,) * 8)
            ),
            ValueError,
        ),
    ],
)
def test_kyber_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
