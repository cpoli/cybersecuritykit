"""Ring-LWE encryption of Lyubashevsky, Peikert and Regev (2010), through the public API."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pq = csk.pqc


def test_the_public_key_is_a_times_s_plus_a_small_error():
    keys = pq.ring_lwe_keygen(16, 257, eta=1, seed=2)
    assert keys == pq.ring_lwe_keygen(16, 257, eta=1, seed=2)
    a, b = keys.public.a, keys.public.b
    s = keys.secret
    assert set(s) <= {-1, 0, 1}
    # Negacyclic product by hand: x^16 = -1.
    product = [0] * 16
    for i in range(16):
        for j in range(16):
            sign = 1 if i + j < 16 else -1
            product[(i + j) % 16] += sign * a[i] * s[j]
    errors = [(y - x) % 257 for x, y in zip(product, b)]
    assert all(min(e, 257 - e) <= 1 for e in errors)


def test_decryption_uses_the_negacyclic_rule():
    # s = x, so u * s = (3 + 4x) x = 3x + 4x^2 = -4 + 3x = (13, 3) mod 17;
    # v = u * s + 8 * (1, 0) = (21, 3) = (4, 3).
    public = pq.RingLWEPublicKey(2, 17, (0, 0), (0, 0))
    keys = pq.RingLWEKeyPair(public, (0, 1))
    assert pq.ring_lwe_decrypt(keys, pq.RingLWECiphertext((3, 4), (4, 3))) == (1, 0)


@settings(max_examples=30, deadline=None)
@given(st.integers(0, 10_000), st.lists(st.integers(0, 1), min_size=16, max_size=16))
def test_messages_round_trip(seed, bits):
    # With eta = 1 the error e r - e1 s + e2 is at most 16 + 16 + 1 = 33 < 257 / 4.
    keys = pq.ring_lwe_keygen(16, 257, eta=1, seed=seed)
    ciphertext = pq.ring_lwe_encrypt(keys.public, bits, seed=seed + 1)
    assert pq.ring_lwe_decrypt(keys, ciphertext) == tuple(bits)


def test_wider_errors_cause_decryption_failures():
    keys = pq.ring_lwe_keygen(64, 97, eta=4, seed=1)
    message = (1, 0) * 32
    wrong = sum(
        pq.ring_lwe_decrypt(keys, pq.ring_lwe_encrypt(keys.public, message, seed=s)) != message
        for s in range(10)
    )
    assert wrong >= 5


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pq.ring_lwe_keygen(12, 257), ValueError),
        (lambda: pq.ring_lwe_keygen(1, 257), ValueError),
        (lambda: pq.ring_lwe_keygen(16, 1), ValueError),
        (lambda: pq.ring_lwe_keygen(16, 257, eta=-1), ValueError),
        (lambda: pq.ring_lwe_keygen(16, 257, seed="s"), TypeError),
        (lambda: pq.ring_lwe_encrypt("key", (0,) * 16), TypeError),
        (lambda: pq.ring_lwe_encrypt(pq.ring_lwe_keygen(16, 257).public, (0,) * 15), ValueError),
        (lambda: pq.ring_lwe_encrypt(pq.ring_lwe_keygen(16, 257).public, (2,) * 16), ValueError),
        (lambda: pq.ring_lwe_decrypt("keys", pq.RingLWECiphertext((0,), (0,))), TypeError),
        (lambda: pq.ring_lwe_decrypt(pq.ring_lwe_keygen(16, 257), "ct"), TypeError),
        (
            lambda: pq.ring_lwe_decrypt(pq.ring_lwe_keygen(16, 257), pq.RingLWECiphertext((0,), (0,))),
            ValueError,
        ),
    ],
)
def test_ring_lwe_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
