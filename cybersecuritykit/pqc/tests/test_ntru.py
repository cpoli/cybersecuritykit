"""NTRU (Hoffstein, Pipher and Silverman, 1998) and its lattice attack, through the public API."""

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pq = csk.pqc

# Hoffstein, Pipher and Silverman, *An Introduction to Mathematical Cryptography*,
# 2nd ed. (Springer, 2014), Example 7.53: N = 7, p = 3, q = 41, d = 2.
F = (-1, 0, 1, 1, -1, 0, 1)  # x^6 - x^4 + x^3 + x^2 - 1
G = (0, -1, -1, 0, 1, 0, 1)  # x^6 + x^4 - x^2 - x
H = (30, 26, 8, 38, 2, 40, 20)
MESSAGE = (1, -1, 1, 1, 0, -1, 0)  # -x^5 + x^3 + x^2 - x + 1
BLINDING = (-1, 1, 0, 0, 0, -1, 1)  # x^6 - x^5 + x - 1
CIPHERTEXT = (25, 3, 40, 2, 4, 19, 31)


def test_ntru_matches_the_textbook_example():
    keys = pq.ntru_keypair(F, G, p=3, q=41)
    assert keys.public == pq.NTRUPublicKey(7, 3, 41, H)
    assert keys.f_p == (1, 1, 1, 1, 0, 2, 1)  # F_p = x^6 + 2x^5 + x^3 + x^2 + x + 1
    ciphertext = pq.ntru_encrypt(keys.public, MESSAGE, blinding=BLINDING)
    assert ciphertext == CIPHERTEXT
    assert pq.ntru_decrypt(keys, ciphertext) == MESSAGE


def test_random_keys_decrypt_random_messages():
    keys = pq.ntru_keygen(11, 3, 64, 3, seed=4)
    assert keys == pq.ntru_keygen(11, 3, 64, 3, seed=4)
    assert sorted(keys.f) == [-1] * 3 + [0] * 4 + [1] * 4
    rng = random.Random(0)
    for trial in range(10):
        message = tuple(rng.choice((-1, 0, 1)) for _ in range(11))
        ciphertext = pq.ntru_encrypt(keys.public, message, seed=trial)
        assert pq.ntru_decrypt(keys, ciphertext) == message


def test_keygen_redraws_f_until_it_is_invertible():
    # Mod 2, x^7 - 1 = (x + 1)(x^3 + x + 1)(x^3 + x^2 + 1): a weight-3 f whose
    # support is a Hamming codeword is a zero divisor, so q = 32 rejects it.
    keys = pq.ntru_keygen(7, 3, 32, 1, seed=1)
    assert pq.ntru_keypair(keys.f, keys.g, 3, 32) == keys
    message = (1, 0, -1, 0, 1, 1, 0)
    assert pq.ntru_decrypt(keys, pq.ntru_encrypt(keys.public, message)) == message


def test_the_attack_fails_when_no_reduced_vector_inverts():
    # A key that came from no real f: every short vector is a zero divisor mod 2.
    with pytest.raises(ValueError, match="invertible"):
        pq.ntru_lattice_attack(pq.NTRUPublicKey(2, 3, 4, (3, 2)))


@settings(max_examples=15, deadline=None)
@given(st.integers(0, 10_000))
def test_coppersmith_shamir_lattice_attack_recovers_a_working_key(seed):
    keys = pq.ntru_keygen(7, 3, 41, 2, seed=seed)
    attack = pq.ntru_lattice_attack(keys.public)
    assert attack.dimension == 14
    assert attack.keypair.public == keys.public
    rng = random.Random(seed)
    message = tuple(rng.choice((-1, 0, 1)) for _ in range(7))
    ciphertext = pq.ntru_encrypt(keys.public, message, seed=seed)
    assert pq.ntru_decrypt(attack.keypair, ciphertext) == message
    # The recovered (f, g) is no longer than the planted one.
    found = attack.keypair.f + attack.keypair.g
    assert sum(x * x for x in found) <= sum(x * x for x in keys.f + keys.g)


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pq.ntru_keypair((1, 1, 1), (1, 0, 0), p=3, q=41), ValueError),  # a zero divisor
        (lambda: pq.ntru_keypair((1, 0, 1, 0), (1, 0, 0, 0), p=2, q=41), ValueError),
        (lambda: pq.ntru_keypair(F, G[:6], p=3, q=41), ValueError),
        (lambda: pq.ntru_keypair(F, G, p=3, q=42), ValueError),
        (lambda: pq.ntru_keypair(F, G, p=4, q=41), ValueError),
        (lambda: pq.ntru_keypair(F, G, p=3, q=3), ValueError),
        (lambda: pq.ntru_keypair((2, 0), (1, 0), p=3, q=40), ValueError),
        (lambda: pq.ntru_keypair(F, (1.0,) * 7, p=3, q=41), TypeError),
        (lambda: pq.ntru_keygen(7, 3, 41, 4), ValueError),
        (lambda: pq.ntru_keygen(7, 3, 41, 0), ValueError),
        (lambda: pq.ntru_keygen(7, 3, 41, 2, seed=1.0), TypeError),
        (lambda: pq.ntru_encrypt("key", MESSAGE), TypeError),
        (lambda: pq.ntru_encrypt(pq.NTRUPublicKey(7, 3, 41, H), MESSAGE[:6]), ValueError),
        (lambda: pq.ntru_encrypt(pq.NTRUPublicKey(7, 3, 41, H), (2,) * 7), ValueError),
        (
            lambda: pq.ntru_encrypt(pq.NTRUPublicKey(7, 3, 41, H), MESSAGE, blinding=(1,)),
            ValueError,
        ),
        (lambda: pq.ntru_decrypt("keys", CIPHERTEXT), TypeError),
        (lambda: pq.ntru_decrypt(pq.ntru_keypair(F, G, 3, 41), CIPHERTEXT[:3]), ValueError),
        (lambda: pq.ntru_lattice_attack("key"), TypeError),
    ],
)
def test_ntru_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
