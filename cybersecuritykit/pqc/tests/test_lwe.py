"""Regev's learning with errors (2005) and its bit encryption, through the public API."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def test_the_public_key_is_a_noisy_linear_system():
    keys = pqc.lwe_keygen(8, 32, 257, eta=2, seed=3)
    assert keys == pqc.lwe_keygen(8, 32, 257, eta=2, seed=3)
    public = keys.public
    assert (public.n, public.q) == (8, 257)
    assert len(public.a) == len(public.b) == 32
    for row, b in zip(public.a, public.b, strict=True):
        error = (b - sum(x * s for x, s in zip(row, keys.secret, strict=True))) % 257
        assert min(error, 257 - error) <= 2


def test_a_hand_computed_encryption():
    public = pqc.LWEPublicKey(2, 17, ((1, 2), (3, 4), (5, 6)), (4, 8, 12))
    # Rows 0 and 2: u = (1 + 5, 2 + 6) = (6, 8); v = 4 + 12 + 8 * 1 = 24 = 7 mod 17.
    assert pqc.lwe_encrypt(public, 1, subset=(1, 0, 1)) == pqc.LWECiphertext((6, 8), 7)
    keys = pqc.LWEKeyPair(public, (1, 1))  # b = A s + (1, 1, 1)
    assert pqc.lwe_decrypt(keys, pqc.LWECiphertext((6, 8), 7)) == 1
    assert pqc.lwe_decrypt(keys, pqc.lwe_encrypt(public, 0, subset=(1, 1, 0))) == 0


@settings(max_examples=30, deadline=None)
@given(st.integers(0, 10_000), st.integers(0, 1))
def test_bits_round_trip_within_the_error_budget(seed, bit):
    # 32 samples with errors of at most 2 sum to at most 64 < 257 / 4.
    keys = pqc.lwe_keygen(8, 32, 257, eta=2, seed=seed)
    assert pqc.lwe_decrypt(keys, pqc.lwe_encrypt(keys.public, bit, seed=seed)) == bit


def test_too_much_noise_breaks_decryption():
    keys = pqc.lwe_keygen(8, 96, 97, eta=16, seed=1)
    wrong = sum(
        pqc.lwe_decrypt(keys, pqc.lwe_encrypt(keys.public, 1, seed=s)) != 1 for s in range(60)
    )
    assert wrong > 5


def test_without_noise_gaussian_elimination_reads_off_the_secret():
    keys = pqc.lwe_keygen(6, 20, 97, eta=0, seed=8)
    attack = pqc.lwe_gaussian_attack(keys.public)
    assert attack.secret == keys.secret
    assert attack.consistent == 20
    noisy = pqc.lwe_keygen(6, 20, 97, eta=2, seed=8)
    attack = pqc.lwe_gaussian_attack(noisy.public)
    assert attack.secret != noisy.secret
    assert attack.consistent < 20


def test_the_attack_needs_independent_rows():
    public = pqc.LWEPublicKey(2, 7, ((1, 2), (2, 4), (3, 6)), (0, 0, 0))
    with pytest.raises(ValueError, match="independent"):
        pqc.lwe_gaussian_attack(public)


@pytest.mark.parametrize(("n", "m", "eta", "seed"), [(4, 16, 2, 1), (6, 24, 4, 2), (8, 24, 2, 3)])
def test_the_primal_attack_recovers_a_noisy_secret(n, m, eta, seed):
    keys = pqc.lwe_keygen(n, m, 97, eta=eta, seed=seed)
    assert pqc.lwe_gaussian_attack(keys.public).secret != keys.secret
    attack = pqc.lwe_lattice_attack(keys.public)
    assert attack.secret == keys.secret
    assert attack.dimension == m + 1
    assert attack.swaps > 0
    # The recovered error is exactly b - A s, centered, and within the binomial bound.
    public = keys.public
    for row, b, e in zip(public.a, public.b, attack.error, strict=True):
        assert (b - sum(x * y for x, y in zip(row, keys.secret, strict=True)) - e) % 97 == 0
        assert abs(e) <= eta


def test_the_primal_attack_fails_on_uniform_samples():
    # b is uniform, so no short error exists and no reduced row has last coordinate +-1.
    public = pqc.LWEPublicKey(1, 97, ((95,), (28,)), (7, 49))
    attack = pqc.lwe_lattice_attack(public)
    assert (attack.secret, attack.error, attack.dimension) == (None, None, 3)


def test_the_primal_attack_needs_independent_first_rows():
    public = pqc.LWEPublicKey(2, 97, ((1, 2), (2, 4), (3, 5)), (0, 0, 0))
    with pytest.raises(ValueError, match="independent"):
        pqc.lwe_lattice_attack(public)


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pqc.lwe_keygen(0, 8, 97), ValueError),
        (lambda: pqc.lwe_keygen(4, 8, 1), ValueError),
        (lambda: pqc.lwe_keygen(4, 8, 97, eta=-1), ValueError),
        (lambda: pqc.lwe_keygen(4, 8, 97, seed=None), TypeError),
        (lambda: pqc.lwe_encrypt("key", 1), TypeError),
        (lambda: pqc.lwe_encrypt(pqc.lwe_keygen(4, 8, 97).public, 2), ValueError),
        (lambda: pqc.lwe_encrypt(pqc.lwe_keygen(4, 8, 97).public, 1, subset=(1,)), ValueError),
        (lambda: pqc.lwe_encrypt(pqc.lwe_keygen(4, 8, 97).public, 1, subset=(2,) * 8), ValueError),
        (lambda: pqc.lwe_decrypt("keys", pqc.LWECiphertext((0,), 0)), TypeError),
        (lambda: pqc.lwe_decrypt(pqc.lwe_keygen(4, 8, 97), "ct"), TypeError),
        (lambda: pqc.lwe_decrypt(pqc.lwe_keygen(4, 8, 97), pqc.LWECiphertext((0,), 0)), ValueError),
        (lambda: pqc.lwe_gaussian_attack("key"), TypeError),
        (lambda: pqc.lwe_lattice_attack("key"), TypeError),
        (lambda: pqc.lwe_lattice_attack(pqc.LWEPublicKey(1, 8, ((1,),), (0,))), ValueError),
        (lambda: pqc.lwe_gaussian_attack(pqc.LWEPublicKey(1, 8, ((1,),), (0,))), ValueError),
    ],
)
def test_lwe_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
