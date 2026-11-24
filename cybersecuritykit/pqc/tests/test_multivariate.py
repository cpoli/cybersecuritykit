"""Matsumoto-Imai and Patarin's linearization attack, through the public API of pqc."""

import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc

KEYS = pqc.matsumoto_imai_keygen(5, 2, seed=3)


def bits(value, n):
    return tuple((value >> i) & 1 for i in range(n))


def test_quadratic_map_evaluates_a_hand_computed_polynomial():
    # f(x0, x1) = 2 x0^2 + x0 x1 + 4 x1 + 1 over GF(5) at (3, 2): 18 + 6 + 8 + 1 = 33 = 3.
    f = pqc.QuadraticMap(5, (((2, 1), (0, 0)),), ((0, 4),), (1,))
    assert (f.n_vars, f.n_polys) == (2, 1)
    assert f.evaluate((3, 2)) == (3,)
    with pytest.raises(ValueError, match="length 2"):
        f.evaluate((1,))


def test_public_key_is_quadratic_over_gf2():
    public = KEYS.public
    assert public.q == 2 and public.n_vars == 5 and public.n_polys == 5
    for quad in public.quadratic:
        assert all(quad[i][j] == 0 for i in range(5) for j in range(i + 1))


def test_matsumoto_imai_is_a_permutation_and_decrypts():
    images = set()
    for value in range(2**5):
        plaintext = bits(value, 5)
        ciphertext = pqc.matsumoto_imai_encrypt(KEYS.public, plaintext)
        images.add(ciphertext)
        assert pqc.matsumoto_imai_decrypt(KEYS.private, ciphertext) == plaintext
    assert len(images) == 2**5


@settings(max_examples=20, deadline=None)
@given(st.integers(0, 2**7 - 1), st.integers(0, 2**32))
def test_matsumoto_imai_round_trip_property(value, seed):
    keys = pqc.matsumoto_imai_keygen(7, 3, seed=seed)
    plaintext = bits(value, 7)
    ciphertext = pqc.matsumoto_imai_encrypt(keys.public, plaintext)
    assert pqc.matsumoto_imai_decrypt(keys.private, ciphertext) == plaintext


def test_patarin_linearization_recovers_every_plaintext():
    for value in (0, 1, 13, 31):
        plaintext = bits(value, 5)
        ciphertext = pqc.matsumoto_imai_encrypt(KEYS.public, plaintext)
        result = pqc.patarin_linearization(KEYS.public, ciphertext, seed=1)
        assert result.plaintext == plaintext
        # Patarin (1995): at least n independent bilinear relations.
        assert result.relations >= 5
        assert 1 <= result.candidates <= 2**5
        assert result.pairs_used == 2**5


def test_patarin_linearization_on_a_larger_key():
    keys = pqc.matsumoto_imai_keygen(7, 3, seed=8)
    plaintext = (1, 0, 1, 1, 0, 0, 1)
    ciphertext = pqc.matsumoto_imai_encrypt(keys.public, plaintext)
    result = pqc.patarin_linearization(keys.public, ciphertext, seed=2, pairs=100)
    assert result.plaintext == plaintext and result.pairs_used == 100


def test_patarin_linearization_with_too_few_pairs_can_lose_the_plaintext():
    outcomes = set()
    for seed, value in itertools.product(range(6), range(0, 32, 3)):
        ciphertext = pqc.matsumoto_imai_encrypt(KEYS.public, bits(value, 5))
        try:
            pqc.patarin_linearization(KEYS.public, ciphertext, seed=seed, pairs=12)
            outcomes.add("found")
        except RuntimeError:
            outcomes.add("lost")
    assert outcomes == {"found", "lost"}


def test_matsumoto_imai_rejects_bad_parameters():
    with pytest.raises(ValueError, match="n"):
        pqc.matsumoto_imai_keygen(1, 1, seed=0)
    with pytest.raises(ValueError, match="n"):
        pqc.matsumoto_imai_keygen(13, 1, seed=0)
    with pytest.raises(ValueError, match="theta"):
        pqc.matsumoto_imai_keygen(5, 0, seed=0)
    with pytest.raises(ValueError, match="theta"):
        pqc.matsumoto_imai_keygen(5, 5, seed=0)
    with pytest.raises(ValueError, match="theta"):
        pqc.matsumoto_imai_keygen(4, 1, seed=0)  # gcd(3, 15) = 3
    with pytest.raises(TypeError):
        pqc.matsumoto_imai_keygen(5, 2, seed=None)
    with pytest.raises(ValueError, match="length 5"):
        pqc.matsumoto_imai_encrypt(KEYS.public, (0, 1))
    with pytest.raises(ValueError, match="0 or 1"):
        pqc.matsumoto_imai_decrypt(KEYS.private, (0, 1, 2, 0, 0))
    with pytest.raises(ValueError, match="length 5"):
        pqc.patarin_linearization(KEYS.public, (0,), seed=0)
    with pytest.raises(ValueError, match="pairs"):
        pqc.patarin_linearization(KEYS.public, (0,) * 5, seed=0, pairs=0)
    with pytest.raises(ValueError, match="GF\\(2\\)"):
        pqc.patarin_linearization(pqc.QuadraticMap(3, (((0,),),), ((1,),), (0,)), (0,), seed=0)
