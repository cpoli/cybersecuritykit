"""Binary Goppa codes, McEliece and Niederreiter, through the public API of cybersecuritykit.pqc."""

import itertools
import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


# An independent GF(2^m) used to check the Goppa parity-check equations.
def gf_mul(a, b, modulus, m):
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if (a >> m) & 1:
            a ^= modulus
    return out


def gf_inv(a, modulus, m):
    return next(b for b in range(1, 2**m) if gf_mul(a, b, modulus, m) == 1)


def gf_eval(coefficients, x, modulus, m):
    out = 0
    for c in reversed(coefficients):
        out = gf_mul(out, x, modulus, m) ^ c
    return out


CODE = pqc.goppa_code(4, 2, seed=7)
KEYS = pqc.mceliece_keygen(5, 3, seed=11)
NKEYS = pqc.niederreiter_keygen(5, 3, seed=12)


def test_goppa_code_has_the_designed_shape():
    assert CODE.n == 16 and CODE.k == 16 - 4 * 2
    assert len(CODE.generator) == CODE.k and len(CODE.parity_check) == CODE.n - CODE.k
    assert sorted(CODE.support) == list(range(16))
    assert len(CODE.polynomial) == 3 and CODE.polynomial[-1] == 1


def test_goppa_codewords_satisfy_the_defining_sums():
    # c is in the code iff sum_i c_i alpha_i^j / g(alpha_i) = 0 for j < t (Goppa 1970).
    m, modulus = CODE.m, CODE.field_modulus
    for row in CODE.generator:
        for j in range(CODE.t):
            total = 0
            for c, alpha in zip(row, CODE.support, strict=True):
                if c:
                    power = 1
                    for _ in range(j):
                        power = gf_mul(power, alpha, modulus, m)
                    g = gf_eval(CODE.polynomial, alpha, modulus, m)
                    total ^= gf_mul(power, gf_inv(g, modulus, m), modulus, m)
            assert total == 0


def test_generator_and_parity_check_are_orthogonal():
    for g_row in CODE.generator:
        assert pqc.syndrome(CODE.parity_check, g_row) == (0,) * (CODE.n - CODE.k)


def test_binary_goppa_code_has_minimum_distance_at_least_2t_plus_1():
    weights = []
    for coefficients in itertools.product((0, 1), repeat=CODE.k):
        if any(coefficients):
            word = [0] * CODE.n
            for c, row in zip(coefficients, CODE.generator, strict=True):
                if c:
                    word = [a ^ b for a, b in zip(word, row, strict=True)]
            weights.append(sum(word))
    assert min(weights) >= 2 * CODE.t + 1


def test_goppa_decoding_corrects_every_error_of_weight_up_to_t():
    codeword = CODE.generator[0]
    for weight in range(CODE.t + 1):
        for positions in itertools.combinations(range(CODE.n), weight):
            error = tuple(int(i in positions) for i in range(CODE.n))
            received = tuple(a ^ b for a, b in zip(codeword, error, strict=True))
            assert pqc.goppa_decode(CODE, received) == error


def test_goppa_decoding_reports_some_errors_beyond_t():
    rng = random.Random(3)
    failures = 0
    for _ in range(60):
        positions = rng.sample(range(CODE.n), CODE.t + 2)
        word = tuple(int(i in positions) for i in range(CODE.n))
        try:
            pqc.goppa_decode(CODE, word)
        except ValueError:
            failures += 1
    assert failures > 0


def test_mceliece_round_trip_and_public_key_hides_the_code():
    private = KEYS.private
    assert KEYS.public.t == 3
    assert KEYS.public.generator != private.code.generator
    message = tuple(random.Random(1).getrandbits(1) for _ in range(private.code.k))
    ciphertext = pqc.mceliece_encrypt(KEYS.public, message, seed=5)
    assert ciphertext != pqc.mceliece_encrypt(KEYS.public, message, seed=6)
    assert pqc.mceliece_decrypt(private, ciphertext) == message


@settings(max_examples=25, deadline=None)
@given(st.lists(st.integers(0, 1), min_size=17, max_size=17), st.integers(0, 2**32))
def test_mceliece_round_trip_property(message, seed):
    ciphertext = pqc.mceliece_encrypt(KEYS.public, tuple(message), seed=seed)
    assert pqc.mceliece_decrypt(KEYS.private, ciphertext) == tuple(message)


def test_mceliece_ciphertext_is_a_codeword_plus_t_errors():
    message = (1,) + (0,) * 16
    ciphertext = pqc.mceliece_encrypt(KEYS.public, message, seed=9)
    error = tuple(a ^ b for a, b in zip(ciphertext, KEYS.public.generator[0], strict=True))
    assert sum(error) == 3


def test_prange_breaks_toy_mceliece():
    message = tuple(random.Random(2).getrandbits(1) for _ in range(17))
    ciphertext = pqc.mceliece_encrypt(KEYS.public, message, seed=8)
    result = pqc.break_mceliece(KEYS.public, ciphertext, seed=4)
    assert result.message == message
    assert sum(result.error) == 3
    assert result.iterations >= 1


def test_niederreiter_round_trip_and_prange_break():
    assert NKEYS.public.t == 3 and len(NKEYS.public.parity_check) == 15
    error = tuple(int(i in (1, 17, 30)) for i in range(32))
    ciphertext = pqc.niederreiter_encrypt(NKEYS.public, error)
    assert len(ciphertext) == 15
    assert pqc.niederreiter_decrypt(NKEYS.private, ciphertext) == error
    assert pqc.break_niederreiter(NKEYS.public, ciphertext, seed=3).error == error


def test_niederreiter_and_mceliece_are_dual():
    # Niederreiter's syndrome of e is H e; McEliece's ciphertext has the same syndrome.
    code = NKEYS.private.code
    error = tuple(int(i in (0, 5)) for i in range(32))
    received = tuple(a ^ b for a, b in zip(code.generator[3], error, strict=True))
    assert pqc.syndrome(code.parity_check, received) == pqc.syndrome(code.parity_check, error)


def test_goppa_and_key_generation_reject_bad_parameters():
    with pytest.raises(ValueError, match="m"):
        pqc.goppa_code(1, 1, seed=0)
    with pytest.raises(ValueError, match="m"):
        pqc.goppa_code(13, 1, seed=0)
    with pytest.raises(ValueError, match="t"):
        pqc.goppa_code(4, 0, seed=0)
    with pytest.raises(ValueError, match="n"):
        pqc.goppa_code(4, 2, n=8, seed=0)
    with pytest.raises(ValueError, match="n"):
        pqc.goppa_code(4, 2, n=17, seed=0)
    with pytest.raises(TypeError):
        pqc.goppa_code(4, 2, seed=1.5)
    assert pqc.goppa_code(4, 2, n=12, seed=0).n == 12
    with pytest.raises(ValueError, match="m"):
        pqc.mceliece_keygen(1, 1, seed=0)
    with pytest.raises(ValueError, match="m"):
        pqc.niederreiter_keygen(1, 1, seed=0)


def test_encryption_rejects_bad_inputs():
    with pytest.raises(ValueError, match="length 17"):
        pqc.mceliece_encrypt(KEYS.public, (0, 1), seed=0)
    with pytest.raises(ValueError, match="length 32"):
        pqc.mceliece_decrypt(KEYS.private, (0, 1))
    with pytest.raises(ValueError, match="length 32"):
        pqc.break_mceliece(KEYS.public, (0,), seed=0)
    with pytest.raises(ValueError, match="weight"):
        pqc.niederreiter_encrypt(NKEYS.public, (1,) * 4 + (0,) * 28)
    with pytest.raises(ValueError, match="length 32"):
        pqc.niederreiter_encrypt(NKEYS.public, (0,))
    with pytest.raises(ValueError, match="length 15"):
        pqc.niederreiter_decrypt(NKEYS.private, (0,))
    with pytest.raises(ValueError, match="length 16"):
        pqc.goppa_decode(CODE, (0,))
