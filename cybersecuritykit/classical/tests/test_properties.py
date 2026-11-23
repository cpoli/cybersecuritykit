"""Round-trip and algebraic properties of the classical ciphers, checked with hypothesis."""

import random

from hypothesis import given
from hypothesis import strategies as st

import cybersecuritykit as csk
from cybersecuritykit.constants import ALPHABET

cl = csk.classical
letters = st.text(alphabet=ALPHABET, min_size=1, max_size=60)
keywords = st.text(alphabet=ALPHABET, min_size=1, max_size=10)
permutations = st.randoms(use_true_random=False).map(lambda rng: "".join(rng.sample(ALPHABET, 26)))


@given(letters, st.integers(0, 25))
def test_shift_round_trip(text, shift):
    assert cl.shift_decrypt(cl.shift_encrypt(text, shift), shift) == text


@given(letters, keywords)
def test_vigenere_round_trip(text, key):
    assert cl.vigenere_decrypt(cl.vigenere_encrypt(text, key), key) == text


@given(letters, permutations, st.integers(0, 25), st.integers(1, 30))
def test_alberti_round_trip(text, disk, start, period):
    ciphertext = cl.alberti_encrypt(text, disk, start, period)
    assert cl.alberti_decrypt(ciphertext, disk, start, period) == text


@given(letters, permutations)
def test_substitution_round_trip(text, key):
    assert cl.substitution_decrypt(cl.substitution_encrypt(text, key), key) == text


@given(st.text(alphabet=ALPHABET, min_size=1, max_size=30).map(lambda t: t * 2))
def test_hill_round_trip_on_whole_blocks(text):
    key = [[3, 3], [2, 5]]
    assert cl.hill_decrypt(cl.hill_encrypt(text, key), key) == text


@given(st.text(alphabet=ALPHABET + "XXXX", min_size=1, max_size=60), keywords)
def test_playfair_never_doubles_a_pair_and_round_trips_its_digraphs(text, key):
    ciphertext = cl.playfair_encrypt(text, key)
    pairs = [ciphertext[i : i + 2] for i in range(0, len(ciphertext), 2)]
    assert all(a != b for a, b in pairs)
    plaintext = cl.playfair_decrypt(ciphertext, key)
    assert plaintext.replace("X", "").replace("Q", "") == (
        text.replace("J", "I").replace("X", "").replace("Q", "")
    )


@given(st.text(alphabet=ALPHABET + "0123456789", min_size=1, max_size=60), keywords)
def test_adfgvx_round_trip(text, keyword):
    square = "".join(random.Random(0).sample(ALPHABET + "0123456789", 36))
    ciphertext = cl.adfgvx_encrypt(text, square, keyword)
    assert cl.adfgvx_decrypt(ciphertext, square, keyword) == text


@given(letters, st.text(alphabet=ALPHABET, min_size=3, max_size=3))
def test_enigma_is_reciprocal_and_never_fixes_a_letter(text, positions):
    settings = cl.EnigmaSettings(("I", "II", "III"), "B", "AB CD")
    ciphertext = cl.enigma_encrypt(text, settings, positions)
    assert cl.enigma_encrypt(ciphertext, settings, positions) == text
    assert all(p != c for p, c in zip(text, ciphertext, strict=True))


@given(st.binary(min_size=1, max_size=64), st.randoms(use_true_random=False))
def test_vernam_is_an_involution(data, rng):
    key = bytes(rng.randrange(256) for _ in data)
    assert cl.vernam_encrypt(cl.vernam_encrypt(data, key), key) == data
