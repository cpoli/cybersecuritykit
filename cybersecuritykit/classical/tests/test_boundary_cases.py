"""Failure behavior and edge cases of the classical public API."""

import pytest

import cybersecuritykit as csk

cl = csk.classical
SQUARE = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
HILL_KEY = [[3, 3], [2, 5]]
ROTORS = ("I", "II", "III")
Settings = cl.EnigmaSettings


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: cl.shift_encrypt(123, 3), TypeError),  # type: ignore[arg-type]
        (lambda: cl.shift_encrypt("abc", 26), ValueError),
        (lambda: cl.letter_frequencies("123"), ValueError),
        (lambda: cl.alberti_encrypt("abc", 123), TypeError),  # type: ignore[arg-type]
        (lambda: cl.alberti_encrypt("abc", "ABC"), ValueError),
        (lambda: cl.vigenere_encrypt("abc", "123"), ValueError),
        (lambda: cl.playfair_decrypt("ABC", "KEY"), ValueError),
        (lambda: cl.playfair_decrypt("AABB", "KEY"), ValueError),
        (lambda: cl.kasiski_examination("ABCDEFGHIJ"), ValueError),
        (lambda: cl.index_of_coincidence("A"), ValueError),
        (lambda: cl.coincidence_profile("ABCDEF", max_period=4), ValueError),
        (lambda: cl.break_vigenere("ABC", 5), ValueError),
        (lambda: cl.adfgvx_encrypt("abc", 123, "KEY"), TypeError),  # type: ignore[arg-type]
        (lambda: cl.adfgvx_encrypt("abc", "ABC", "KEY"), ValueError),
        (lambda: cl.adfgvx_encrypt("abc", SQUARE, "123"), ValueError),
        (lambda: cl.adfgvx_encrypt(123, SQUARE, "KEY"), TypeError),  # type: ignore[arg-type]
        (lambda: cl.adfgvx_decrypt("ADF", SQUARE, "KEY"), ValueError),
        (lambda: cl.adfgvx_decrypt("ABCD", SQUARE, "KEY"), ValueError),
        (lambda: cl.vernam_encrypt(b"long", b"ab"), ValueError),
        (lambda: cl.crib_drag(b"ab", b"cd", b""), ValueError),
        (lambda: cl.hill_inverse([]), ValueError),
        (lambda: cl.hill_inverse([[1, 2], [3]]), ValueError),
        (lambda: cl.hill_inverse([[2, 4], [6, 8]]), ValueError),
        (lambda: cl.hill_known_plaintext("AAAA", "AAAA", 2), ValueError),
        (lambda: cl.enigma_encrypt("A", ROTORS, "AAA"), TypeError),  # type: ignore[arg-type]
        (lambda: cl.enigma_encrypt("A", Settings(["I", "II", "III"]), "AAA"), ValueError),  # type: ignore[arg-type]
        (lambda: cl.enigma_encrypt("A", Settings(("I", "I", "II")), "AAA"), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(("I", "II", "IX")), "AAA"), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS, "Z"), "AAA"), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS), "AA"), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS, "B", 5), "AAA"), TypeError),  # type: ignore[arg-type]
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS, "B", "ABC"), "AAA"), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS, "B", "AB AC"), "AAA"), ValueError),
        (lambda: cl.bombe_search("ABC", "X", 0, Settings(ROTORS, "B", "AB")), ValueError),
        (lambda: cl.crib_positions("ABC", ""), ValueError),
        (lambda: cl.crib_positions("ABC", "ABCD"), ValueError),
        (lambda: cl.crib_menu("ABCD", "AX", 0), ValueError),
        (lambda: cl.lorenz_keystream("wheels", 5), TypeError),  # type: ignore[arg-type]
        (lambda: cl.tutte_period_test([0, 2, 1], [2]), ValueError),
        (lambda: cl.tutte_period_test([0, True, 1], [2]), ValueError),
        (lambda: cl.tutte_period_test([0, 1, 1, 0], []), ValueError),
        (lambda: cl.tutte_period_test([0, 1, 1, 0], [3]), ValueError),
        (lambda: cl.shift_cipher_posterior({}, "AB"), ValueError),
        (lambda: cl.shift_cipher_posterior([("AB", 1.0)], "AB"), ValueError),  # type: ignore[arg-type]
        (lambda: cl.shift_cipher_posterior({"ab": 1.0}, "AB"), ValueError),
        (lambda: cl.shift_cipher_posterior({"ABC": 1.0}, "AB"), ValueError),
        (lambda: cl.shift_cipher_posterior({"AB": 0.5}, "AB"), ValueError),
        (lambda: cl.shift_cipher_posterior({"AB": 1.0}, "AC"), ValueError),
        (lambda: cl.unicity_distance(26, letter_entropy=5.0), ValueError),
        (lambda: cl.hill_climb_substitution("A"), ValueError),
        (lambda: cl.homophonic_encrypt("a", {"A": (1,)}), ValueError),
        (lambda: cl.homophonic_encrypt("a", [("A", (1,))]), ValueError),  # type: ignore[arg-type]
        (lambda: cl.solve_homophonic([1]), ValueError),
        (lambda: cl.enigma_encrypt("A", Settings(ROTORS), 123), TypeError),  # type: ignore[arg-type]
        (lambda: cl.break_playfair("ABC"), ValueError),
        (lambda: cl.break_playfair("ABCD", restarts=0), ValueError),
        (lambda: cl.break_playfair("ABCD", steps=0), ValueError),
        (lambda: cl.break_adfgvx("ADFGVX", 0), ValueError),
        (lambda: cl.break_adfgvx("ADFGVX", 9), ValueError),
        (lambda: cl.break_adfgvx("ADFGVX", 7), ValueError),
        (lambda: cl.break_adfgvx("AD", 1), ValueError),
        (lambda: cl.spurious_shift_keys("123"), ValueError),
    ],
)
def test_invalid_input_is_rejected(call, error):
    with pytest.raises(error):
        call()


def test_homophonic_key_rejects_empty_or_shared_symbols():
    key = dict(cl.homophonic_key(seed=1, symbols=26))
    with pytest.raises(ValueError):
        cl.homophonic_encrypt("a", {**key, "A": ()})
    with pytest.raises(ValueError):
        cl.homophonic_encrypt("a", {**key, "A": key["B"]})
    with pytest.raises(ValueError):
        cl.homophonic_decrypt((99,), key)


def test_hill_known_plaintext_rejects_texts_with_no_invertible_block_choice():
    # every block is a multiple of 2, so no matrix built from them is invertible mod 26
    with pytest.raises(ValueError):
        cl.hill_known_plaintext("ACEGACEG", "ACEGACEG", 2)


def test_hill_encrypt_rejects_a_singular_key():
    with pytest.raises(ValueError):
        cl.hill_encrypt("abcd", [[2, 4], [6, 8]])


def test_bombe_finds_a_crib_that_does_not_start_the_message():
    text = "XQWETTERVORHERSAGE"
    settings = Settings(("II", "V", "III"))
    cipher = cl.enigma_encrypt(text, settings, "QCB")
    found = cl.bombe_search(cipher, "WETTERVORHERSAGE", 2, settings)
    assert "QCB" in found.positions


def test_crib_drag_skips_offsets_that_decode_to_control_bytes():
    # combined stream 0x41 0x00: offset 0 gives NUL, offset 1 gives "A"
    hits = cl.crib_drag(b"\x41\x00", b"\x00\x00", b"A")
    assert [(h.offset, h.fragment) for h in hits] == [(1, b"A")]


def test_single_symbol_alphabet_edge_cases():
    assert cl.shift_encrypt("", 5) == ""
    assert cl.vigenere_decrypt(cl.vigenere_encrypt("abc", "z"), "z") == "ABC"


def test_break_adfgvx_rejects_more_than_26_symbols():
    # 36 distinct symbols under a one-column key cannot be renamed as 26 letters
    text = cl.adfgvx_encrypt(SQUARE * 2, SQUARE, "A")
    with pytest.raises(ValueError):
        cl.break_adfgvx(text, 1)


def test_mapping_fields_of_results_are_read_only():
    kasiski = cl.kasiski_examination(cl.vigenere_encrypt("the cat and the hat " * 4, "KEY"))
    secrecy = cl.one_time_pad_posterior({"AB": 1.0}, "BC")
    homophonic = cl.solve_homophonic(
        cl.homophonic_encrypt("attack at dawn" * 3, cl.homophonic_key())
    )
    for mapping in (kasiski.repeats, kasiski.factor_counts, secrecy.posterior, homophonic.mapping):
        with pytest.raises(TypeError):
            mapping["X"] = 1  # type: ignore[index]
