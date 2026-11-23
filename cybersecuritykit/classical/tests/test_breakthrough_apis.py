"""Breakthrough APIs of cybersecuritykit.classical checked against published vectors."""

import math

import pytest

import cybersecuritykit as csk

PROSE_TEXT = (
    "It was the best of times and the worst of times for the small band of clerks who kept "
    "the cipher office running through the long winter of the war"
)

LONG_TEXT = (
    "When the messenger reached the northern fort he found the gates closed and the walls "
    "lined with archers who would not let him pass until the captain had read the letter. "
    "The captain was a careful man who trusted nobody, and he held the sealed paper up to "
    "the light before he broke the wax. Inside there were only rows of letters that made "
    "no sense at all, and he called for the old scribe who kept the books of the garrison. "
    "The scribe sat down at the long table with a candle and a sheet of clean paper and "
    "began to count the letters one by one. He noticed that some groups of three letters "
    "appeared again and again at regular distances, and he wrote those distances in a "
    "column at the side of the page. By morning he had found that every distance could be "
    "divided by the same small number, and from that number he guessed the length of the "
    "secret word. Then the rest was only patience, because each column of letters had been "
    "shifted by a single amount and could be solved like the simple ciphers of the market. "
    "When the captain read the message at last he ordered the gates to be opened, and the "
    "soldiers rode out before noon to meet the enemy at the river crossing"
)


def test_caesar_shift_of_three_matches_suetonius():
    # Suetonius: Caesar replaced each letter by the one three places further on.
    assert csk.classical.shift_encrypt("veni vidi vici", 3) == "YHQLYLGLYLFL"
    assert csk.classical.shift_decrypt("YHQLYLGLYLFL", 3) == "VENIVIDIVICI"


def test_letter_frequencies_count_only_letters():
    frequencies = csk.classical.letter_frequencies("Aab, b!")
    assert frequencies["A"] == 0.5 and frequencies["B"] == 0.5 and frequencies["Z"] == 0.0


def test_frequency_analysis_breaks_a_shift_cipher():
    ciphertext = csk.classical.shift_encrypt(PROSE_TEXT, 11)
    result = csk.classical.break_shift_cipher(ciphertext)
    assert result.shift == 11
    assert result.plaintext.startswith("ITWASTHEBESTOFTIMES")
    assert len(result.chi_squared) == 26
    assert min(result.chi_squared) == result.chi_squared[11]


def test_alberti_disk_turns_one_step_every_period_letters():
    # With the plain alphabet on the inner disk the turns are visible by hand.
    alphabet = csk.constants.ALPHABET
    assert csk.classical.alberti_encrypt("AAAAAA", alphabet, start=0, period=1) == "ABCDEF"
    assert csk.classical.alberti_encrypt("AAAAAA", alphabet, start=2, period=2) == "CCDDEE"
    disk = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = csk.classical.alberti_encrypt(PROSE_TEXT, disk, start=5, period=4)
    assert csk.classical.alberti_decrypt(ciphertext, disk, start=5, period=4).startswith("ITWAS")


def test_vigenere_matches_the_textbook_vector():
    # The ATTACKATDAWN / LEMON example of Wikipedia and most textbooks.
    assert csk.classical.vigenere_encrypt("attack at dawn", "lemon") == "LXFOPVEFRNHR"
    assert csk.classical.vigenere_decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def test_playfair_matches_the_published_example():
    # Wikipedia's Playfair example: key PLAYFAIR EXAMPLE, J merged into I.
    square = csk.classical.playfair_square("playfair example")
    assert square == ("PLAYF", "IREXM", "BCDGH", "KNOQS", "TUVWZ")
    ciphertext = csk.classical.playfair_encrypt(
        "hide the gold in the tree stump", "playfair example"
    )
    assert ciphertext == "BMODZBXDNABEKUDMUIXMMOUVIF"
    assert csk.classical.playfair_decrypt(ciphertext, "playfair example") == (
        "HIDETHEGOLDINTHETREXESTUMP"
    )


@pytest.mark.parametrize("key", ["KEY", "LEMON", "CIPHER", "FORTRESS"])
def test_kasiski_examination_finds_the_keyword_length(key):
    result = csk.classical.kasiski_examination(csk.classical.vigenere_encrypt(LONG_TEXT, key))
    assert result.likely_period == len(key)
    assert all(len(trigram) == 3 and len(at) >= 2 for trigram, at in result.repeats.items())
    assert result.factor_counts[len(key)] > 0


def test_index_of_coincidence_of_a_small_text_by_hand():
    # AABB: two pairs of equal letters out of 4*3/2 = 6 pairs.
    assert abs(csk.classical.index_of_coincidence("AABB") - 1 / 3) < 1e-10
    assert abs(csk.classical.index_of_coincidence("ABCD")) < 1e-10


def test_english_text_has_friedmans_coincidence_rate():
    # Friedman: English about 0.066, uniformly random letters 1/26 = 0.038.
    assert 0.06 < csk.classical.index_of_coincidence(LONG_TEXT) < 0.08
    ciphertext = csk.classical.vigenere_encrypt(LONG_TEXT, "FORTRESS")
    assert csk.classical.index_of_coincidence(ciphertext) < 0.05


@pytest.mark.parametrize("key", ["KEY", "LEMON", "CIPHER", "FORTRESS"])
def test_coincidence_profile_and_column_attack_break_vigenere(key):
    ciphertext = csk.classical.vigenere_encrypt(LONG_TEXT, key)
    profile = csk.classical.coincidence_profile(ciphertext, max_period=12)
    assert profile.periods == tuple(range(1, 13))
    assert profile.best_period == len(key)
    result = csk.classical.break_vigenere(ciphertext, profile.best_period)
    assert result.key == key
    assert result.plaintext.startswith("WHENTHEMESSENGER")


def test_adfgvx_round_trip_and_fractionation():
    square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    ciphertext = csk.classical.adfgvx_encrypt("attack at 1200am", square, "GERMAN")
    assert set(ciphertext) <= set("ADFGVX") and len(ciphertext) == 2 * len("ATTACKAT1200AM")
    assert csk.classical.adfgvx_decrypt(ciphertext, square, "GERMAN") == "ATTACKAT1200AM"


def test_adfgvx_fractionation_by_hand():
    # A sits in row D, column G of this square; one letter gives one column pair.
    square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    assert csk.classical.adfgvx_encrypt("A", square, "Z") == "DG"
    # Keyword BA reads column 1 (G) before column 0 (D).
    assert csk.classical.adfgvx_encrypt("A", square, "BA") == "GD"


def test_two_time_pad_cancels_the_key():
    key = bytes(range(7, 7 + 40))
    p1 = b"MEET AT THE NORTH GATE AT DAWN"
    p2 = b"RETREAT TO THE OLD MILL TONIGHT"[: len(p1)]
    c1, c2 = csk.classical.vernam_encrypt(p1, key), csk.classical.vernam_encrypt(p2, key)
    assert csk.classical.vernam_encrypt(c1, key) == p1
    combined = csk.classical.two_time_pad(c1, c2)
    assert all(x == a ^ b for x, a, b in zip(combined, p1, p2, strict=True))
    # Dragging the crib " THE " along the combined stream reveals p2 where p1 has it.
    hits = csk.classical.crib_drag(c1, c2, b" THE ")
    assert any(h.offset == 7 and h.fragment == b" TO T" for h in hits)
    assert all(h.fragment.decode("ascii").isprintable() for h in hits)


def test_hill_cipher_matches_the_textbook_vector():
    # Wikipedia: key GYBNQKURP encrypts ACT to POH and CAT to FIN.
    key = ((6, 24, 1), (13, 16, 10), (20, 17, 15))
    assert csk.classical.hill_encrypt("ACTCAT", key) == "POHFIN"
    assert csk.classical.hill_inverse(key) == ((8, 5, 10), (21, 8, 21), (21, 12, 8))
    assert csk.classical.hill_decrypt("POHFIN", key) == "ACTCAT"


def test_hill_known_plaintext_recovers_the_key():
    key = ((6, 24, 1), (13, 16, 10), (20, 17, 15))
    plaintext = "THEARMYMARCHESATDAWNTOWARDSTHERIVER"
    ciphertext = csk.classical.hill_encrypt(plaintext, key)
    result = csk.classical.hill_known_plaintext(plaintext, ciphertext, 3)
    assert result.key == key
    assert len(result.blocks) == 3


def test_enigma_matches_the_standard_vector():
    # Enigma I, rotors I-II-III, reflector B, rings and start AAA: AAAAA -> BDZGO.
    settings = csk.classical.EnigmaSettings(("I", "II", "III"), "B")
    ciphertext = csk.classical.enigma_encrypt("AAAAA", settings, "AAA")
    assert ciphertext == "BDZGO"
    assert csk.classical.enigma_encrypt("BDZGO", settings, "AAA") == "AAAAA"


def test_enigma_middle_rotor_double_steps():
    # Rotor III turns II at V; II at its own notch E turns itself and I.
    settings = csk.classical.EnigmaSettings(("I", "II", "III"))
    assert csk.classical.enigma_positions(settings, "ADU", 3) == ("ADV", "AEW", "BFX")


def test_enigma_never_encrypts_a_letter_to_itself_and_plugboard_swaps():
    plugged = csk.classical.EnigmaSettings(("II", "IV", "V"), "B", "AV BS CG")
    bare = csk.classical.EnigmaSettings(("II", "IV", "V"), "B")
    plain = "WEATHERREPORTFORTHENORTHSEA"
    cipher = csk.classical.enigma_encrypt(plain, plugged, "QEV")
    assert all(p != c for p, c in zip(plain, cipher, strict=True))
    assert csk.classical.enigma_encrypt(cipher, plugged, "QEV") == plain
    assert cipher != csk.classical.enigma_encrypt(plain, bare, "QEV")


def test_rejewski_characteristic_ignores_the_plugboard():
    settings, start = csk.classical.EnigmaSettings(("III", "I", "II"), "B"), "KDO"
    bare = csk.classical.rejewski_characteristic(settings, start)
    plugged = csk.classical.rejewski_characteristic(
        csk.classical.EnigmaSettings(("III", "I", "II"), "B", "AQ BW CE DR FT GY"), start
    )
    assert bare == plugged
    for lengths in (bare.ad, bare.be, bare.cf):
        assert sum(lengths) == 26
        # Products of two involutions: every cycle length occurs an even number of times.
        assert all(lengths.count(n) % 2 == 0 for n in lengths)
    other = csk.classical.rejewski_characteristic(settings, "KDP")
    assert other != bare


def test_crib_positions_rule_out_self_encryption():
    # A crib cannot sit where any of its letters meets the same ciphertext letter.
    assert csk.classical.crib_positions("ABCDEF", "XB") == (1, 2, 3, 4)


def test_crib_menu_counts_edges_and_loops():
    menu = csk.classical.crib_menu("ETWB", "WEAT", 0)
    assert menu.edges == (("W", "E", 0), ("E", "T", 1), ("A", "W", 2), ("T", "B", 3))
    # W-E-T-? with A-W and T-B: a tree on 5 letters with 4 edges has no loop.
    assert menu.loops == 0
    assert csk.classical.crib_menu("EW", "WE", 0).loops == 1


def test_bombe_finds_the_rotor_start_from_a_crib():
    settings = csk.classical.EnigmaSettings(("I", "II", "III"), "B")
    message = "WETTERVORHERSAGEBISKAYA"
    ciphertext = csk.classical.enigma_encrypt(message, settings, "JXM")
    result = csk.classical.bombe_search(ciphertext, "WETTERVORHERSAGE", 0, settings)
    assert result.tested == 26**3
    assert result.positions == ("JXM",)


def test_lorenz_wheels_have_the_real_lengths_and_are_seeded():
    wheels = csk.classical.lorenz_wheels(seed=7)
    assert tuple(len(w) for w in wheels.chi) == (41, 31, 29, 26, 23)
    assert tuple(len(w) for w in wheels.psi) == (43, 47, 51, 53, 59)
    assert len(wheels.motor) == 61
    assert wheels == csk.classical.lorenz_wheels(seed=7) != csk.classical.lorenz_wheels(seed=8)
    stream = csk.classical.lorenz_keystream(wheels, 100)
    assert len(stream) == 100 and all(0 <= x < 32 for x in stream)


def test_tutte_period_test_finds_the_first_chi_wheel():
    # Tutte (1942): the delta of impulse 1 agrees with itself 41 places on more often.
    stream = csk.classical.lorenz_keystream(csk.classical.lorenz_wheels(seed=2026), 4000)
    bits = [x >> 4 & 1 for x in stream]
    result = csk.classical.tutte_period_test(bits, range(20, 70))
    assert result.best_period == 41
    assert result.agreement[result.periods.index(41)] > 0.55


def test_shift_cipher_leaks_on_two_letters_but_not_one():
    # AB shifts to BC with key 1; AC cannot become BC under any single shift.
    result = csk.classical.shift_cipher_posterior({"AB": 0.5, "AC": 0.5}, "BC")
    assert abs(result.posterior["AB"] - 1) < 1e-10 and abs(result.posterior["AC"]) < 1e-10
    assert not result.perfect
    # Shannon: one letter under a uniform shift key is perfectly secret.
    single = csk.classical.shift_cipher_posterior({"A": 0.7, "B": 0.3}, "Q")
    assert single.perfect and abs(single.posterior["A"] - 0.7) < 1e-10


def test_one_time_pad_posterior_equals_the_prior():
    result = csk.classical.one_time_pad_posterior({"AB": 0.5, "AC": 0.25, "ZZ": 0.25}, "BC")
    assert result.perfect
    assert all(abs(result.posterior[m] - result.prior[m]) < 1e-10 for m in result.prior)


def test_unicity_distance_of_simple_substitution():
    # Shannon (1949): log2 26! = 88.4 bits over a redundancy of about 3.2 bits per letter.
    result = csk.classical.unicity_distance(math.factorial(26))
    assert abs(result.key_entropy - 88.3817) < 1e-3
    assert abs(result.redundancy - 3.2004) < 1e-3
    assert abs(result.distance - 27.6) < 0.05
    assert csk.classical.unicity_distance(26).distance < 2


def test_substitution_key_maps_plain_to_cipher_letters():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    assert csk.classical.substitution_encrypt("abc xyz", key) == "QWEBNM"
    assert csk.classical.substitution_decrypt("QWEBNM", key) == "ABCXYZ"


def test_hill_climbing_recovers_a_substitution_plaintext():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = csk.classical.substitution_encrypt(LONG_TEXT, key)
    result = csk.classical.hill_climb_substitution(ciphertext, seed=2026, restarts=3)
    expected = csk.classical.substitution_decrypt(ciphertext, key)
    correct = sum(a == b for a, b in zip(result.plaintext, expected, strict=True))
    assert correct / len(expected) > 0.9
    assert list(result.history) == sorted(result.history)
    assert result.score == result.history[-1]
    assert csk.classical.substitution_decrypt(ciphertext, result.key) == result.plaintext


def test_homophonic_key_gives_common_letters_more_symbols():
    key = csk.classical.homophonic_key(seed=1, symbols=40)
    used = sorted(s for group in key.values() for s in group)
    assert used == list(range(40))
    assert all(key[c] for c in csk.constants.ALPHABET)
    assert len(key["E"]) >= len(key["T"]) >= len(key["Z"]) == 1


def test_homophonic_encryption_flattens_letter_counts_and_round_trips():
    key = csk.classical.homophonic_key(seed=1, symbols=40)
    symbols = csk.classical.homophonic_encrypt(LONG_TEXT, key)
    plain = "".join(ch for ch in LONG_TEXT.upper() if ch.isalpha())
    assert csk.classical.homophonic_decrypt(symbols, key) == plain
    top_letter = max(plain.count(c) for c in set(plain)) / len(plain)
    top_symbol = max(symbols.count(s) for s in set(symbols)) / len(symbols)
    assert top_symbol < top_letter / 2


def test_annealing_reads_most_of_a_homophonic_ciphertext():
    key = csk.classical.homophonic_key(seed=1, symbols=30)
    symbols = csk.classical.homophonic_encrypt(LONG_TEXT, key)
    plain = "".join(ch for ch in LONG_TEXT.upper() if ch.isalpha())
    result = csk.classical.solve_homophonic(symbols, seed=2026)
    correct = sum(a == b for a, b in zip(result.plaintext, plain, strict=True))
    assert correct / len(plain) > 0.8
    assert result.plaintext == "".join(result.mapping[s] for s in symbols)


def test_annealing_recovers_a_playfair_plaintext():
    ciphertext = csk.classical.playfair_encrypt(LONG_TEXT, "harbour master")
    result = csk.classical.break_playfair(ciphertext, seed=0, restarts=1, steps=20_000)
    assert result.plaintext == csk.classical.playfair_decrypt(ciphertext, "harbour master")
    # the square found may be a cyclic shift of the key square, which encrypts identically
    assert csk.classical.playfair_encrypt(result.plaintext, "".join(result.square)) == ciphertext
    assert result.tested == 20_001


def test_painvin_style_break_undoes_the_transposition_and_substitution():
    square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    ciphertext = csk.classical.adfgvx_encrypt(LONG_TEXT, square, "CARGO")
    result = csk.classical.break_adfgvx(ciphertext, 5)
    # CARGO reads its columns in alphabetical order of the keyword: A, C, G, O, R
    assert result.order == (1, 0, 3, 4, 2)
    plain = "".join(ch for ch in LONG_TEXT.upper() if ch.isalpha())
    # the substitution solver may swap a rare pair such as J and X
    assert sum(a == b for a, b in zip(result.plaintext, plain, strict=True)) / len(plain) > 0.99
    assert result.tested > 120


def test_spurious_shift_keys_die_out_after_a_few_letters():
    # text from the English sample itself, so the true key never fails the pair test
    text = " ".join(csk.classical.utils.english.CORPUS.split()[:12])
    result = csk.classical.spurious_shift_keys(csk.classical.shift_encrypt(text, 7))
    assert result.counts[0] == 26 and result.lengths[0] == 1
    assert list(result.counts) == sorted(result.counts, reverse=True)
    assert result.counts[-1] == 1 and result.unique_from is not None
    # Shannon's estimate for a shift cipher is under two letters; the real count is a few more
    assert 2 <= result.unique_from <= 10
    assert csk.classical.spurious_shift_keys("Q").unique_from is None


def test_spurious_shift_keys_keep_the_true_key_through_unseen_pairs():
    # the pair IZ never occurs in the English sample; the old all-or-nothing test dropped to 0
    text = "the quiz quickly questioned the bazaar keeper about the harbour"
    result = csk.classical.spurious_shift_keys(csk.classical.shift_encrypt(text, 11))
    assert min(result.counts) >= 1 and result.counts[-1] == 1
    assert result.unique_from is not None and result.unique_from < len(result.counts)


def test_attacks_report_their_cost():
    vigenere = csk.classical.break_vigenere(csk.classical.vigenere_encrypt(LONG_TEXT, "KEY"), 3)
    assert vigenere.tested == 26 * 3
    key = [[3, 3], [2, 5]]
    hill = csk.classical.hill_known_plaintext(
        "HELPMENOW", csk.classical.hill_encrypt("HELPMENOW", key), 2
    )
    assert hill.tested >= 1
    cipher = csk.classical.substitution_encrypt(LONG_TEXT, "QWERTYUIOPASDFGHJKLZXCVBNM")
    assert csk.classical.hill_climb_substitution(cipher, restarts=1).tested > 1
    symbols = csk.classical.homophonic_encrypt(LONG_TEXT, csk.classical.homophonic_key(seed=1))
    assert csk.classical.solve_homophonic(symbols).tested > 1
