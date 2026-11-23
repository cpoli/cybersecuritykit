"""Smoke tests for cybersecuritykit.classical.visualizers."""

import matplotlib.axes
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical.visualizers import (
    plot_climb_history,
    plot_coincidence_profile,
    plot_kasiski_factors,
    plot_letter_frequencies,
    plot_period_test,
    plot_posterior,
    plot_shift_scores,
)

cl = csk.classical
TEXT = "the quick brown fox jumps over the lazy dog while the cat sleeps by the fire " * 3


def teardown_function():
    plt.close("all")


def test_letter_frequencies_draw_text_and_english_bars():
    ax = plot_letter_frequencies(TEXT)
    assert isinstance(ax, matplotlib.axes.Axes)
    assert len(ax.patches) == 52


def test_shift_scores_title_the_recovered_shift_and_draw_on_given_axes():
    _, given = plt.subplots()
    ax = plot_shift_scores(cl.break_shift_cipher(cl.shift_encrypt(TEXT, 5)), ax=given)
    assert ax is given
    assert len(ax.patches) == 26
    assert ax.get_title() == "best shift: 5"


def test_coincidence_profile_and_kasiski_plots_mark_the_period():
    cipher = cl.vigenere_encrypt(TEXT, "KEY")
    ax = plot_coincidence_profile(cl.coincidence_profile(cipher, max_period=6))
    assert list(ax.lines[0].get_xdata()) == [1, 2, 3, 4, 5, 6]
    result = cl.kasiski_examination(cipher)
    ax = plot_kasiski_factors(result)
    assert ax.get_title() == f"likely period: {result.likely_period}"


def test_period_test_plot_titles_the_best_shift():
    stream = cl.lorenz_keystream(cl.lorenz_wheels(), 600)
    bits = [s >> 4 & 1 for s in stream]
    test = cl.tutte_period_test(bits, range(30, 50))
    assert plot_period_test(test).get_title() == "best period: 41"


def test_climb_history_plots_one_point_per_improvement():
    result = cl.hill_climb_substitution(
        cl.substitution_encrypt(TEXT, "QWERTYUIOPASDFGHJKLZXCVBNM"), restarts=1
    )
    assert len(plot_climb_history(result).lines[0].get_ydata()) == len(result.history)


def test_posterior_plot_says_whether_secrecy_is_perfect():
    prior = {"AB": 0.5, "CD": 0.25, "AA": 0.25}
    assert plot_posterior(cl.one_time_pad_posterior(prior, "XY")).get_title() == "perfect secrecy"
    leaky = plot_posterior(cl.shift_cipher_posterior(prior, "BB"))
    assert leaky.get_title() == "the ciphertext leaks information"
