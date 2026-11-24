"""Smoke tests for cybersecuritykit.pqc.visualizers."""

import dataclasses

import matplotlib.axes
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import (
    plot_auth_path,
    plot_binary_matrix,
    plot_few_time_security,
    plot_gram_schmidt_profile,
    plot_grover_success,
    plot_isd_iterations,
    plot_key_reuse,
    plot_quadratic_form,
    plot_shor_distribution,
    plot_signature_leakage,
    plot_winternitz_tradeoff,
)

pqc = csk.pqc


def teardown_function():
    plt.close("all")


def test_gram_schmidt_profile_draws_both_bases_on_a_log_scale():
    result = pqc.lll_reduce([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
    ax = plot_gram_schmidt_profile(result)
    assert isinstance(ax, matplotlib.axes.Axes)
    assert len(ax.lines) == 2
    assert list(ax.lines[1].get_ydata()) == list(result.norms_after)
    assert ax.get_yscale() == "log"
    assert ax.get_title() == f"LLL profile after {result.swaps} swaps"


def test_shor_distribution_marks_the_measured_outcomes():
    result = pqc.shor_factor(15, base=7, qubits=4, seed=2)
    _, given = plt.subplots()
    ax = plot_shor_distribution(result, ax=given)
    assert ax is given
    assert len(ax.patches) == 16
    red = {i for i, bar in enumerate(ax.patches) if bar.get_facecolor()[0] > 0.8}
    assert red == set(result.measurements)
    assert ax.get_title() == "Shor, $a = 7$ mod 15: period 4"
    missed = plot_shor_distribution(dataclasses.replace(result, period=None))
    assert missed.get_title().endswith("period missed")


def test_grover_success_plots_one_point_per_iteration():
    result = pqc.grover_search(6, [5], seed=1)
    ax = plot_grover_success(result)
    assert len(ax.lines[0].get_xdata()) == result.iterations + 1
    assert ax.lines[1].get_ydata()[0] == 1 / 64
    assert ax.get_title() == "Grover on 64 items, 1 marked"


def test_signature_leakage_draws_one_bar_group_per_estimate():
    keys = pqc.lyubashevsky_keygen(8, kappa=2, bound=16, seed=4)
    leaky = [pqc.lyubashevsky_sign(keys, b"m", seed=s, abort=False) for s in range(50)]
    safe = [pqc.lyubashevsky_sign(keys, b"m", seed=s) for s in range(50)]
    leaks = {
        "without aborts": pqc.lyubashevsky_leakage(keys.public, leaky),
        "with aborts": pqc.lyubashevsky_leakage(keys.public, safe),
    }
    ax = plot_signature_leakage(leaks, keys.s1)
    assert len(ax.patches) == 16
    assert list(ax.lines[0].get_ydata()) == list(keys.s1)
    assert [t.get_text() for t in ax.get_legend().get_texts()] == [
        "true $s_1$",
        "without aborts",
        "with aborts",
    ]


def test_isd_iterations_draw_one_bar_per_count_and_the_geometric_law():
    ax = plot_isd_iterations([1, 1, 2, 4], 0.5)
    assert isinstance(ax, matplotlib.axes.Axes)
    assert [p.get_height() for p in ax.patches] == [0.5, 0.25, 0.0, 0.25]
    assert list(ax.lines[0].get_ydata()) == [0.5, 0.25, 0.125, 0.0625]
    assert list(ax.lines[1].get_xdata()) == [2.0, 2.0]


def test_binary_matrix_draws_on_given_axes():
    _, given = plt.subplots()
    ax = plot_binary_matrix(((1, 0, 1), (0, 1, 1)), ax=given)
    assert ax is given
    assert ax.images[0].get_array().shape == (2, 3)


def test_quadratic_form_shows_the_chosen_polynomial():
    keys = pqc.uov_keygen(7, vinegar=4, oil=2, seed=0)
    ax = plot_quadratic_form(keys.private.central, 1)
    assert ax.get_title() == "quadratic part of polynomial 1 over GF(7)"
    assert ax.images[0].get_array().tolist() == [list(r) for r in keys.private.central.quadratic[1]]


def test_winternitz_tradeoff_marks_one_point_per_width():
    ax = plot_winternitz_tradeoff()
    assert isinstance(ax, matplotlib.axes.Axes)
    assert len(ax.lines[0].get_xdata()) == 4
    assert [t.get_text() for t in ax.texts] == ["w = 2", "w = 4", "w = 16", "w = 256"]


def test_auth_path_colours_the_path_and_draws_on_given_axes():
    key = pqc.xmss_keygen(5, height=3, n=8)
    signature = pqc.xmss_sign(key, b"block 0").signature
    _, given = plt.subplots()
    ax = plot_auth_path(signature, ax=given)
    assert ax is given
    assert len(ax.collections) == 15  # 8 + 4 + 2 + 1 nodes
    assert len(ax.lines) == 14  # one edge per non-root node
    assert ax.get_title() == "leaf 0: 3 sibling hashes reach the root"


def test_few_time_security_plots_one_point_per_count():
    ax = plot_few_time_security(8, 6, [1, 10, 100])
    assert list(ax.lines[0].get_xdata()) == [1, 10, 100]


def test_key_reuse_counts_keys_by_how_often_they_signed():
    ax = plot_key_reuse([0, 1, 1, 2, 2, 3])
    # Keys 0 and 3 signed once, keys 1 and 2 twice.
    assert [p.get_height() for p in ax.patches] == [2, 2]
    assert ax.get_title() == "6 signatures on 4 keys"
