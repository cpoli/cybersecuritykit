"""Smoke tests for the lattice and quantum plots of cybersecuritykit.pqc.visualizers."""

import dataclasses

import matplotlib.axes
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import (
    plot_gram_schmidt_profile,
    plot_grover_success,
    plot_shor_distribution,
    plot_signature_leakage,
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
