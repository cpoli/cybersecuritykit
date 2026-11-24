"""Smoke tests for the code-based and multivariate plots of cybersecuritykit.pqc.visualizers."""

import matplotlib.axes
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import (
    plot_binary_matrix,
    plot_isd_iterations,
    plot_quadratic_form,
)

pqc = csk.pqc


def teardown_function():
    plt.close("all")


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
