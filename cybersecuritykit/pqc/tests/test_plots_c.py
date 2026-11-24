"""Smoke tests for the hash-based signature plots of cybersecuritykit.pqc.visualizers."""

import matplotlib.axes
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import (
    plot_auth_path,
    plot_few_time_security,
    plot_key_reuse,
    plot_winternitz_tradeoff,
)

pqc = csk.pqc


def teardown_function():
    plt.close("all")


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
