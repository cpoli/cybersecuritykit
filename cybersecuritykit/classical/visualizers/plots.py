"""Matplotlib figures for :mod:`cybersecuritykit.classical`.

Not imported by the subpackage, so ``import cybersecuritykit`` stays stdlib-only.
"""

from __future__ import annotations

import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from cybersecuritykit.classical.core.base import (
    CoincidenceProfile,
    HillClimbResult,
    KasiskiResult,
    PeriodTest,
    SecrecyResult,
    ShiftBreakResult,
)
from cybersecuritykit.classical.systems.frequency import letter_frequencies
from cybersecuritykit.classical.utils.english import ENGLISH_FREQUENCIES
from cybersecuritykit.constants import ALPHABET

__all__ = [
    "plot_climb_history",
    "plot_coincidence_profile",
    "plot_kasiski_factors",
    "plot_letter_frequencies",
    "plot_period_test",
    "plot_posterior",
    "plot_shift_scores",
]

_OBSERVED = "#2563eb"
_REFERENCE = "#94a3b8"
_HIGHLIGHT = "#dc2626"


def _axes(ax: Axes | None) -> Axes:
    if ax is None:
        _, ax = plt.subplots()
    return ax


def plot_letter_frequencies(text: str, ax: Axes | None = None) -> Axes:
    """Bar chart of the letter frequencies of ``text`` beside English.

    Parameters
    ----------
    text : str
        Any text with at least one letter.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    observed = letter_frequencies(text)
    x = range(26)
    ax.bar([i - 0.2 for i in x], [observed[c] for c in ALPHABET], 0.4, color=_OBSERVED,
           label="text")  # fmt: skip
    ax.bar([i + 0.2 for i in x], [ENGLISH_FREQUENCIES[c] / 100 for c in ALPHABET], 0.4,
           color=_REFERENCE, label="English")  # fmt: skip
    ax.set_xticks(list(x), list(ALPHABET))
    ax.set_ylabel("fraction of letters")
    ax.legend()
    return ax


def plot_shift_scores(result: ShiftBreakResult, ax: Axes | None = None) -> Axes:
    r"""Plot the :math:`\chi^2` score of every shift, marking the one chosen.

    Parameters
    ----------
    result : ShiftBreakResult
        From :func:`~cybersecuritykit.classical.systems.frequency.break_shift_cipher`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    colors = [_HIGHLIGHT if s == result.shift else _REFERENCE for s in range(26)]
    ax.bar(range(26), result.chi_squared, color=colors)
    ax.set_xlabel("shift")
    ax.set_ylabel(r"$\chi^2$ against English")
    ax.set_title(f"best shift: {result.shift}")
    return ax


def plot_coincidence_profile(profile: CoincidenceProfile, ax: Axes | None = None) -> Axes:
    """Plot mean column index of coincidence against candidate period.

    Parameters
    ----------
    profile : CoincidenceProfile
        From :func:`~cybersecuritykit.classical.systems.coincidence.coincidence_profile`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    ax.plot(profile.periods, profile.mean_ic, "o-", color=_OBSERVED)
    ax.axhline(0.0667, color=_REFERENCE, linestyle="--", label="English, 0.067")
    ax.axhline(1 / 26, color=_REFERENCE, linestyle=":", label="random, 0.038")
    ax.axvline(profile.best_period, color=_HIGHLIGHT, alpha=0.4)
    ax.set_xlabel("candidate period")
    ax.set_ylabel("mean index of coincidence")
    ax.legend()
    return ax


def plot_kasiski_factors(result: KasiskiResult, ax: Axes | None = None) -> Axes:
    """Bar chart of how many repeat gaps each candidate period divides.

    Parameters
    ----------
    result : KasiskiResult
        From :func:`~cybersecuritykit.classical.systems.kasiski.kasiski_examination`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    periods = sorted(result.factor_counts)
    colors = [_HIGHLIGHT if p == result.likely_period else _OBSERVED for p in periods]
    ax.bar(periods, [result.factor_counts[p] for p in periods], color=colors)
    ax.set_xlabel("candidate period")
    ax.set_ylabel("gaps divided")
    ax.set_title(f"likely period: {result.likely_period}")
    return ax


def plot_period_test(test: PeriodTest, ax: Axes | None = None) -> Axes:
    """Plot delta-stream self-agreement against shift, as in Tutte's analysis.

    Parameters
    ----------
    test : PeriodTest
        From :func:`~cybersecuritykit.classical.systems.lorenz.tutte_period_test`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    ax.plot(test.periods, test.agreement, ".-", color=_OBSERVED)
    ax.axhline(0.5, color=_REFERENCE, linestyle="--", label="chance")
    ax.axvline(test.best_period, color=_HIGHLIGHT, alpha=0.4)
    ax.set_xlabel("shift")
    ax.set_ylabel("agreement")
    ax.set_title(f"best period: {test.best_period}")
    ax.legend()
    return ax


def plot_climb_history(result: HillClimbResult, ax: Axes | None = None) -> Axes:
    """Plot the best score after each accepted improvement of a hill climb.

    Parameters
    ----------
    result : HillClimbResult
        From :func:`~cybersecuritykit.classical.systems.hillclimb.hill_climb_substitution`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    ax.plot(range(len(result.history)), result.history, color=_OBSERVED)
    ax.set_xlabel("accepted improvement")
    ax.set_ylabel("bigram log-likelihood")
    return ax


def plot_posterior(result: SecrecyResult, ax: Axes | None = None) -> Axes:
    """Bar chart of prior and posterior probability for each message.

    Parameters
    ----------
    result : SecrecyResult
        From :func:`~cybersecuritykit.classical.systems.shannon.shift_cipher_posterior` or
        :func:`~cybersecuritykit.classical.systems.shannon.one_time_pad_posterior`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    messages = list(result.prior)
    x = range(len(messages))
    ax.bar([i - 0.2 for i in x], [result.prior[m] for m in messages], 0.4, color=_REFERENCE,
           label="prior")  # fmt: skip
    ax.bar([i + 0.2 for i in x], [result.posterior[m] for m in messages], 0.4,
           color=_OBSERVED, label="posterior")  # fmt: skip
    ax.set_xticks(list(x), messages)
    ax.set_ylabel("probability")
    ax.set_title("perfect secrecy" if result.perfect else "the ciphertext leaks information")
    ax.legend()
    return ax
