"""Plotting functions for :mod:`cybersecuritykit.classical`.

Imports matplotlib, so ``import cybersecuritykit`` does not load this module;
import it explicitly: ``from cybersecuritykit.classical.visualizers import ...``.
"""

from cybersecuritykit.classical.visualizers.plots import (
    plot_climb_history,
    plot_coincidence_profile,
    plot_kasiski_factors,
    plot_letter_frequencies,
    plot_period_test,
    plot_posterior,
    plot_shift_scores,
)

__all__ = [
    "plot_climb_history",
    "plot_coincidence_profile",
    "plot_kasiski_factors",
    "plot_letter_frequencies",
    "plot_period_test",
    "plot_posterior",
    "plot_shift_scores",
]
