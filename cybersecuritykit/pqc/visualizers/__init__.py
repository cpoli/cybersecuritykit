"""Matplotlib figures for :mod:`cybersecuritykit.pqc`.

Not imported by the subpackage, so ``import cybersecuritykit`` stays stdlib-only.
"""

from cybersecuritykit.pqc.visualizers.plots import (
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

__all__: list[str] = [
    "plot_auth_path",
    "plot_binary_matrix",
    "plot_few_time_security",
    "plot_gram_schmidt_profile",
    "plot_grover_success",
    "plot_isd_iterations",
    "plot_key_reuse",
    "plot_quadratic_form",
    "plot_shor_distribution",
    "plot_signature_leakage",
    "plot_winternitz_tradeoff",
]
