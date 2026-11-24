"""Matplotlib figures for :mod:`cybersecuritykit.pqc`.

Not imported by the subpackage, so ``import cybersecuritykit`` stays stdlib-only.
"""

# --- slice C ---
from cybersecuritykit.pqc.visualizers.plots import (
    plot_auth_path,
    plot_few_time_security,
    plot_key_reuse,
    plot_winternitz_tradeoff,
)

# --- end slice C ---

__all__: list[str] = [
    # --- slice C ---
    "plot_auth_path",
    "plot_few_time_security",
    "plot_key_reuse",
    "plot_winternitz_tradeoff",
    # --- end slice C ---
]
