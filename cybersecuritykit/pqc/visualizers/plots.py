"""Plotting functions for :mod:`cybersecuritykit.pqc`."""

from __future__ import annotations

# --- slice C ---
from collections import Counter
from collections.abc import Sequence

import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from cybersecuritykit.pqc.core.base import XMSSSignature
from cybersecuritykit.pqc.systems.sphincs import few_time_security
from cybersecuritykit.pqc.systems.winternitz import WINTERNITZ_WIDTHS, winternitz_cost

# --- end slice C ---
# isort: split
# --- slice B: codes and multivariate ---
from cybersecuritykit.pqc.core.base import QuadraticMap

# --- end slice B ---

__all__: list[str] = [
    # --- slice B: codes and multivariate ---
    "plot_binary_matrix",
    "plot_isd_iterations",
    "plot_quadratic_form",
    # --- end slice B ---
    # --- slice C ---
    "plot_auth_path",
    "plot_few_time_security",
    "plot_key_reuse",
    "plot_winternitz_tradeoff",
    # --- end slice C ---
]

# --- slice C ---
_OBSERVED = "#2563eb"
_REFERENCE = "#94a3b8"
_HIGHLIGHT = "#dc2626"


def _axes(ax: Axes | None) -> Axes:
    if ax is None:
        _, ax = plt.subplots()
    return ax


def plot_winternitz_tradeoff(
    n: int = 16, widths: Sequence[int] = WINTERNITZ_WIDTHS, ax: Axes | None = None
) -> Axes:
    """Signature size against hashing work, one point per Winternitz parameter.

    Parameters
    ----------
    n : int, optional
        Hash length in bytes.
    widths : sequence of int, optional
        Winternitz parameters to compare.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    costs = [winternitz_cost(n, w) for w in widths]
    ax.plot([c.signature_bytes for c in costs], [c.keygen_hashes for c in costs], "o-",
            color=_OBSERVED)  # fmt: skip
    for cost in costs:
        ax.annotate(f"w = {cost.w}", (cost.signature_bytes, cost.keygen_hashes),
                    textcoords="offset points", xytext=(6, 4))  # fmt: skip
    ax.set_yscale("log")
    ax.set_xlabel("signature bytes")
    ax.set_ylabel("hashes to make the public key")
    ax.set_title(f"Winternitz trade-off, n = {n} bytes")
    return ax


def plot_auth_path(signature: XMSSSignature, ax: Axes | None = None) -> Axes:
    """Draw the Merkle tree of an XMSS key with one signature's authentication path.

    The signing leaf and its path to the root are red; the sibling hashes the
    signature carries are blue; every other node is grey.

    Parameters
    ----------
    signature : XMSSSignature
        From :func:`~cybersecuritykit.pqc.systems.xmss.xmss_sign`; the tree height
        is the length of its path.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    height = len(signature.auth_path)
    path = {(level, signature.index >> level) for level in range(height + 1)}
    siblings = {(level, (signature.index >> level) ^ 1) for level in range(height)}
    for level in range(height + 1):
        for i in range(2 ** (height - level)):
            x = (i + 0.5) * 2**level
            if level:
                for child in (2 * i, 2 * i + 1):
                    ax.plot([x, (child + 0.5) * 2 ** (level - 1)], [level, level - 1],
                            color=_REFERENCE, lw=0.8, zorder=1)  # fmt: skip
            node = (level, i)
            color = _HIGHLIGHT if node in path else _OBSERVED if node in siblings else _REFERENCE
            ax.scatter([x], [level], s=60, color=color, zorder=2)
    ax.set_yticks(range(height + 1))
    ax.set_xticks([])
    ax.set_ylabel("level")
    ax.set_title(f"leaf {signature.index}: {height} sibling hashes reach the root")
    return ax


def plot_few_time_security(
    k: int, a: int, signatures: Sequence[int], ax: Axes | None = None
) -> Axes:
    """Bits of security of a few-time key as signatures accumulate.

    Parameters
    ----------
    k, a : int
        HORST parameters.
    signatures : sequence of int
        Signature counts to evaluate, each at least 1.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    bits = [few_time_security(k, a, r) for r in signatures]
    ax.plot(list(signatures), bits, "o-", color=_OBSERVED, label=f"k = {k}, a = {a}")
    ax.set_xscale("log")
    ax.set_xlabel("signatures made with one key")
    ax.set_ylabel("bits of security")
    ax.legend()
    return ax


def plot_key_reuse(indices: Sequence[int], ax: Axes | None = None) -> Axes:
    """How many few-time keys were used once, twice, and so on.

    Parameters
    ----------
    indices : sequence of int
        The few-time key each signature used, such as
        :attr:`~cybersecuritykit.pqc.core.base.SPHINCSSignature.index`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    uses = Counter(Counter(indices).values())
    counts = sorted(uses)
    colors = [_OBSERVED if c == 1 else _HIGHLIGHT for c in counts]
    ax.bar(counts, [uses[c] for c in counts], color=colors)
    ax.set_xticks(counts)
    ax.set_xlabel("signatures on the same few-time key")
    ax.set_ylabel("few-time keys")
    ax.set_title(f"{len(indices)} signatures on {sum(uses.values())} keys")
    return ax


# --- end slice C ---


# --- slice B: codes and multivariate ---
def plot_isd_iterations(
    iterations: Sequence[int], probability: float, ax: Axes | None = None
) -> Axes:
    """Histogram of Prange iteration counts beside the geometric law they follow.

    Each Prange guess succeeds independently with probability ``p``, so the iteration
    count is geometric with mean ``1 / p`` (Prange, 1962).

    Parameters
    ----------
    iterations : sequence of int
        Observed iteration counts, such as ``ISDResult.iterations`` over many seeds.
    probability : float
        Success probability of one guess, from
        :func:`~cybersecuritykit.pqc.prange_success_probability`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    top = max(iterations)
    counts = Counter(iterations)
    xs = range(1, top + 1)
    ax.bar(xs, [counts[x] / len(iterations) for x in xs], color=_OBSERVED, label="observed")
    expected = [probability * (1 - probability) ** (x - 1) for x in xs]
    ax.plot(xs, expected, "o-", color=_HIGHLIGHT, label="geometric law")
    ax.axvline(1 / probability, color=_REFERENCE, linestyle="--", label="mean 1/p")
    ax.set_xlabel("iterations until success")
    ax.set_ylabel("fraction of runs")
    ax.legend()
    return ax


def plot_binary_matrix(matrix: Sequence[Sequence[int]], ax: Axes | None = None) -> Axes:
    """Draw a binary matrix as black and white cells.

    Parameters
    ----------
    matrix : sequence of sequence of int
        Rows of 0 and 1 entries, such as a generator or parity-check matrix.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    ax.imshow([list(row) for row in matrix], cmap="Greys", vmin=0, vmax=1)
    ax.set_xlabel("column")
    ax.set_ylabel("row")
    return ax


def plot_quadratic_form(public: QuadraticMap, index: int, ax: Axes | None = None) -> Axes:
    """Heat map of the quadratic coefficients of one polynomial of a quadratic map.

    In an oil and vinegar central map the oil-by-oil block is zero (Patarin, 1997);
    after the secret change of variables the public polynomial is dense.

    Parameters
    ----------
    public : QuadraticMap
        The map whose polynomial to draw.
    index : int
        Which polynomial, ``0 <= index < public.n_polys``.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    quad = public.quadratic[index]
    ax.imshow([list(row) for row in quad], cmap="viridis", vmin=0, vmax=public.q - 1)
    ax.set_title(f"quadratic part of polynomial {index} over GF({public.q})")
    ax.set_xlabel("variable j")
    ax.set_ylabel("variable i")
    return ax


# --- end slice B ---
