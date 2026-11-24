"""Plotting functions for :mod:`cybersecuritykit.pqc`."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from cybersecuritykit.pqc.core.base import (
    GroverResult,
    LLLResult,
    QuadraticMap,
    ShorResult,
    SignatureLeakage,
    XMSSSignature,
)
from cybersecuritykit.pqc.systems.sphincs import few_time_security
from cybersecuritykit.pqc.systems.winternitz import WINTERNITZ_WIDTHS, winternitz_cost

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

_OBSERVED = "#2563eb"
_REFERENCE = "#94a3b8"
_HIGHLIGHT = "#dc2626"


def _axes(ax: Axes | None) -> Axes:
    if ax is None:
        _, ax = plt.subplots()
    return ax


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
        :func:`~cybersecuritykit.pqc.systems.isd.prange_success_probability`.
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


def plot_gram_schmidt_profile(result: LLLResult, ax: Axes | None = None) -> Axes:
    """Gram-Schmidt lengths of a basis before and after LLL reduction.

    A reduced basis has a flatter profile: the lengths fall off slowly, so the
    first vector is short. The product of the lengths, the lattice volume, does
    not change.

    Parameters
    ----------
    result : LLLResult
        From :func:`~cybersecuritykit.pqc.systems.lattice.lll_reduce`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    index = range(1, len(result.norms_before) + 1)
    ax.plot(index, result.norms_before, "o--", color=_REFERENCE, label="input basis")
    ax.plot(index, result.norms_after, "o-", color=_OBSERVED, label="LLL-reduced")
    ax.set_yscale("log")
    ax.set_xticks(list(index))
    ax.set_xlabel("basis vector $i$")
    ax.set_ylabel(r"Gram-Schmidt length $\|b_i^*\|$")
    ax.set_title(f"LLL profile after {result.swaps} swaps")
    ax.legend()
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


def plot_shor_distribution(result: ShorResult, ax: Axes | None = None) -> Axes:
    """Outcome probabilities of Shor's first register, with the shots taken.

    The peaks sit near multiples of :math:`Q / r`; the measured outcomes are red.

    Parameters
    ----------
    result : ShorResult
        From :func:`~cybersecuritykit.pqc.systems.shor.shor_factor`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    seen = set(result.measurements)
    colors = [_HIGHLIGHT if y in seen else _OBSERVED for y in range(len(result.distribution))]
    ax.bar(range(len(result.distribution)), result.distribution, width=1.0, color=colors)
    ax.set_xlabel("measured $y$")
    ax.set_ylabel("probability")
    period = "missed" if result.period is None else str(result.period)
    ax.set_title(f"Shor, $a = {result.base}$ mod {result.n}: period {period}")
    return ax


def plot_grover_success(result: GroverResult, ax: Axes | None = None) -> Axes:
    """Probability of measuring a marked item after each Grover iteration.

    Parameters
    ----------
    result : GroverResult
        From :func:`~cybersecuritykit.pqc.systems.grover.grover_search`.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    steps = range(len(result.success))
    ax.plot(steps, result.success, "o-", color=_OBSERVED)
    ax.axhline(len(result.marked) / 2**result.qubits, color=_REFERENCE, linestyle="--",
               label="random guess")  # fmt: skip
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("Grover iterations")
    ax.set_ylabel("success probability")
    ax.set_title(f"Grover on {2**result.qubits} items, {len(result.marked)} marked")
    ax.legend()
    return ax


def plot_signature_leakage(
    leaks: dict[str, SignatureLeakage], secret: Sequence[int], ax: Axes | None = None
) -> Axes:
    """Compare secret-key estimates averaged from signatures with the real key.

    Parameters
    ----------
    leaks : dict of str to SignatureLeakage
        Estimates from :func:`~cybersecuritykit.pqc.systems.aborts.lyubashevsky_leakage`,
        keyed by a legend label.
    secret : sequence of int
        The true secret :math:`s_1`, drawn as black markers.
    ax : matplotlib.axes.Axes, optional
        Axes to draw on; a new figure is created if omitted.

    Returns
    -------
    matplotlib.axes.Axes
    """
    ax = _axes(ax)
    width = 0.8 / max(len(leaks), 1)
    colors = [_REFERENCE, _HIGHLIGHT, _OBSERVED]
    for k, (label, leak) in enumerate(leaks.items()):
        x = [i + (k - (len(leaks) - 1) / 2) * width for i in range(len(leak.estimate))]
        ax.bar(x, leak.estimate, width=width, color=colors[k % 3], label=label)
    ax.plot(range(len(secret)), secret, "k_", markersize=14, label="true $s_1$")
    ax.set_xlabel("coefficient")
    ax.set_ylabel(r"mean of $c^* z_1 / \kappa$")
    ax.set_title("What averaged signatures reveal about the key")
    ax.legend()
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
