"""Grover's search on a simulated state vector (1996).

L. K. Grover, "A fast quantum mechanical algorithm for database search",
*Proceedings of the 28th Annual ACM Symposium on Theory of Computing*,
212-219 (1996). Start from the uniform superposition over :math:`N = 2^m`
items, and repeat two reflections: the oracle flips the sign of the
:math:`M` marked items, and the diffusion operator reflects every amplitude
about the mean. Each iteration rotates the state by :math:`2\\theta` towards
the marked items, :math:`\\sin \\theta = \\sqrt{M/N}`, so about
:math:`\\frac{\\pi}{4} \\sqrt{N/M}` iterations find one. Bennett, Bernstein,
Brassard and Vazirani proved no quantum algorithm does better, which is why a
:math:`k`-bit key keeps :math:`k/2` bits of security.

Amplitudes stay real throughout, so the state is a list of floats.
"""

import math
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import GroverResult

__all__ = ["grover_iterations", "grover_search"]

MAX_QUBITS = 16
"""Largest simulated register: :math:`2^{16}` amplitudes."""


def grover_iterations(space: int, marked: int = 1) -> int:
    r"""The iteration count :math:`\lfloor \pi / (4 \theta) \rfloor`, :math:`\sin \theta = \sqrt{M/N}`.

    Parameters
    ----------
    space : int
        Number of items :math:`N`.
    marked : int, optional
        Number of marked items :math:`M`, from 1 to :math:`N`.

    Returns
    -------
    int

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.grover_iterations(2**20)
    804
    """
    _validation.integer(space, "space", minimum=1)
    _validation.integer(marked, "marked", minimum=1)
    if marked > space:
        raise ValueError("marked must be at most space")
    return math.floor(math.pi / (4 * math.asin(math.sqrt(marked / space))))


def grover_search(
    qubits: int,
    marked: Sequence[int],
    iterations: int | None = None,
    seed: int = DEFAULT_SEED,
) -> GroverResult:
    """Run Grover iterations on :math:`2^m` amplitudes, then measure once.

    Parameters
    ----------
    qubits : int
        Register size :math:`m`, 1 to 16.
    marked : sequence of int
        Distinct marked items in :math:`[0, 2^m)`, at least one.
    iterations : int, optional
        Defaults to :func:`grover_iterations`.
    seed : int, optional
        Seed of the final measurement.

    Returns
    -------
    GroverResult

    Raises
    ------
    ValueError
        A register out of range, or marked items empty, repeated or out of range.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> result = pqc.grover_search(8, [42], seed=1)
    >>> result.iterations, round(result.success[-1], 4), result.found
    (12, 0.9999, True)
    """
    _validation.integer(qubits, "qubits", minimum=1)
    if qubits > MAX_QUBITS:
        raise ValueError(f"qubits must be at most {MAX_QUBITS}")
    space = 1 << qubits
    targets = tuple(sorted(marked))
    for x in targets:
        _validation.integer(x, "marked")
    if not targets or targets[-1] >= space or len(set(targets)) < len(targets):
        raise ValueError("marked must hold distinct items of the search space")
    if iterations is None:
        iterations = grover_iterations(space, len(targets))
    _validation.integer(iterations, "iterations")
    _validation.seed(seed)
    state = [1 / math.sqrt(space)] * space
    success = [sum(state[x] ** 2 for x in targets)]
    for _ in range(iterations):
        for x in targets:
            state[x] = -state[x]
        twice_mean = 2 * sum(state) / space
        state = [twice_mean - a for a in state]
        success.append(sum(state[x] ** 2 for x in targets))
    measured = random.Random(seed).choices(range(space), weights=[a * a for a in state])[0]
    return GroverResult(qubits, targets, iterations, tuple(success), measured, measured in targets)
