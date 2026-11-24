"""Prange's information-set decoding (1962), the generic attack on code-based schemes.

E. Prange, "The use of information sets in decoding cyclic codes", *IRE Transactions
on Information Theory* 8(5), 1962, S5-S9. To find a low-weight ``e`` with
``H e = s`` for an ``r x n`` parity-check matrix ``H``, guess ``r`` positions that
hold every error. If those columns of ``H`` are invertible, the guess fixes ``e``
by Gaussian elimination; it is right when ``e`` has weight at most ``t``. A random
guess is right with probability ``C(n - t, k) / C(n, k)``, so the expected work is
the inverse of that ratio, the number every McEliece parameter set is sized against.
"""

import math
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import ISDResult
from cybersecuritykit.pqc.utils import binary

__all__ = ["prange_isd", "prange_success_probability", "syndrome"]


def syndrome(parity_check: Sequence[Sequence[int]], word: Sequence[int]) -> tuple[int, ...]:
    """Return the syndrome ``H w`` over GF(2).

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.syndrome(((1, 0, 1), (0, 1, 1)), (1, 1, 0))
    (1, 1)
    """
    rows, n = binary.check_matrix(parity_check, "parity_check")
    w = binary.pack(binary.check_vector(word, n, "word"))
    return binary.unpack(binary.mat_vec(rows, w), len(rows))


def prange_success_probability(n: int, k: int, t: int) -> float:
    """Probability that one random information set of size ``k`` misses all ``t`` errors.

    Parameters
    ----------
    n, k, t : int
        Code length, dimension and error weight, with ``0 <= k <= n`` and ``0 <= t <= n``.

    Returns
    -------
    float
        ``C(n - t, k) / C(n, k)``; one Prange iteration succeeds with this probability.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> round(pqc.prange_success_probability(7, 4, 1), 4)
    0.4286
    """
    _validation.integer(n, "n", minimum=1)
    _validation.integer(k, "k")
    _validation.integer(t, "t")
    if k > n:
        raise ValueError("k must be at most n")
    if t > n:
        raise ValueError("t must be at most n")
    return math.comb(n - t, k) / math.comb(n, k)


def prange_isd(
    parity_check: Sequence[Sequence[int]],
    target: Sequence[int],
    t: int,
    seed: int = DEFAULT_SEED,
    max_iterations: int = 100_000,
) -> ISDResult:
    """Find an error of weight at most ``t`` with syndrome ``target`` by Prange's method.

    Parameters
    ----------
    parity_check : sequence of sequence of int
        A binary ``r x n`` matrix of full row rank ``r``.
    target : sequence of int
        The syndrome, ``r`` bits.
    t : int
        The largest error weight accepted.
    seed : int, optional
        Seed for the random choice of column sets.
    max_iterations : int, optional
        How many column sets to try, singular ones included.

    Returns
    -------
    ISDResult
        The error, the iteration that found it and the ``r`` columns that held it.

    Raises
    ------
    RuntimeError
        No error of weight ``t`` or less was found within ``max_iterations``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> h = ((1, 0, 1, 0, 1, 0, 1), (0, 1, 1, 0, 0, 1, 1), (0, 0, 0, 1, 1, 1, 1))
    >>> pqc.prange_isd(h, (1, 0, 1), 1, seed=2026).error
    (0, 0, 0, 0, 1, 0, 0)
    """
    rows, n = binary.check_matrix(parity_check, "parity_check")
    r = len(rows)
    s = binary.pack(binary.check_vector(target, r, "syndrome"))
    _validation.integer(t, "t")
    _validation.seed(seed)
    _validation.integer(max_iterations, "max_iterations", minimum=1)
    if len(binary.rref(rows, range(n))[1]) < r:
        raise ValueError("parity_check must have full row rank")
    augmented = [row | (((s >> i) & 1) << n) for i, row in enumerate(rows)]
    rng = random.Random(seed)
    for iteration in range(1, max_iterations + 1):
        columns = sorted(rng.sample(range(n), r))
        reduced, pivots = binary.rref(augmented, columns)
        if len(pivots) < r:
            continue  # these columns are singular: Prange counts the wasted guess
        error = sum(((row >> n) & 1) << col for row, col in zip(reduced, pivots, strict=True))
        if bin(error).count("1") <= t:
            return ISDResult(binary.unpack(error, n), iteration, tuple(columns))
    raise RuntimeError(f"no error of weight <= {t} found in {max_iterations} iterations")
