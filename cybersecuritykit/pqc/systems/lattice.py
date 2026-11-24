"""LLL lattice basis reduction (Lenstra, Lenstra and Lovász, 1982).

A. K. Lenstra, H. W. Lenstra Jr. and L. Lovász, "Factoring polynomials with
rational coefficients", *Mathematische Annalen* 261, 515-534 (1982). The
algorithm alternates size reduction (subtract integer multiples of earlier
vectors) with swaps of neighbours that break the Lovász condition. This version
keeps the Gram-Schmidt data as exact fractions and updates it after each swap,
following H. Cohen, *A Course in Computational Algebraic Number Theory*
(Springer, 1993), Algorithm 2.6.3.
"""

import math
from collections.abc import Sequence
from fractions import Fraction

from cybersecuritykit import _validation
from cybersecuritykit.pqc.core.base import LLLResult
from cybersecuritykit.pqc.utils.rings import dot, int_vector

__all__ = ["lll_reduce"]


def _basis(rows: Sequence[Sequence[int]]) -> list[list[int]]:
    basis = [list(int_vector(row, "basis entry")) for row in rows]
    if not basis or not basis[0] or any(len(row) != len(basis[0]) for row in basis):
        raise ValueError("basis must be a non-empty list of rows of equal length")
    if len(basis) > len(basis[0]):
        raise ValueError("basis has more vectors than dimensions, so they are dependent")
    return basis


def _gram_schmidt(b: list[list[int]]) -> tuple[list[list[Fraction]], list[Fraction]]:
    """Return the coefficients ``mu`` and squared norms ``B`` of the Gram-Schmidt vectors."""
    n = len(b)
    mu = [[Fraction(0)] * n for _ in range(n)]
    norms: list[Fraction] = []
    for i in range(n):
        for j in range(i):
            mu[i][j] = (
                Fraction(dot(b[i], b[j])) - sum(mu[j][k] * mu[i][k] * norms[k] for k in range(j))
            ) / norms[j]
        norm = dot(b[i], b[i]) - sum(mu[i][k] ** 2 * norms[k] for k in range(i))
        if norm == 0:
            raise ValueError("basis vectors are linearly dependent")
        norms.append(Fraction(norm))
    return mu, norms


def lll_reduce(basis: Sequence[Sequence[int]], delta: float = 0.75) -> LLLResult:
    r"""Reduce a lattice basis with the LLL algorithm.

    A basis :math:`b_1, \dots, b_n` with Gram-Schmidt vectors :math:`b_i^*` and
    coefficients :math:`\mu_{ij}` is reduced when :math:`|\mu_{ij}| \le 1/2` and
    :math:`\|b_i^*\|^2 \ge (\delta - \mu_{i,i-1}^2)\|b_{i-1}^*\|^2`. Its first
    vector is then at most :math:`(4/(4\delta - 1))^{(n-1)/2}` times longer than
    the shortest vector of the lattice.

    Parameters
    ----------
    basis : sequence of sequence of int
        Linearly independent integer row vectors of equal length.
    delta : float, optional
        Lovász constant in :math:`(1/4, 1)`; 3/4 as in the original paper.

    Returns
    -------
    LLLResult
        The reduced basis, the number of swaps and the Gram-Schmidt norms.

    Raises
    ------
    ValueError
        The basis is empty, ragged or linearly dependent, or ``delta`` is out of range.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.lll_reduce([[1, 1, 1], [-1, 0, 2], [3, 5, 6]]).basis
    ((0, 1, 0), (1, 0, 1), (-1, 0, 2))
    """
    _validation.probability(delta, "delta")
    if not 0.25 < delta < 1:
        raise ValueError("delta must lie strictly between 1/4 and 1")
    b = _basis(basis)
    d = Fraction(delta)
    mu, norms = _gram_schmidt(b)
    before = tuple(math.sqrt(x) for x in norms)
    n, k, swaps = len(b), 1, 0
    while k < n:
        for j in range(k - 1, -1, -1):
            r = math.ceil(mu[k][j] - Fraction(1, 2))  # nearest integer, halves rounded down
            if r:
                b[k] = [x - r * y for x, y in zip(b[k], b[j], strict=True)]
                for i in range(j):
                    mu[k][i] -= r * mu[j][i]
                mu[k][j] -= r
        if norms[k] >= (d - mu[k][k - 1] ** 2) * norms[k - 1]:
            k += 1
            continue
        swaps += 1
        b[k], b[k - 1] = b[k - 1], b[k]
        m = mu[k][k - 1]
        new = norms[k] + m * m * norms[k - 1]
        mu[k][k - 1] = m * norms[k - 1] / new
        norms[k] = norms[k - 1] * norms[k] / new
        norms[k - 1] = new
        for j in range(k - 1):
            mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
        for i in range(k + 1, n):
            t = mu[i][k]
            mu[i][k] = mu[i][k - 1] - m * t
            mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
        k = max(k - 1, 1)
    after = tuple(math.sqrt(x) for x in norms)
    return LLLResult(tuple(tuple(row) for row in b), swaps, before, after)
