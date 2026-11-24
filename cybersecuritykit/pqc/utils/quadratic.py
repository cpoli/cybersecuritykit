"""Building quadratic maps by interpolation, and their polar (bilinear) forms."""

from collections.abc import Callable, Sequence

from cybersecuritykit.pqc.core.base import QuadraticMap

__all__ = ["interpolate", "polar_matrix", "symmetric_forms"]


def interpolate(f: Callable[[list[int]], Sequence[int]], n: int, q: int) -> QuadraticMap:
    """Recover the coefficients of a black-box quadratic map on GF(q)^n.

    With ``c = f(0)``: ``Q_ij = f(e_i + e_j) - f(e_i) - f(e_j) + c`` for ``i < j``. Over
    GF(2), ``x^2 = x`` so ``L_i = f(e_i) - c``; for odd ``q``,
    ``Q_ii = (f(e_i) + f(-e_i) - 2c) / 2`` and ``L_i = (f(e_i) - f(-e_i)) / 2``.
    """

    def unit(*pairs: tuple[int, int]) -> list[int]:
        x = [0] * n
        for i, value in pairs:
            x[i] = value
        return x

    c = list(f([0] * n))
    m = len(c)
    plus = [list(f(unit((i, 1)))) for i in range(n)]
    minus = [list(f(unit((i, q - 1)))) for i in range(n)]
    half = pow(2, -1, q) if q > 2 else 0
    quadratic = [[[0] * n for _ in range(n)] for _ in range(m)]
    linear = [[0] * n for _ in range(m)]
    for i in range(n):
        for k in range(m):
            if q == 2:
                linear[k][i] = (plus[i][k] - c[k]) % q
            else:
                quadratic[k][i][i] = (plus[i][k] + minus[i][k] - 2 * c[k]) * half % q
                linear[k][i] = (plus[i][k] - minus[i][k]) * half % q
        for j in range(i + 1, n):
            both = f(unit((i, 1), (j, 1)))
            for k in range(m):
                quadratic[k][i][j] = (both[k] - plus[i][k] - plus[j][k] + c[k]) % q
    return QuadraticMap(
        q,
        tuple(tuple(tuple(row) for row in quad) for quad in quadratic),
        tuple(tuple(row) for row in linear),
        tuple(x % q for x in c),
    )


def symmetric_forms(p: QuadraticMap) -> list[list[list[int]]]:
    """``M_k = Q_k + Q_k^T``, so that ``P(x + y) - P(x) - P(y) + P(0) = x^T M_k y``."""
    n, q = p.n_vars, p.q
    return [
        [[(quad[i][j] + quad[j][i]) % q for j in range(n)] for i in range(n)]
        for quad in p.quadratic
    ]


def polar_matrix(
    forms: Sequence[Sequence[Sequence[int]]], x: Sequence[int], q: int
) -> list[list[int]]:
    """The ``m x n`` matrix of the linear map ``D_x : y -> (x^T M_k y)_k``."""
    return [
        [sum(xi * row[j] for xi, row in zip(x, form, strict=True)) % q for j in range(len(x))]
        for form in forms
    ]
