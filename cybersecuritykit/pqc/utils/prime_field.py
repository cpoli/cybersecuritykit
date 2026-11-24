"""Linear algebra over a prime field GF(q), on matrices stored as lists of rows."""

import random
from collections.abc import Iterable, Sequence

__all__ = [
    "Matrix",
    "check_prime",
    "identity",
    "inverse",
    "is_prime",
    "mat_vec",
    "nullspace",
    "prime_power_base",
    "random_invertible",
    "rank",
    "rref",
    "smallest_factor",
    "solve",
]

Matrix = list[list[int]]


def smallest_factor(n: int) -> int:
    """The smallest prime factor of ``n >= 2``, by trial division: enough for toy sizes."""
    d = 2
    while d * d <= n:
        if n % d == 0:
            return d
        d += 1
    return n


def is_prime(q: int) -> bool:
    """Whether ``q`` is prime."""
    return q >= 2 and smallest_factor(q) == q


def prime_power_base(n: int) -> int | None:
    """The prime ``p`` with ``n = p^k`` for some ``k >= 1``, or ``None`` if there is none."""
    p = smallest_factor(n)
    while n % p == 0:
        n //= p
    return p if n == 1 else None


def check_prime(q: int, name: str, *, odd: bool = False) -> None:
    """Raise :class:`ValueError` unless the integer ``q`` is prime (and odd, if asked)."""
    if not is_prime(q) or (odd and q == 2):
        raise ValueError(f"{name} must be {'an odd prime' if odd else 'prime'}")


def identity(n: int) -> Matrix:
    """The ``n x n`` identity matrix."""
    return [[int(i == j) for j in range(n)] for i in range(n)]


def rref(rows: Sequence[Sequence[int]], q: int, columns: Iterable[int]) -> tuple[Matrix, list[int]]:
    """Reduced row echelon form mod ``q``, pivoting only on ``columns`` in the given order."""
    out = [[x % q for x in row] for row in rows]
    pivots: list[int] = []
    for col in columns:
        r = len(pivots)
        hit = next((i for i in range(r, len(out)) if out[i][col]), None)
        if hit is None:
            continue
        out[r], out[hit] = out[hit], out[r]
        scale = pow(out[r][col], -1, q)
        out[r] = [x * scale % q for x in out[r]]
        for i, row in enumerate(out):
            if i != r and row[col]:
                c = row[col]
                out[i] = [(a - c * b) % q for a, b in zip(row, out[r], strict=True)]
        pivots.append(col)
    return out, pivots


def solve(
    a: Sequence[Sequence[int]], b: Sequence[int], n: int, q: int
) -> tuple[list[int] | None, Matrix]:
    """Solve ``a x = b`` for ``x`` in GF(q)^n.

    Returns a particular solution (``None`` when there is none) and a basis of the
    kernel of ``a``.
    """
    reduced, pivots = rref([list(row) + [y] for row, y in zip(a, b, strict=True)], q, range(n))
    consistent = all(not row[n] for row in reduced[len(pivots) :])
    particular = [0] * n
    for row, col in zip(reduced, pivots, strict=False):
        particular[col] = row[n]
    basis = []
    for free in sorted(set(range(n)) - set(pivots)):
        vector = [0] * n
        vector[free] = 1
        for row, col in zip(reduced, pivots, strict=False):
            vector[col] = -row[free] % q
        basis.append(vector)
    return (particular if consistent else None), basis


def nullspace(a: Sequence[Sequence[int]], n: int, q: int) -> Matrix:
    """A basis of ``{x : a x = 0}``."""
    return solve(a, [0] * len(a), n, q)[1]


def rank(a: Sequence[Sequence[int]], q: int) -> int:
    """Rank of a non-empty matrix mod ``q``."""
    return len(rref(a, q, range(len(a[0])))[1])


def mat_vec(a: Sequence[Sequence[int]], x: Sequence[int], q: int) -> list[int]:
    """``a x`` mod ``q``."""
    return [sum(c * y for c, y in zip(row, x, strict=True)) % q for row in a]


def inverse(a: Sequence[Sequence[int]], q: int) -> Matrix | None:
    """Inverse of a square matrix mod ``q``, or ``None`` if it is singular."""
    n = len(a)
    reduced, pivots = rref(
        [list(row) + unit for row, unit in zip(a, identity(n), strict=True)], q, range(n)
    )
    return [row[n:] for row in reduced] if len(pivots) == n else None


def random_invertible(n: int, q: int, rng: random.Random) -> Matrix:
    """A uniformly random invertible ``n x n`` matrix over GF(q), by rejection."""
    while True:
        a = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
        if rank(a, q) == n:
            return a
