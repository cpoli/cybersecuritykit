"""Linear algebra over GF(2) with matrix rows packed into ``int`` bit masks.

Bit ``j`` of a row is the entry in column ``j``. A vector is packed the same
way, so ``row & x`` and a parity count give one entry of a matrix-vector
product. The public API works with tuples of 0s and 1s; these helpers convert.
"""

import random
from collections.abc import Sequence

__all__ = [
    "check_matrix",
    "check_vector",
    "inverse",
    "mat_vec",
    "nullspace",
    "pack",
    "permute_columns",
    "random_invertible",
    "rref",
    "unpack",
    "unpack_matrix",
    "vec_mat",
]

Matrix = tuple[tuple[int, ...], ...]


def check_vector(vector: Sequence[int], length: int, name: str) -> tuple[int, ...]:
    """Return ``vector`` as a tuple after checking its length and that it is binary."""
    bits = tuple(vector)
    if len(bits) != length:
        raise ValueError(f"{name} must have length {length}")
    if any(type(b) is not int or b not in (0, 1) for b in bits):
        raise ValueError(f"{name} entries must be 0 or 1")
    return bits


def check_matrix(matrix: Sequence[Sequence[int]], name: str) -> tuple[list[int], int]:
    """Pack a non-empty rectangular 0/1 matrix; return its rows and column count."""
    rows = [tuple(row) for row in matrix]
    if not rows or not rows[0]:
        raise ValueError(f"{name} must be a non-empty matrix")
    n = len(rows[0])
    if any(len(row) != n for row in rows):
        raise ValueError(f"{name} must be rectangular")
    return [pack(check_vector(row, n, name)) for row in rows], n


def pack(bits: Sequence[int]) -> int:
    """Pack a 0/1 sequence into an ``int``, entry ``j`` in bit ``j``."""
    return sum(b << j for j, b in enumerate(bits))


def unpack(x: int, n: int) -> tuple[int, ...]:
    """Unpack the low ``n`` bits of ``x`` into a tuple."""
    return tuple((x >> j) & 1 for j in range(n))


def unpack_matrix(rows: Sequence[int], n: int) -> Matrix:
    """Unpack a list of packed rows of width ``n``."""
    return tuple(unpack(row, n) for row in rows)


def mat_vec(rows: Sequence[int], x: int) -> int:
    """Return ``A x`` packed: bit ``i`` is the parity of ``rows[i] & x``."""
    return sum((bin(row & x).count("1") & 1) << i for i, row in enumerate(rows))


def vec_mat(x: int, rows: Sequence[int]) -> int:
    """Return ``x A`` packed: the XOR of the rows selected by the bits of ``x``."""
    out = 0
    for i, row in enumerate(rows):
        if (x >> i) & 1:
            out ^= row
    return out


def rref(rows: Sequence[int], columns: Sequence[int]) -> tuple[list[int], list[int]]:
    """Reduce rows to reduced row echelon form, pivoting only on ``columns`` in order.

    Returns the reduced rows (non-zero rows first, one per pivot) and the pivot columns.
    """
    work = list(rows)
    pivots: list[int] = []
    for col in columns:
        r = len(pivots)
        pivot = next((i for i in range(r, len(work)) if (work[i] >> col) & 1), None)
        if pivot is None:
            continue
        work[r], work[pivot] = work[pivot], work[r]
        for i in range(len(work)):
            if i != r and (work[i] >> col) & 1:
                work[i] ^= work[r]
        pivots.append(col)
    return work, pivots


def nullspace(rows: Sequence[int], n: int) -> list[int]:
    """Basis of ``{x : A x = 0}`` for an ``A`` with ``n`` columns."""
    reduced, pivots = rref(rows, range(n))
    basis = []
    for free in (j for j in range(n) if j not in pivots):
        x = 1 << free
        for row, col in zip(reduced, pivots, strict=False):
            if (row >> free) & 1:
                x |= 1 << col
        basis.append(x)
    return basis


def inverse(rows: Sequence[int], n: int) -> list[int] | None:
    """Inverse of a square ``n x n`` matrix, or ``None`` if it is singular."""
    augmented = [row | (1 << (n + i)) for i, row in enumerate(rows)]
    reduced, pivots = rref(augmented, range(n))
    if len(pivots) < n:
        return None
    return [row >> n for row in reduced]


def random_invertible(n: int, rng: random.Random) -> list[int]:
    """A uniformly random invertible ``n x n`` matrix, by rejection sampling."""
    while True:
        rows = [rng.getrandbits(n) for _ in range(n)]
        if inverse(rows, n) is not None:
            return rows


def permute_columns(rows: Sequence[int], permutation: Sequence[int]) -> list[int]:
    """Column ``j`` of the result is column ``permutation[j]`` of the input."""
    return [sum(((row >> src) & 1) << j for j, src in enumerate(permutation)) for row in rows]
