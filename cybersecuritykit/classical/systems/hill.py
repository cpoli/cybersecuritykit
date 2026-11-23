"""Hill's matrix cipher (1929) and its known-plaintext break.

L. S. Hill, "Cryptography in an algebraic alphabet", *American Mathematical
Monthly* 36(6), 1929. Blocks of ``n`` letters are column vectors multiplied by
an invertible ``n x n`` key matrix mod 26. The map is linear, so ``n``
plaintext blocks with an invertible matrix and their ciphertexts give the key.
"""

from collections.abc import Sequence
from itertools import combinations

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import HillBreakResult
from cybersecuritykit.classical.utils.text import clean, to_letters, to_numbers

__all__ = ["hill_decrypt", "hill_encrypt", "hill_inverse", "hill_known_plaintext"]

Matrix = tuple[tuple[int, ...], ...]


def _matrix(key: Sequence[Sequence[int]]) -> Matrix:
    rows = tuple(tuple(row) for row in key)
    n = len(rows)
    if n == 0 or any(len(row) != n for row in rows):
        raise ValueError("key must be a non-empty square matrix")
    for row in rows:
        for x in row:
            _validation.integer(x, "key entry")
    return tuple(tuple(x % 26 for x in row) for row in rows)


def _field_inverse(m: Matrix, q: int) -> Matrix | None:
    """Gauss-Jordan elimination over the prime field of order ``q``."""
    n = len(m)
    rows = [[x % q for x in row] + [int(i == j) for j in range(n)] for i, row in enumerate(m)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if rows[r][col]), None)
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inv = pow(rows[col][col], -1, q)
        rows[col] = [x * inv % q for x in rows[col]]
        for r in range(n):
            f = rows[r][col]
            if r != col and f:
                rows[r] = [(x - f * y) % q for x, y in zip(rows[r], rows[col], strict=True)]
    return tuple(tuple(row[n:]) for row in rows)


def _inverse(m: Matrix) -> Matrix | None:
    """Invert mod 26 by inverting mod 2 and mod 13 and joining them (Chinese remainders)."""
    mod2, mod13 = _field_inverse(m, 2), _field_inverse(m, 13)
    if mod2 is None or mod13 is None:
        return None
    # 13 is 1 mod 2 and 0 mod 13; 14 is 0 mod 2 and 1 mod 13.
    return tuple(
        tuple((13 * a + 14 * b) % 26 for a, b in zip(r2, r13, strict=True))
        for r2, r13 in zip(mod2, mod13, strict=True)
    )


def hill_inverse(key: Sequence[Sequence[int]]) -> Matrix:
    """Return the inverse of a Hill key matrix mod 26.

    Raises
    ------
    ValueError
        The determinant shares a factor with 26, so the key cannot decrypt.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.hill_inverse([[3, 3], [2, 5]])
    ((15, 17), (20, 9))
    """
    inverse = _inverse(_matrix(key))
    if inverse is None:
        raise ValueError("key is not invertible mod 26")
    return inverse


def _apply(text: str, m: Matrix) -> str:
    n = len(m)
    p = to_numbers(text)
    p += [23] * (-len(p) % n)  # pad with X
    out: list[int] = []
    for b in range(0, len(p), n):
        out += [sum(m[i][j] * p[b + j] for j in range(n)) for i in range(n)]
    return to_letters(out)


def hill_encrypt(plaintext: str, key: Sequence[Sequence[int]]) -> str:
    """Encrypt blocks of ``n`` letters as ``c = K p`` mod 26, padding with ``X``.

    Parameters
    ----------
    plaintext : str
        Text to encrypt; non-letters are dropped.
    key : sequence of sequence of int
        An invertible ``n x n`` matrix mod 26.

    Returns
    -------
    str
        Upper-case ciphertext, a multiple of ``n`` letters long.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.hill_encrypt("ACT", [[6, 24, 1], [13, 16, 10], [20, 17, 15]])
    'POH'
    """
    m = _matrix(key)
    hill_inverse(m)
    return _apply(clean(plaintext, "plaintext"), m)


def hill_decrypt(ciphertext: str, key: Sequence[Sequence[int]]) -> str:
    """Invert :func:`hill_encrypt` with the inverse key matrix.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.hill_decrypt("POH", [[6, 24, 1], [13, 16, 10], [20, 17, 15]])
    'ACT'
    """
    return _apply(clean(ciphertext, "ciphertext"), hill_inverse(key))


def hill_known_plaintext(plaintext: str, ciphertext: str, n: int) -> HillBreakResult:
    """Recover an ``n x n`` Hill key from matching plaintext and ciphertext.

    Only blocks complete in both texts are used, so a trailing padded block may
    be left off the plaintext. Chooses the first ``n`` blocks whose plaintext
    matrix ``P`` is invertible, then solves ``K = C P^{-1}`` mod 26.

    Raises
    ------
    ValueError
        No ``n`` blocks give an invertible plaintext matrix.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = [[3, 3], [2, 5]]
    >>> ciphertext = classical.hill_encrypt("HELPMEPLEASE", key)
    >>> classical.hill_known_plaintext("HELPMEPLEASE", ciphertext, 2).key
    ((3, 3), (2, 5))
    """
    _validation.integer(n, "n", minimum=1)
    p, c = to_numbers(clean(plaintext, "plaintext")), to_numbers(clean(ciphertext, "ciphertext"))
    count = min(len(p), len(c)) // n
    for tested, chosen in enumerate(combinations(range(count), n), 1):
        # Columns are the chosen blocks, so P has P[i][k] = block k, letter i.
        pm = tuple(tuple(p[b * n + i] for b in chosen) for i in range(n))
        inverse = _inverse(pm)
        if inverse is not None:
            cm = [[c[b * n + i] for b in chosen] for i in range(n)]
            key = tuple(
                tuple(sum(cm[i][k] * inverse[k][j] for k in range(n)) % 26 for j in range(n))
                for i in range(n)
            )
            return HillBreakResult(key, chosen, tested)
    raise ValueError("no choice of n plaintext blocks gives an invertible matrix")
