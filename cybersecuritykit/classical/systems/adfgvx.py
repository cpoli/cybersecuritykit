"""The German ADFGVX field cipher (1918), broken by Georges Painvin.

Introduced on the Western Front in March 1918 (ADFGX, then ADFGVX from
June); see D. Kahn, *The Codebreakers* (1967), ch. 9. A 6x6 Polybius square
splits each letter or digit into two coordinates (fractionation), and a
keyed columnar transposition then separates the halves.
"""

from collections import Counter
from itertools import permutations

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import ADFGVXBreakResult
from cybersecuritykit.classical.systems.hillclimb import hill_climb_substitution
from cybersecuritykit.classical.utils.text import clean, string
from cybersecuritykit.constants import ALPHABET, DEFAULT_SEED

__all__ = ["adfgvx_decrypt", "adfgvx_encrypt", "break_adfgvx"]

_LABELS = "ADFGVX"
_SYMBOLS = ALPHABET + "0123456789"


def _square(square: str) -> str:
    square = string(square, "square").upper()
    if sorted(square) != sorted(_SYMBOLS):
        raise ValueError("square must use each of A-Z and 0-9 exactly once")
    return square


def _order(keyword: str) -> list[int]:
    key = clean(keyword, "keyword")
    if not key:
        raise ValueError("keyword must contain at least one letter")
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def _symbols(text: str) -> str:
    return "".join(c for c in string(text, "plaintext").upper() if c in _SYMBOLS)


def adfgvx_encrypt(plaintext: str, square: str, keyword: str) -> str:
    """Fractionate through the square, then transpose by the keyword's columns.

    Parameters
    ----------
    plaintext : str
        Letters and digits to encrypt; anything else is dropped.
    square : str
        The 36 symbols A-Z, 0-9 in any order, read row by row into the 6x6 square.
    keyword : str
        Transposition keyword; columns are read in alphabetical order of its letters.

    Returns
    -------
    str
        Ciphertext over the letters ADFGVX, twice as long as the plaintext.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    >>> classical.adfgvx_encrypt("attack", square, "GERMAN")
    'XGGGDDGVGDXG'
    """
    square = _square(square)
    order = _order(keyword)
    stream = "".join(
        _LABELS[square.index(c) // 6] + _LABELS[square.index(c) % 6] for c in _symbols(plaintext)
    )
    width = len(order)
    return "".join(stream[col::width] for col in order)


def adfgvx_decrypt(ciphertext: str, square: str, keyword: str) -> str:
    """Invert :func:`adfgvx_encrypt` with the same square and keyword.

    Raises
    ------
    ValueError
        ``ciphertext`` is not an even number of ADFGVX letters.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    >>> classical.adfgvx_decrypt("XGGGDDGVGDXG", square, "GERMAN")
    'ATTACK'
    """
    square = _square(square)
    stream = _untranspose(_labels(ciphertext), _order(keyword))
    return "".join(
        square[_LABELS.index(stream[i]) * 6 + _LABELS.index(stream[i + 1])]
        for i in range(0, len(stream), 2)
    )


def _labels(ciphertext: str) -> str:
    text = clean(ciphertext, "ciphertext")
    if len(text) % 2 or any(c not in _LABELS for c in text):
        raise ValueError("ciphertext must be an even number of the letters A, D, F, G, V, X")
    return text


def _untranspose(text: str, order: list[int] | tuple[int, ...]) -> str:
    """Write ``text`` back into columns read out in ``order``, then read the rows."""
    width, n = len(order), len(text)
    columns: dict[int, str] = {}
    pos = 0
    for col in order:
        size = len(range(col, n, width))
        columns[col] = text[pos : pos + size]
        pos += size
    return "".join(columns[i % width][i // width] for i in range(n))


def _pair_coincidence(stream: str) -> float:
    counts = Counter(stream[i : i + 2] for i in range(0, len(stream), 2))
    n = len(stream) // 2
    return sum(k * (k - 1) for k in counts.values()) / (n * (n - 1))


def break_adfgvx(
    ciphertext: str, width: int, seed: int = DEFAULT_SEED, restarts: int = 10
) -> ADFGVXBreakResult:
    """Undo the transposition by coincidence counting, then solve the substitution.

    Every order of the ``width`` columns is tried. Under the right one each
    pair of the stream is the two coordinates of one plaintext symbol, so the
    pairs repeat as often as English letters do and their index of
    coincidence is highest; a wrong order splits and mixes coordinates and
    flattens it. The pairs are then renamed as letters and solved with
    :func:`~cybersecuritykit.classical.systems.hillclimb.hill_climb_substitution`.

    Painvin worked from several messages sent the same day with the same key,
    lining up their common openings and endings. This teaching version knows
    the keyword length and searches all its orders, so it needs one long
    message and a short keyword.

    Parameters
    ----------
    ciphertext : str
        Text from :func:`adfgvx_encrypt`; several hundred letters or more.
    width : int
        Length of the transposition keyword, 1 to 8.
    seed : int, optional
        Seed for the substitution solver's restarts.
    restarts : int, optional
        Climbs for the substitution solver, at least 1.

    Returns
    -------
    ADFGVXBreakResult
        The column order, the plaintext, and the orders and keys scored.

    Raises
    ------
    ValueError
        ``width`` is out of range or longer than the stream, or the best
        order gives more than 26 distinct pairs to rename as letters.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> square = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"
    >>> c = classical.adfgvx_encrypt("attack at dawn " * 4, square, "CARGO")
    >>> classical.break_adfgvx(c, 5, restarts=1).order
    (1, 0, 3, 4, 2)
    """
    _validation.integer(width, "width", minimum=1)
    text = _labels(ciphertext)
    if width > 8 or width > len(text):
        raise ValueError("width must be 1 to 8 and no longer than the ciphertext")
    if len(text) < 4:
        raise ValueError("ciphertext must hold at least two symbols")
    tested = 0
    best: tuple[float, tuple[int, ...]] = (-1.0, ())
    for order in permutations(range(width)):
        tested += 1
        best = max(best, (_pair_coincidence(_untranspose(text, order)), order))
    order = best[1]
    stream = _untranspose(text, order)
    pairs = [stream[i : i + 2] for i in range(0, len(stream), 2)]
    names = {pair: ALPHABET[k] for k, pair in enumerate(dict.fromkeys(pairs)) if k < 26}
    if len(names) < len(set(pairs)):
        raise ValueError("more than 26 distinct symbols; the pairs cannot be renamed as letters")
    climb = hill_climb_substitution("".join(names[p] for p in pairs), seed, restarts)
    return ADFGVXBreakResult(order, climb.plaintext, tested + climb.tested)
