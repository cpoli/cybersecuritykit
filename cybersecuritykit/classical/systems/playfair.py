"""Wheatstone's Playfair cipher (1854), the first practical digraph cipher.

Invented by Charles Wheatstone in 1854 and promoted by Lyon Playfair; see
D. Kahn, *The Codebreakers* (1967), ch. 6. Encrypting pairs of letters hides
single-letter frequencies, leaving only the much flatter digraph statistics.
Those statistics are still enough for simulated annealing over key squares;
see M. J. Cowan, "Breaking short Playfair ciphers with the simulated annealing
algorithm", *Cryptologia* 32(1), 2008, doi:10.1080/01611190701743658.
"""

import math
import random

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import PlayfairBreakResult
from cybersecuritykit.classical.utils.english import bigram_log_probabilities
from cybersecuritykit.classical.utils.text import clean, to_numbers
from cybersecuritykit.constants import ALPHABET, DEFAULT_SEED

__all__ = ["break_playfair", "playfair_decrypt", "playfair_encrypt", "playfair_square"]

_LETTERS = ALPHABET.replace("J", "")  # 25 letters: J is written as I


def playfair_square(key: str) -> tuple[str, ...]:
    """Return the 5x5 key square: the keyword's letters first, then the rest.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.playfair_square("playfair example")[0]
    'PLAYF'
    """
    seen: list[str] = []
    for c in clean(key, "key").replace("J", "I") + _LETTERS:
        if c not in seen:
            seen.append(c)
    return tuple("".join(seen[r * 5 : r * 5 + 5]) for r in range(5))


def _digraphs(text: str) -> list[str]:
    letters = clean(text, "plaintext").replace("J", "I")
    pairs: list[str] = []
    i = 0
    while i < len(letters):
        a = letters[i]
        filler = "Q" if a == "X" else "X"
        b = letters[i + 1] if i + 1 < len(letters) else filler
        if a == b:
            b = filler
            i += 1
        else:
            i += 2
        pairs.append(a + b)
    return pairs


def _apply(pairs: list[str], square: tuple[str, ...], step: int) -> str:
    where = {c: (r, k) for r, row in enumerate(square) for k, c in enumerate(row)}
    out = []
    for pair in pairs:
        (ra, ca), (rb, cb) = where[pair[0]], where[pair[1]]
        if ra == rb:
            out.append(square[ra][(ca + step) % 5] + square[rb][(cb + step) % 5])
        elif ca == cb:
            out.append(square[(ra + step) % 5][ca] + square[(rb + step) % 5][cb])
        else:
            out.append(square[ra][cb] + square[rb][ca])
    return "".join(out)


def playfair_encrypt(plaintext: str, key: str) -> str:
    """Encrypt letter pairs with the Playfair rules.

    The plaintext is split into pairs, with ``X`` between doubled letters and at
    the end of an odd-length text (``Q`` where the filler would follow an ``X``,
    so that no pair is ever doubled). Pairs in one row move right, pairs in one
    column move down, and any other pair swaps the corners of its rectangle.

    Parameters
    ----------
    plaintext : str
        Text to encrypt; non-letters are dropped and ``J`` becomes ``I``.
    key : str
        Keyword for :func:`playfair_square`.

    Returns
    -------
    str
        Upper-case ciphertext of even length.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.playfair_encrypt("hide the gold", "playfair example")
    'BMODZBXDNAGE'
    """
    return _apply(_digraphs(plaintext), playfair_square(key), 1)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    """Invert :func:`playfair_encrypt`; the padding ``X`` letters stay in place.

    Raises
    ------
    ValueError
        ``ciphertext`` has an odd number of letters or a doubled pair.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.playfair_decrypt("BMODZBXDNAGE", "playfair example")
    'HIDETHEGOLDX'
    """
    return _apply(_cipher_pairs(ciphertext), playfair_square(key), 4)


def _cipher_pairs(ciphertext: str) -> list[str]:
    letters = clean(ciphertext, "ciphertext").replace("J", "I")
    pairs = [letters[i : i + 2] for i in range(0, len(letters), 2)]
    if len(letters) % 2 or any(pair[0] == pair[1] for pair in pairs):
        raise ValueError("ciphertext must be whole Playfair pairs with no doubled letter")
    return pairs


def _neighbour(cells: list[str], rng: random.Random) -> list[str]:
    """Swap two cells (most moves), or two whole rows, or two whole columns."""
    new = cells[:]
    move = rng.random()
    a, b = rng.sample(range(25) if move < 0.9 else range(5), 2)
    if move < 0.9:
        new[a], new[b] = new[b], new[a]
    else:
        for k in range(5):
            i, j = (a * 5 + k, b * 5 + k) if move < 0.95 else (k * 5 + a, k * 5 + b)
            new[i], new[j] = new[j], new[i]
    return new


def break_playfair(
    ciphertext: str, seed: int = DEFAULT_SEED, restarts: int = 5, steps: int = 50_000
) -> PlayfairBreakResult:
    """Search for the key square by simulated annealing on English bigrams.

    Each anneal starts from a seeded random square. A move swaps two cells,
    or occasionally two rows or two columns; it is kept by the Metropolis
    rule at a temperature falling linearly from a fortieth of the text
    length, since score differences grow with the text, and the decryption
    is rescored in full after every move. The best square over all anneals wins.

    Parameters
    ----------
    ciphertext : str
        Text from :func:`playfair_encrypt`; several hundred letters or more.
        With the default moves, one anneal finds the square on about half of
        the 400-letter texts tried, so five restarts rarely all fail there.
    seed : int, optional
        Seed for the starting squares and the moves.
    restarts : int, optional
        Number of independent anneals, at least 1.
    steps : int, optional
        Moves per anneal, at least 1.

    Returns
    -------
    PlayfairBreakResult
        The best square, its plaintext and score, and the number of squares scored.

    Raises
    ------
    ValueError
        ``ciphertext`` is not whole Playfair pairs.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> c = classical.playfair_encrypt("the harbour was quiet in the morning", "lighthouse")
    >>> len(classical.break_playfair(c, restarts=1, steps=50).plaintext)
    30
    """
    _validation.seed(seed)
    _validation.integer(restarts, "restarts", minimum=1)
    _validation.integer(steps, "steps", minimum=1)
    pairs = _cipher_pairs(ciphertext)
    table = bigram_log_probabilities()
    rng = random.Random(seed)
    start = len(pairs) / 20

    def score(cells: list[str]) -> float:
        square = tuple("".join(cells[r * 5 : r * 5 + 5]) for r in range(5))
        n = to_numbers(_apply(pairs, square, 4))
        return sum(table[a][b] for a, b in zip(n, n[1:], strict=False))

    best_cells: list[str] = []
    best = float("-inf")
    tested = 0
    for _ in range(restarts):
        cells = rng.sample(_LETTERS, 25)
        current = score(cells)
        tested += 1
        for i in range(steps):
            temperature = start * (1 - i / steps) + 0.01
            new = _neighbour(cells, rng)
            trial = score(new)
            tested += 1
            if trial > current or rng.random() < math.exp((trial - current) / temperature):
                cells, current = new, trial
            if current > best:
                best, best_cells = current, cells
    square = tuple("".join(best_cells[r * 5 : r * 5 + 5]) for r in range(5))
    return PlayfairBreakResult(square, _apply(pairs, square, 4), best, tested)
