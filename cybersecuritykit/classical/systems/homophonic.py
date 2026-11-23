"""Homophonic substitution and the 2020 solution of the Zodiac 340.

D. Oranchak, S. Blake and J. Van Eycke solved the Zodiac Killer's 340-symbol
cipher in December 2020 with Van Eycke's AZdecrypt, a hill-climbing solver,
after untangling a transposition; see D. Oranchak, S. Blake and J. Van Eycke,
"The solution of the Zodiac Killer's 340-character cipher", *Cryptologia*
(2024), doi:10.1080/01611194.2023.2245401. A homophonic cipher gives common
letters several symbols, flattening single-letter frequencies, but the
symbols still have to follow English letter pairs, which a climb exploits.
"""

import math
import random
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import HomophonicResult
from cybersecuritykit.classical.utils.english import (
    ENGLISH_FREQUENCIES,
    bigram_log_probabilities,
)
from cybersecuritykit.classical.utils.text import clean
from cybersecuritykit.constants import ALPHABET, DEFAULT_SEED

__all__ = ["homophonic_decrypt", "homophonic_encrypt", "homophonic_key", "solve_homophonic"]


def homophonic_key(seed: int = DEFAULT_SEED, symbols: int = 40) -> dict[str, tuple[int, ...]]:
    """Share ``symbols`` cipher symbols among the letters in proportion to English use.

    Every letter gets at least one symbol; the rest go by largest remainder.
    Symbols are the integers ``0 .. symbols - 1``, shuffled with ``seed``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = classical.homophonic_key(seed=1, symbols=40)
    >>> len(key["E"]) > len(key["Z"]) == 1
    True
    """
    _validation.seed(seed)
    _validation.integer(symbols, "symbols", minimum=26)
    spare = symbols - 26
    shares = {c: ENGLISH_FREQUENCIES[c] / 100 * spare for c in ALPHABET}
    counts = {c: 1 + math.floor(shares[c]) for c in ALPHABET}
    left = symbols - sum(counts.values())
    for c in sorted(ALPHABET, key=lambda c: (math.floor(shares[c]) - shares[c], c))[:left]:
        counts[c] += 1
    pool = list(range(symbols))
    random.Random(seed).shuffle(pool)
    key, at = {}, 0
    for c in ALPHABET:
        key[c] = tuple(pool[at : at + counts[c]])
        at += counts[c]
    return key


def _key(key: Mapping[str, Sequence[int]]) -> dict[str, tuple[int, ...]]:
    if not isinstance(key, Mapping) or sorted(key) != list(ALPHABET):
        raise ValueError("key must map each of the letters A-Z to its symbols")
    out = {c: tuple(key[c]) for c in ALPHABET}
    used = [s for c in ALPHABET for s in out[c]]
    if any(not out[c] for c in ALPHABET) or len(set(used)) != len(used):
        raise ValueError("every letter needs at least one symbol and no symbol may repeat")
    for s in used:
        _validation.integer(s, "symbol")
    return out


def homophonic_encrypt(plaintext: str, key: Mapping[str, Sequence[int]]) -> tuple[int, ...]:
    """Encrypt, cycling through each letter's symbols in turn.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = classical.homophonic_key(seed=1)
    >>> c = classical.homophonic_encrypt("eee", key)
    >>> len(set(c))
    3
    """
    k = _key(key)
    used: Counter[str] = Counter()
    out = []
    for c in clean(plaintext, "plaintext"):
        out.append(k[c][used[c] % len(k[c])])
        used[c] += 1
    return tuple(out)


def homophonic_decrypt(symbols: Sequence[int], key: Mapping[str, Sequence[int]]) -> str:
    """Read a homophonic ciphertext back through ``key``.

    Raises
    ------
    ValueError
        A symbol does not appear in the key.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = classical.homophonic_key(seed=1)
    >>> classical.homophonic_decrypt(classical.homophonic_encrypt("zodiac", key), key)
    'ZODIAC'
    """
    letter = {s: c for c, group in _key(key).items() for s in group}
    if any(s not in letter for s in symbols):
        raise ValueError("ciphertext uses a symbol that is not in the key")
    return "".join(letter[s] for s in symbols)


def _english_pairs() -> tuple[tuple[float, ...], ...]:
    """Return ``table[a][b] = log P(ab)``, the joint bigram log-probability."""
    conditional = bigram_log_probabilities()
    unigram = [ENGLISH_FREQUENCIES[c] / 100 for c in ALPHABET]
    return tuple(
        tuple(math.log(unigram[a]) + conditional[a][b] for b in range(26)) for a in range(26)
    )


def solve_homophonic(
    symbols: Sequence[int], seed: int = DEFAULT_SEED, restarts: int = 4, steps: int = 50_000
) -> HomophonicResult:
    r"""Assign letters to symbols by simulated annealing, then a greedy polish.

    The score of a candidate plaintext with bigram counts :math:`n_{xy}` out
    of :math:`N` is :math:`\sum n_{xy} \log(P_{xy} / (n_{xy}/N))`, minus the
    Kullback-Leibler divergence of its bigrams from English (times
    :math:`N`). Scoring conditional bigram probabilities alone rewards
    collapsing every symbol onto T, H and E; the divergence does not.
    Each move gives one random symbol a random letter and is kept by the
    Metropolis rule at a temperature falling linearly to zero; a final
    sweep then takes every single-symbol change that helps. Only the
    bigrams touching the changed symbol are rescored.

    Parameters
    ----------
    symbols : sequence of int
        The ciphertext, as from :func:`homophonic_encrypt`.
    seed : int, optional
        Seed for the starting assignments and the moves.
    restarts : int, optional
        Number of independent anneals, at least 1.
    steps : int, optional
        Moves per anneal, at least 1.

    Returns
    -------
    HomophonicResult
        The best-scoring assignment found and the number of assignments scored.

    Raises
    ------
    ValueError
        Fewer than two symbols.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = classical.homophonic_key(seed=1)
    >>> c = classical.homophonic_encrypt("the stranger left a page of strange letters", key)
    >>> len(classical.solve_homophonic(c, restarts=1, steps=100).plaintext)
    36
    """
    _validation.seed(seed)
    _validation.integer(restarts, "restarts", minimum=1)
    _validation.integer(steps, "steps", minimum=1)
    text = list(symbols)
    for s in text:
        _validation.integer(s, "symbol")
    if len(text) < 2:
        raise ValueError("ciphertext must contain at least two symbols")
    table = _english_pairs()
    pairs = Counter(zip(text, text[1:], strict=False))
    total = len(text) - 1
    touching: dict[int, list[tuple[int, int, int]]] = defaultdict(list)
    for (a, b), n in pairs.items():
        touching[a].append((a, b, n))
        if b != a:
            touching[b].append((a, b, n))
    alphabet = sorted(set(text))
    weights = [ENGLISH_FREQUENCIES[c] for c in ALPHABET]
    rng = random.Random(seed)

    def cell(x: int, y: int, n: int) -> float:
        return n * (table[x][y] - math.log(n / total)) if n else 0.0

    def change(m: dict[int, int], counts: list[list[int]], s: int, letter: int) -> float:
        """Move symbol ``s`` to ``letter``, updating ``counts``; return the score change."""
        moved: dict[tuple[int, int], int] = defaultdict(int)
        for a, b, n in touching[s]:
            moved[m[a], m[b]] -= n
        m[s] = letter
        for a, b, n in touching[s]:
            moved[m[a], m[b]] += n
        delta = 0.0
        for (x, y), dn in moved.items():
            delta += cell(x, y, counts[x][y] + dn) - cell(x, y, counts[x][y])
            counts[x][y] += dn
        return delta

    best: tuple[float, dict[int, int]] = (float("-inf"), {})
    tested = 0
    for _ in range(restarts):
        m = dict(zip(alphabet, rng.choices(range(26), weights, k=len(alphabet)), strict=True))
        counts = [[0] * 26 for _ in range(26)]
        for (a, b), n in pairs.items():
            counts[m[a]][m[b]] += n
        score = sum(cell(x, y, counts[x][y]) for x in range(26) for y in range(26))
        for i in range(steps):
            temperature = total / 40 * (1 - i / steps)
            s, letter = rng.choice(alphabet), rng.randrange(26)
            old = m[s]
            delta = change(m, counts, s, letter)
            tested += 1
            if delta >= 0 or rng.random() < math.exp(delta / temperature):
                score += delta
            else:
                change(m, counts, s, old)
        improved = True
        while improved:
            improved = False
            for s in alphabet:
                for letter in range(26):
                    old = m[s]
                    delta = change(m, counts, s, letter)
                    tested += 1
                    if delta > 1e-9:
                        score += delta
                        improved = True
                    else:
                        change(m, counts, s, old)
        if score > best[0]:
            best = (score, dict(m))
    score, m = best
    mapping = {s: ALPHABET[m[s]] for s in alphabet}
    return HomophonicResult(mapping, "".join(mapping[s] for s in text), score, tested)
