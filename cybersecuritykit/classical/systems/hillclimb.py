"""Simple substitution and Jakobsen's fast hill-climbing attack (1995).

T. Jakobsen, "A fast method for cryptanalysis of substitution ciphers",
*Cryptologia* 19(3), 1995, doi:10.1080/0161-119591883944. Start from the key
that matches letter frequencies, then try swapping pairs of key letters in a
fixed order of increasing distance, keeping any swap that makes the bigram
statistics of the decryption more English-like. The ciphertext's bigram
counts are taken once, so each trial costs one pass over them.
"""

import random
from collections import Counter

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import HillClimbResult
from cybersecuritykit.classical.utils.english import ENGLISH_FREQUENCIES, bigram_log_probabilities
from cybersecuritykit.classical.utils.text import clean, permutation, to_numbers
from cybersecuritykit.constants import ALPHABET, DEFAULT_SEED

__all__ = ["hill_climb_substitution", "substitution_decrypt", "substitution_encrypt"]


def substitution_encrypt(plaintext: str, key: str) -> str:
    """Replace each letter A-Z by the letter at the same place in ``key``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.substitution_encrypt("cab", "QWERTYUIOPASDFGHJKLZXCVBNM")
    'EQW'
    """
    key = permutation(key, "key")
    return "".join(key[i] for i in to_numbers(clean(plaintext, "plaintext")))


def substitution_decrypt(ciphertext: str, key: str) -> str:
    """Invert :func:`substitution_encrypt` with the same key.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.substitution_decrypt("EQW", "QWERTYUIOPASDFGHJKLZXCVBNM")
    'CAB'
    """
    key = permutation(key, "key")
    return "".join(ALPHABET[key.index(c)] for c in clean(ciphertext, "ciphertext"))


def hill_climb_substitution(
    ciphertext: str, seed: int = DEFAULT_SEED, restarts: int = 3
) -> HillClimbResult:
    """Search for the substitution key whose decryption scores best on English bigrams.

    The first climb starts from the frequency-matched key, later ones from
    seeded random keys. Each climb sweeps swaps of key positions ``i`` and
    ``i + d`` for ``d = 1, 2, ...`` and starts over after every improvement,
    stopping when a whole sweep improves nothing.

    Parameters
    ----------
    ciphertext : str
        Text from :func:`substitution_encrypt`; a few hundred letters or more.
    seed : int, optional
        Seed for the random restarts.
    restarts : int, optional
        Number of climbs, at least 1.

    Returns
    -------
    HillClimbResult
        The best key, its plaintext and score, the score history and the
        number of keys scored.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    >>> c = classical.substitution_encrypt("the harbour was quiet in the morning", key)
    >>> len(classical.hill_climb_substitution(c, restarts=1).key)
    26
    """
    _validation.seed(seed)
    _validation.integer(restarts, "restarts", minimum=1)
    numbers = to_numbers(clean(ciphertext, "ciphertext"))
    if len(numbers) < 2:
        raise ValueError("ciphertext must contain at least two letters")
    table = bigram_log_probabilities()
    pairs = list(Counter(zip(numbers, numbers[1:], strict=False)).items())

    tested = 0

    def score(plain_of: list[int]) -> float:
        nonlocal tested
        tested += 1
        return sum(n * table[plain_of[a]][plain_of[b]] for (a, b), n in pairs)

    counts = Counter(numbers)
    by_cipher = sorted(range(26), key=lambda c: (-counts[c], c))
    by_english = sorted(range(26), key=lambda p: -ENGLISH_FREQUENCIES[ALPHABET[p]])
    rng = random.Random(seed)
    best_plain_of: list[int] = []
    best = float("-inf")
    history: list[float] = []
    for attempt in range(restarts):
        plain_of = [0] * 26
        english = by_english if attempt == 0 else rng.sample(range(26), 26)
        for c, p in zip(by_cipher, english, strict=True):
            plain_of[c] = p
        current = score(plain_of)
        if current > best:
            best, best_plain_of = current, plain_of[:]
            history.append(best)
        improved = True
        while improved:
            improved = False
            for d in range(1, 26):
                for i in range(26 - d):
                    a, b = by_cipher[i], by_cipher[i + d]
                    plain_of[a], plain_of[b] = plain_of[b], plain_of[a]
                    trial = score(plain_of)
                    if trial > current:
                        current, improved = trial, True
                        if current > best:
                            best, best_plain_of = current, plain_of[:]
                            history.append(best)
                        break
                    plain_of[a], plain_of[b] = plain_of[b], plain_of[a]
                if improved:
                    break
    key = [""] * 26
    for c, p in enumerate(best_plain_of):
        key[p] = ALPHABET[c]
    return HillClimbResult(
        "".join(key),
        "".join(ALPHABET[best_plain_of[c]] for c in numbers),
        best,
        tuple(history),
        tested,
    )
