"""Shannon's perfect secrecy and unicity distance (1949).

C. E. Shannon, "Communication theory of secrecy systems", *Bell System
Technical Journal* 28(4), 1949, doi:10.1002/j.1538-7305.1949.tb00928.x.
A cipher is perfectly secret when every ciphertext leaves the probability of
every message unchanged; the one-time pad is, a shift cipher on more than one
letter is not. The unicity distance ``H(K) / D`` estimates how many letters
of ciphertext leave a single meaningful decryption; :func:`spurious_shift_keys`
counts the meaningful decryptions directly.
"""

import math
from collections.abc import Mapping
from functools import cache

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import SecrecyResult, SpuriousKeyCount, UnicityResult
from cybersecuritykit.classical.utils.english import CORPUS
from cybersecuritykit.classical.utils.text import clean, to_numbers

__all__ = [
    "one_time_pad_posterior",
    "shift_cipher_posterior",
    "spurious_shift_keys",
    "unicity_distance",
]


def _prior(prior: Mapping[str, float], ciphertext: str) -> tuple[dict[str, float], str]:
    c = clean(ciphertext, "ciphertext")
    if not isinstance(prior, Mapping) or not prior:
        raise ValueError("prior must be a non-empty mapping of messages to probabilities")
    out: dict[str, float] = {}
    for message, p in prior.items():
        _validation.probability(p, "prior probability")
        if not isinstance(message, str) or clean(message) != message or len(message) != len(c):
            raise ValueError("messages must be upper-case letters as long as the ciphertext")
        out[message] = p
    if abs(sum(out.values()) - 1) > 1e-9:
        raise ValueError("prior probabilities must sum to 1")
    return out, c


def _posterior(prior: dict[str, float], likelihood: dict[str, float]) -> SecrecyResult:
    total = sum(prior[m] * likelihood[m] for m in prior)
    if total == 0:
        raise ValueError("ciphertext is impossible under this prior")
    posterior = {m: prior[m] * likelihood[m] / total for m in prior}
    perfect = all(abs(posterior[m] - prior[m]) < 1e-12 for m in prior)
    return SecrecyResult(prior, posterior, perfect)


def shift_cipher_posterior(prior: Mapping[str, float], ciphertext: str) -> SecrecyResult:
    """Bayes' rule for a shift cipher whose 26 keys are equally likely.

    Parameters
    ----------
    prior : mapping of str to float
        Candidate messages, upper-case and as long as the ciphertext, with probabilities.
    ciphertext : str
        The intercepted ciphertext.

    Returns
    -------
    SecrecyResult
        Prior, posterior and whether they agree.

    Raises
    ------
    ValueError
        The prior is malformed, or no candidate could produce the ciphertext.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.shift_cipher_posterior({"AB": 0.5, "AC": 0.5}, "BC").posterior["AB"]
    1.0
    """
    clean_prior, c = _prior(prior, ciphertext)
    cn = to_numbers(c)
    likelihood = {
        m: sum(
            all((x + s) % 26 == y for x, y in zip(to_numbers(m), cn, strict=True))
            for s in range(26)
        )
        / 26
        for m in clean_prior
    }
    return _posterior(clean_prior, likelihood)


def one_time_pad_posterior(prior: Mapping[str, float], ciphertext: str) -> SecrecyResult:
    """Bayes' rule for a one-time pad: an independent uniform shift for every letter.

    Every message of the right length yields every ciphertext with probability
    ``26**-n``, so the posterior is always the prior.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.one_time_pad_posterior({"AB": 0.5, "AC": 0.5}, "BC").perfect
    True
    """
    clean_prior, c = _prior(prior, ciphertext)
    return _posterior(clean_prior, {m: 26.0 ** -len(c) for m in clean_prior})


def unicity_distance(keyspace_size: int, letter_entropy: float = 1.5) -> UnicityResult:
    """Return Shannon's unicity distance ``log2(keys) / (log2 26 - H)`` for English.

    Parameters
    ----------
    keyspace_size : int
        Number of equally likely keys, at least 1 (``math.factorial(26)`` for
        simple substitution).
    letter_entropy : float, optional
        Bits of information per letter of the language; Shannon's estimates
        for English run from about 1 to 1.5.

    Examples
    --------
    >>> import math
    >>> from cybersecuritykit import classical
    >>> round(classical.unicity_distance(math.factorial(26)).distance, 1)
    27.6
    """
    _validation.integer(keyspace_size, "keyspace_size", minimum=1)
    _validation.positive(letter_entropy, "letter_entropy")
    if letter_entropy >= math.log2(26):
        raise ValueError("letter_entropy must be below log2(26), or the language has no redundancy")
    key_entropy = math.log2(keyspace_size)
    redundancy = math.log2(26) - letter_entropy
    return UnicityResult(key_entropy, redundancy, key_entropy / redundancy)


@cache
def _english_pairs() -> frozenset[tuple[int, int]]:
    letters = to_numbers(clean(CORPUS))
    return frozenset(zip(letters, letters[1:], strict=False))


def spurious_shift_keys(ciphertext: str) -> SpuriousKeyCount:
    """Count the shift keys that still give English-looking text, letter by letter.

    Each key's decryption is checked pair by pair against the package's English
    sample, and a key counts as English-looking while no other key's decryption
    has fewer pairs missing from the sample. Shannon called the wrong keys that
    pass such a test spurious; the unicity distance estimates the length at
    which they run out. Since the test is relative, the true key survives a
    pair the sample lacks, and at least one key always survives.

    Parameters
    ----------
    ciphertext : str
        A shift-cipher ciphertext with at least one letter.

    Returns
    -------
    SpuriousKeyCount
        The surviving keys for every prefix length, and the length from which
        only one survives up to the end of the text.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> c = classical.shift_encrypt("the harbour was quiet", 3)
    >>> result = classical.spurious_shift_keys(c)
    >>> result.counts[:5], result.unique_from
    ((26, 12, 5, 4, 4), 6)
    """
    c = to_numbers(clean(ciphertext, "ciphertext"))
    if not c:
        raise ValueError("ciphertext must contain at least one letter")
    pairs = _english_pairs()
    missing = [0] * 26
    counts = [26]
    for a, b in zip(c, c[1:], strict=False):
        for k in range(26):
            missing[k] += ((a - k) % 26, (b - k) % 26) not in pairs
        counts.append(missing.count(min(missing)))
    last_tie = max((n for n, k in enumerate(counts, 1) if k > 1), default=0)
    unique_from = last_tie + 1 if last_tie < len(counts) else None
    return SpuriousKeyCount(tuple(range(1, len(c) + 1)), tuple(counts), unique_from)
