"""Friedman's index of coincidence (1922) and the column attack on Vigenère.

W. F. Friedman, *The Index of Coincidence and Its Applications in
Cryptography*, Riverbank Publication No. 22 (Geneva, IL, 1922). Two letters
drawn from English text agree about 6.6% of the time, from random letters
only 1/26 = 3.8%; the columns of a Vigenère ciphertext taken at the right
period are shift ciphers and recover the English rate.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import CoincidenceProfile, VigenereBreakResult
from cybersecuritykit.classical.systems.frequency import break_shift_cipher
from cybersecuritykit.classical.systems.vigenere import vigenere_decrypt
from cybersecuritykit.classical.utils.text import clean
from cybersecuritykit.constants import ALPHABET

__all__ = ["break_vigenere", "coincidence_profile", "index_of_coincidence"]


def index_of_coincidence(text: str) -> float:
    r"""Return the probability that two letters drawn without replacement agree.

    .. math:: \mathrm{IC} = \sum_i \frac{n_i (n_i - 1)}{N (N - 1)}

    Raises
    ------
    ValueError
        ``text`` has fewer than two letters.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> round(classical.index_of_coincidence("AABB"), 4)
    0.3333
    """
    letters = clean(text)
    n = len(letters)
    if n < 2:
        raise ValueError("text must contain at least two letters")
    return sum(letters.count(c) * (letters.count(c) - 1) for c in ALPHABET) / (n * (n - 1))


def coincidence_profile(ciphertext: str, max_period: int = 12) -> CoincidenceProfile:
    """Average the columns' index of coincidence for each period up to ``max_period``.

    Raises
    ------
    ValueError
        A column at ``max_period`` would have fewer than two letters.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.coincidence_profile("ABABABABABAB", max_period=3).best_period
    2
    """
    _validation.integer(max_period, "max_period", minimum=1)
    letters = clean(ciphertext, "ciphertext")
    if len(letters) < 2 * max_period:
        raise ValueError("ciphertext needs at least two letters per column at max_period")
    periods = tuple(range(1, max_period + 1))
    means = tuple(sum(index_of_coincidence(letters[j::p]) for j in range(p)) / p for p in periods)
    best = next(p for p, m in zip(periods, means, strict=True) if m >= 0.9 * max(means))
    return CoincidenceProfile(periods, means, best)


def break_vigenere(ciphertext: str, period: int) -> VigenereBreakResult:
    """Recover the keyword by breaking each column as a shift cipher.

    Parameters
    ----------
    ciphertext : str
        Vigenère ciphertext.
    period : int
        Keyword length, from :func:`coincidence_profile` or Kasiski examination.

    Returns
    -------
    VigenereBreakResult
        The keyword, the plaintext and the number of shifts scored.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> plaintext = "the general orders the army to cross the river at first light " * 3
    >>> ciphertext = classical.vigenere_encrypt(plaintext, "ROME")
    >>> classical.break_vigenere(ciphertext, 4).key
    'ROME'
    """
    _validation.integer(period, "period", minimum=1)
    letters = clean(ciphertext, "ciphertext")
    if len(letters) < period:
        raise ValueError("ciphertext must have at least one letter per column")
    key = "".join(ALPHABET[break_shift_cipher(letters[j::period]).shift] for j in range(period))
    return VigenereBreakResult(key, vigenere_decrypt(letters, key), 26 * period)
