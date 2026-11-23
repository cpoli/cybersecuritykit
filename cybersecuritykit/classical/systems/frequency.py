"""Shift ciphers and al-Kindi's frequency analysis (c. 850).

al-Kindi, *Risala fi istikhraj al-mu'amma* (Manuscript on Deciphering
Cryptographic Messages); see I. A. Al-Kadi, "Origins of cryptology: the Arab
contributions", *Cryptologia* 16(2), 1992.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import ShiftBreakResult
from cybersecuritykit.classical.utils.english import ENGLISH_FREQUENCIES
from cybersecuritykit.classical.utils.text import clean, to_letters, to_numbers
from cybersecuritykit.constants import ALPHABET

__all__ = [
    "break_shift_cipher",
    "chi_squared",
    "letter_frequencies",
    "shift_decrypt",
    "shift_encrypt",
]


def _shift_key(shift: int) -> None:
    _validation.integer(shift, "shift")
    if shift > 25:
        raise ValueError("shift must be in 0..25")


def shift_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt with a shift (Caesar) cipher: each letter moves ``shift`` places on.

    Parameters
    ----------
    plaintext : str
        Text to encrypt; everything but letters is dropped.
    shift : int
        Key in ``0..25``.

    Returns
    -------
    str
        Upper-case ciphertext.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.shift_encrypt("attack at dawn", 3)
    'DWWDFNDWGDZQ'
    """
    _shift_key(shift)
    return to_letters([n + shift for n in to_numbers(clean(plaintext, "plaintext"))])


def shift_decrypt(ciphertext: str, shift: int) -> str:
    """Invert :func:`shift_encrypt` for the same ``shift``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.shift_decrypt("DWWDFNDWGDZQ", 3)
    'ATTACKATDAWN'
    """
    _shift_key(shift)
    return shift_encrypt(ciphertext, (26 - shift) % 26)


def letter_frequencies(text: str) -> dict[str, float]:
    """Return the fraction of each letter A-Z among the letters of ``text``.

    Raises
    ------
    ValueError
        ``text`` contains no letters.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.letter_frequencies("abba")["B"]
    0.5
    """
    letters = clean(text)
    if not letters:
        raise ValueError("text must contain at least one letter")
    return {c: letters.count(c) / len(letters) for c in ALPHABET}


def chi_squared(text: str) -> float:
    r"""Return Pearson's :math:`\chi^2` distance between ``text`` and English letter counts.

    Smaller is more English-like; this is the score al-Kindi's method
    minimizes, written in modern form.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.chi_squared("etaoin") < classical.chi_squared("qzjxkv")
    True
    """
    observed = letter_frequencies(text)
    n = len(clean(text))
    return sum(
        (observed[c] * n - ENGLISH_FREQUENCIES[c] / 100 * n) ** 2
        / (ENGLISH_FREQUENCIES[c] / 100 * n)
        for c in ALPHABET
    )


def break_shift_cipher(ciphertext: str) -> ShiftBreakResult:
    """Recover a shift key by trying all 26 and keeping the most English-looking.

    Parameters
    ----------
    ciphertext : str
        Text produced by :func:`shift_encrypt`.

    Returns
    -------
    ShiftBreakResult
        The best shift, its plaintext and the :func:`chi_squared` score of every shift.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> ciphertext = classical.shift_encrypt("the enemy retreats at nightfall", 7)
    >>> classical.break_shift_cipher(ciphertext).shift
    7
    """
    scores = tuple(chi_squared(shift_decrypt(ciphertext, s)) for s in range(26))
    best = scores.index(min(scores))
    return ShiftBreakResult(best, shift_decrypt(ciphertext, best), scores)
