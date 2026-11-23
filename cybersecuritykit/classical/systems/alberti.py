"""Alberti's cipher disk (c. 1467), the first polyalphabetic cipher.

L. B. Alberti, *De componendis cifris* (c. 1467). The inner disk carries a
mixed alphabet; turning it every few letters changes the substitution, so one
plaintext letter no longer has one ciphertext letter.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.utils.text import clean, permutation, to_letters, to_numbers

__all__ = ["alberti_decrypt", "alberti_encrypt"]


def _check(disk: str, start: int, period: int) -> str:
    _validation.integer(start, "start")
    _validation.integer(period, "period", minimum=1)
    return permutation(disk, "disk")


def alberti_encrypt(plaintext: str, disk: str, start: int = 0, period: int = 1) -> str:
    """Encrypt with a cipher disk turned one step after every ``period`` letters.

    Letter ``i`` of the plaintext, at alphabet index ``p``, becomes
    ``disk[(p + start + i // period) % 26]``.

    Parameters
    ----------
    plaintext : str
        Text to encrypt; non-letters are dropped.
    disk : str
        The inner disk: the 26 letters in any order.
    start : int, optional
        Initial rotation of the inner disk.
    period : int, optional
        Number of letters enciphered before each turn; at least 1.

    Returns
    -------
    str
        Upper-case ciphertext.

    Examples
    --------
    >>> from cybersecuritykit import classical, constants
    >>> classical.alberti_encrypt("AAAA", constants.ALPHABET, period=2)
    'AABB'
    """
    disk = _check(disk, start, period)
    numbers = to_numbers(clean(plaintext, "plaintext"))
    return "".join(disk[(p + start + i // period) % 26] for i, p in enumerate(numbers))


def alberti_decrypt(ciphertext: str, disk: str, start: int = 0, period: int = 1) -> str:
    """Invert :func:`alberti_encrypt` for the same disk, start and period.

    Examples
    --------
    >>> from cybersecuritykit import classical, constants
    >>> classical.alberti_decrypt("AABB", constants.ALPHABET, period=2)
    'AAAA'
    """
    disk = _check(disk, start, period)
    letters = clean(ciphertext, "ciphertext")
    return to_letters([disk.index(c) - start - i // period for i, c in enumerate(letters)])
