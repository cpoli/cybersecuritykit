"""Bellaso's polyalphabetic cipher (1553), later misattributed to Vigenère.

G. B. Bellaso, *La cifra del Sig. Giovan Battista Bellaso* (Venice, 1553).
A short keyword selects one shift per position; the shifts repeat with the
keyword's length, which is the weakness Kasiski and Friedman exploited.
"""

from cybersecuritykit.classical.utils.text import clean, to_letters, to_numbers

__all__ = ["vigenere_decrypt", "vigenere_encrypt"]


def _key(key: str) -> list[int]:
    numbers = to_numbers(clean(key, "key"))
    if not numbers:
        raise ValueError("key must contain at least one letter")
    return numbers


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt by adding the repeating keyword to the plaintext, letter by letter.

    Parameters
    ----------
    plaintext : str
        Text to encrypt; non-letters are dropped.
    key : str
        Keyword; ``A`` is a shift of 0.

    Returns
    -------
    str
        Upper-case ciphertext.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.vigenere_encrypt("attack at dawn", "lemon")
    'LXFOPVEFRNHR'
    """
    k = _key(key)
    p = to_numbers(clean(plaintext, "plaintext"))
    return to_letters([x + k[i % len(k)] for i, x in enumerate(p)])


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Invert :func:`vigenere_encrypt` with the same keyword.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.vigenere_decrypt("LXFOPVEFRNHR", "LEMON")
    'ATTACKATDAWN'
    """
    k = _key(key)
    c = to_numbers(clean(ciphertext, "ciphertext"))
    return to_letters([x - k[i % len(k)] for i, x in enumerate(c)])
