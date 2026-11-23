"""Text normalization shared by the classical ciphers."""

from cybersecuritykit.constants import ALPHABET

_INDEX = {letter: i for i, letter in enumerate(ALPHABET)}


def string(value: object, name: str) -> str:
    """Return ``value`` unchanged if it is a ``str``; raise ``TypeError`` otherwise."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, not {type(value).__name__}")
    return value


def clean(text: str, name: str = "text") -> str:
    """Return the letters of ``text`` in upper case, dropping everything else.

    Classical ciphers act on the 26-letter alphabet only, so spaces,
    punctuation and digits are removed before encryption, as clerks did.

    Raises
    ------
    TypeError
        ``text`` is not a ``str``.
    """
    return "".join(c for c in string(text, name).upper() if c in _INDEX)


def to_numbers(text: str) -> list[int]:
    """Map already cleaned letters to 0..25."""
    return [_INDEX[c] for c in text]


def to_letters(numbers: list[int]) -> str:
    """Map numbers to letters modulo 26."""
    return "".join(ALPHABET[n % 26] for n in numbers)


def permutation(key: str, name: str) -> str:
    """Validate a 26-letter key that uses every letter exactly once."""
    key = string(key, name).upper()
    if sorted(key) != list(ALPHABET):
        raise ValueError(f"{name} must use each of the 26 letters exactly once")
    return key
