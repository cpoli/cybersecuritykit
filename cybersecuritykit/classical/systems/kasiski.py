"""Kasiski's examination (1863) of repeated fragments in polyalphabetic ciphertext.

F. W. Kasiski, *Die Geheimschriften und die Dechiffrir-Kunst* (Berlin, 1863).
Charles Babbage had found the same attack earlier but never published it.
A fragment of plaintext that recurs at a multiple of the keyword length is
enciphered identically, so the gaps between ciphertext repeats share the
keyword length as a factor.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import KasiskiResult
from cybersecuritykit.classical.utils.text import clean

__all__ = ["kasiski_examination"]


def kasiski_examination(ciphertext: str, length: int = 3, max_period: int = 20) -> KasiskiResult:
    """Find repeated fragments and count which periods divide the gaps between them.

    Parameters
    ----------
    ciphertext : str
        Polyalphabetic ciphertext; non-letters are dropped.
    length : int, optional
        Length of the fragments to look for; at least 2.
    max_period : int, optional
        Largest candidate period; at least 2.

    Returns
    -------
    KasiskiResult
        The repeats, the factor counts, and the likely period.

    Raises
    ------
    ValueError
        No fragment repeats, so there is nothing to examine.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> result = classical.kasiski_examination("ABCXXABCYYABC", max_period=5)
    >>> result.repeats["ABC"], result.likely_period
    ((0, 5, 10), 5)
    """
    _validation.integer(length, "length", minimum=2)
    _validation.integer(max_period, "max_period", minimum=2)
    letters = clean(ciphertext, "ciphertext")
    starts: dict[str, list[int]] = {}
    for i in range(len(letters) - length + 1):
        starts.setdefault(letters[i : i + length], []).append(i)
    repeats = {f: tuple(at) for f, at in starts.items() if len(at) > 1}
    gaps = [b - a for at in repeats.values() for a, b in zip(at, at[1:], strict=False)]
    if not gaps:
        raise ValueError("no fragment repeats; the ciphertext is too short to examine")
    counts = {f: sum(g % f == 0 for g in gaps) for f in range(2, max_period + 1)}
    top = max(counts.values())
    likely = max(f for f, n in counts.items() if n >= 0.8 * top)
    return KasiskiResult(repeats, counts, likely)
