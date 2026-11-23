"""Vernam's teleprinter cipher (1917) and the two-time pad.

G. S. Vernam, "Cipher printing telegraph systems for secret wire and radio
telegraphic communications", *J. AIEE* 45, 1926. Combining each plaintext
symbol with a key symbol by exclusive or is unbreakable when the key is
random and used once; reusing it cancels the key and leaves the exclusive
or of the two plaintexts, which cribs then pick apart.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import CribDragHit

__all__ = ["crib_drag", "two_time_pad", "vernam_encrypt"]


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings, stopping at the end of the shorter."""
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def vernam_encrypt(data: bytes, key: bytes) -> bytes:
    """Exclusive-or ``data`` with the first ``len(data)`` bytes of ``key``.

    The operation is its own inverse, so it also decrypts.

    Raises
    ------
    ValueError
        ``key`` is shorter than ``data``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.vernam_encrypt(b"HI", b"\\x01\\x02")
    b'IK'
    """
    _validation.byte_string(data, "data")
    _validation.byte_string(key, "key")
    if len(key) < len(data):
        raise ValueError("key must be at least as long as data")
    return _xor(data, key)


def two_time_pad(first: bytes, second: bytes) -> bytes:
    """Combine two ciphertexts made with the same key: the key cancels.

    Returns
    -------
    bytes
        The exclusive or of the two plaintexts, as long as the shorter input.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = b"\\x10\\x20\\x30"
    >>> c1 = classical.vernam_encrypt(b"ABC", key)
    >>> c2 = classical.vernam_encrypt(b"ABD", key)
    >>> classical.two_time_pad(c1, c2)
    b'\\x00\\x00\\x07'
    """
    _validation.byte_string(first, "first")
    _validation.byte_string(second, "second")
    return _xor(first, second)


def crib_drag(first: bytes, second: bytes, crib: bytes) -> tuple[CribDragHit, ...]:
    """Slide a guessed fragment of one plaintext along a two-time pad.

    At each offset the crib is combined with :func:`two_time_pad`; where the
    result is printable ASCII, the guess may be right and the result is the
    other plaintext there.

    Parameters
    ----------
    first, second : bytes
        Two ciphertexts made with the same key.
    crib : bytes
        A fragment guessed to occur in either plaintext; not empty.

    Returns
    -------
    tuple of CribDragHit
        Every offset that yields printable text, in order.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> key = bytes(range(100, 110))
    >>> c1 = classical.vernam_encrypt(b"ATTACK NOW", key)
    >>> c2 = classical.vernam_encrypt(b"HOLD STILL", key)
    >>> [h.fragment for h in classical.crib_drag(c1, c2, b"NOW") if h.offset == 7]
    [b'ILL']
    """
    _validation.byte_string(crib, "crib", allow_empty=False)
    combined = two_time_pad(first, second)
    hits = []
    for offset in range(len(combined) - len(crib) + 1):
        fragment = _xor(combined[offset:], crib)
        if all(32 <= b < 127 for b in fragment):
            hits.append(CribDragHit(offset, fragment))
    return tuple(hits)
