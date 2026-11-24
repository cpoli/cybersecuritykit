"""Winternitz one-time signatures (Merkle 1979, crediting Winternitz).

R. C. Merkle, "A certified digital signature", *CRYPTO '89*, LNCS 435, 1990,
pp. 218-238 (written in 1979). Lamport's scheme reveals one of two secrets per
message bit. Winternitz's improvement signs :math:`\\log_2 w` bits at once: the
signer publishes the end of a hash chain of length :math:`w - 1` for each
base-:math:`w` digit, and signs digit :math:`d` by revealing the value
:math:`d` steps along it. A checksum of the missing steps stops a forger from
moving every chain forward. Chain and digit layout follow WOTS+ in RFC 8391,
with a tweakable SHA-256 in place of its bitmasks.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    WinternitzCost,
    WinternitzForgery,
    WinternitzKey,
    WinternitzPublicKey,
    WinternitzSignature,
)
from cybersecuritykit.pqc.utils.hash_trees import derive, tweak_hash

__all__ = [
    "WINTERNITZ_WIDTHS",
    "winternitz_cost",
    "winternitz_digest",
    "winternitz_digits",
    "winternitz_forge",
    "winternitz_keygen",
    "winternitz_sign",
    "winternitz_verify",
]

WINTERNITZ_WIDTHS = (2, 4, 16, 256)
"""The Winternitz parameters allowed; each digit is a whole number of bits dividing 8."""


def _check_width(w: int) -> int:
    """Validate the Winternitz parameter and return its bits per digit."""
    _validation.integer(w, "w", 2)
    if w not in WINTERNITZ_WIDTHS:
        raise ValueError(f"w must be one of {WINTERNITZ_WIDTHS}")
    return w.bit_length() - 1


def _lengths(n: int, w: int) -> tuple[int, int]:
    """Message digits and checksum digits for an ``n``-byte digest (RFC 8391, 3.1.1)."""
    bits = w.bit_length() - 1
    message = 8 * n // bits
    checksum, top = 1, message * (w - 1)
    while top >= w:
        top //= w
        checksum += 1
    return message, checksum


def winternitz_digits(digest: bytes, w: int) -> tuple[int, ...]:
    """Split a digest into base-``w`` digits and append the checksum digits.

    The checksum :math:`C = \\sum_i (w - 1 - d_i)` counts the hash steps the
    signature leaves undone. Raising any message digit lowers :math:`C`, so a
    forger who can only move chains forward cannot raise every digit.

    Parameters
    ----------
    digest : bytes
        The value to sign; not empty.
    w : int
        The Winternitz parameter, one of 2, 4, 16 and 256.

    Returns
    -------
    tuple of int
        The message digits, most significant first, then the checksum digits.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.winternitz_digits(b"\\x12\\x34", 16)
    (1, 2, 3, 4, 3, 2)
    """
    _validation.byte_string(digest, "digest", allow_empty=False)
    bits = _check_width(w)
    message_count, checksum_count = _lengths(len(digest), w)
    value = int.from_bytes(digest, "big")
    digits = [(value >> (bits * i)) & (w - 1) for i in reversed(range(message_count))]
    checksum = sum(w - 1 - d for d in digits)
    digits += [(checksum >> (bits * i)) & (w - 1) for i in reversed(range(checksum_count))]
    return tuple(digits)


def _check_hash_length(n: int) -> None:
    _validation.integer(n, "n", 2)
    if n > 32:
        raise ValueError("n must be at most 32, the length of a SHA-256 digest")


def _chain(
    public_seed: bytes, address: bytes, index: int, value: bytes, start: int, steps: int
) -> bytes:
    """Apply steps ``start + 1, ..., start + steps`` of chain ``index`` to ``value``."""
    for step in range(start, start + steps):
        tweak = address + b"chain" + index.to_bytes(2, "big") + step.to_bytes(1, "big")
        value = tweak_hash(public_seed, tweak, value)
    return value


def _wots_key(secret_seed: bytes, public_seed: bytes, address: bytes, w: int) -> WinternitzKey:
    """The one-time key at ``address``, derived from ``secret_seed``."""
    count = sum(_lengths(len(public_seed), w))
    secret = tuple(
        derive(secret_seed, address + b"wots" + i.to_bytes(2, "big")) for i in range(count)
    )
    chains = tuple(_chain(public_seed, address, i, s, 0, w - 1) for i, s in enumerate(secret))
    return WinternitzKey(secret, WinternitzPublicKey(chains, public_seed, address, w))


def _wots_sign(key: WinternitzKey, digest: bytes) -> WinternitzSignature:
    """Sign an ``n``-byte digest: move each chain forward by its digit."""
    public = key.public
    digits = winternitz_digits(digest, public.w)
    return WinternitzSignature(
        tuple(
            _chain(public.public_seed, public.address, i, s, 0, d)
            for i, (s, d) in enumerate(zip(key.secret, digits, strict=True))
        )
    )


def _wots_public(
    public_seed: bytes, address: bytes, w: int, digest: bytes, signature: WinternitzSignature
) -> WinternitzPublicKey | None:
    """Finish every chain of a signature; ``None`` if it has the wrong number of chains."""
    digits = winternitz_digits(digest, w)
    if len(signature.chains) != len(digits):
        return None
    chains = tuple(
        _chain(public_seed, address, i, v, d, w - 1 - d)
        for i, (v, d) in enumerate(zip(signature.chains, digits, strict=True))
    )
    return WinternitzPublicKey(chains, public_seed, address, w)


def winternitz_keygen(seed: int = DEFAULT_SEED, *, n: int = 16, w: int = 16) -> WinternitzKey:
    r"""Make a Winternitz one-time key pair.

    Each secret is the start of a hash chain; the public key is the end of
    each chain after :math:`w - 1` steps,

    .. math::

       \mathrm{pk}_i = F^{w-1}(\mathrm{sk}_i).

    Parameters
    ----------
    seed : int, optional
        Seeds the secret and public seeds; the same seed gives the same key.
    n : int, optional
        Hash length in bytes, from 2 to 32. Real schemes use 16 or more.
    w : int, optional
        The Winternitz parameter, one of ``WINTERNITZ_WIDTHS``.

    Returns
    -------
    WinternitzKey

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.winternitz_keygen(1, n=16, w=16)
    >>> len(key.public.chains)
    35
    """
    _validation.seed(seed)
    _check_hash_length(n)
    _check_width(w)
    rng = random.Random(seed)
    secret_seed, public_seed = rng.randbytes(n), rng.randbytes(n)
    return _wots_key(secret_seed, public_seed, b"", w)


def winternitz_digest(public: WinternitzPublicKey, message: bytes) -> bytes:
    """The ``n``-byte value that a key signs for ``message``.

    It is hashed with the key's seed and address, so that the digits of one
    key's signature say nothing about another key's.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.winternitz_keygen(1, n=8)
    >>> len(pqc.winternitz_digest(key.public, b"hello"))
    8
    """
    _validation.byte_string(message, "message")
    return tweak_hash(public.public_seed, public.address + b"message", message)


def winternitz_sign(key: WinternitzKey, message: bytes) -> WinternitzSignature:
    """Sign ``message``: reveal, for each digit :math:`d_i`, the value :math:`F^{d_i}(sk_i)`.

    The key must sign only once; see
    :func:`~cybersecuritykit.pqc.systems.winternitz.winternitz_forge` for what a
    second signature gives away.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.winternitz_keygen(1)
    >>> signature = pqc.winternitz_sign(key, b"hello")
    >>> pqc.winternitz_verify(key.public, b"hello", signature)
    True
    """
    return _wots_sign(key, winternitz_digest(key.public, message))


def winternitz_verify(
    public: WinternitzPublicKey, message: bytes, signature: WinternitzSignature
) -> bool:
    r"""Check a signature by finishing each chain, :math:`F^{w-1-d_i}(\sigma_i) = pk_i`.

    Returns
    -------
    bool
        Whether every finished chain equals the public chain end.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.winternitz_keygen(1)
    >>> signature = pqc.winternitz_sign(key, b"hello")
    >>> pqc.winternitz_verify(key.public, b"goodbye", signature)
    False
    """
    digest = winternitz_digest(public, message)
    recovered = _wots_public(public.public_seed, public.address, public.w, digest, signature)
    return recovered is not None and recovered.chains == public.chains


def _forge_chains(
    public: WinternitzPublicKey,
    observed: Sequence[tuple[bytes, WinternitzSignature]],
    max_tries: int,
) -> WinternitzForgery:
    """Search messages whose every digit is at least the smallest digit seen there."""
    w, seed, address = public.w, public.public_seed, public.address
    lowest: list[tuple[int, bytes]] = []
    for message, signature in observed:
        if not winternitz_verify(public, message, signature):
            raise ValueError("every observed signature must verify under the public key")
        digits = winternitz_digits(winternitz_digest(public, message), w)
        pairs = zip(digits, signature.chains, strict=True)
        lowest = (
            list(pairs) if not lowest else [min(a, b) for a, b in zip(lowest, pairs, strict=True)]
        )
    signed = {message for message, _ in observed}
    for tested in range(1, max_tries + 1):
        candidate = b"forgery %d" % (tested - 1)
        digits = winternitz_digits(winternitz_digest(public, candidate), w)
        if candidate in signed or any(d < low for d, (low, _) in zip(digits, lowest, strict=True)):
            continue
        chains = tuple(
            _chain(seed, address, i, value, low, d - low)
            for i, (d, (low, value)) in enumerate(zip(digits, lowest, strict=True))
        )
        return WinternitzForgery(candidate, WinternitzSignature(chains), tested)
    return WinternitzForgery(None, None, max_tries)


def winternitz_forge(
    public: WinternitzPublicKey,
    observed: Sequence[tuple[bytes, WinternitzSignature]],
    *,
    max_tries: int = 100_000,
) -> WinternitzForgery:
    r"""Forge a signature from several signatures made with one Winternitz key.

    Anyone can move a chain forward, never back. From the signatures seen the
    forger keeps, for each chain :math:`i`, the value with the smallest digit
    :math:`m_i`, and can sign every message whose digits satisfy

    .. math::

       d_i \ge m_i \quad \text{for every message and checksum digit } i.

    After one signature the checksum makes this impossible for any other
    message; each further signature lowers the :math:`m_i` and the search
    soon succeeds. The candidates are ``b"forgery 0"``, ``b"forgery 1"``, ...

    Parameters
    ----------
    public : WinternitzPublicKey
        The victim's public key.
    observed : sequence of tuple
        ``(message, signature)`` pairs signed with the key; at least one, all valid.
    max_tries : int, optional
        Candidate messages to try before giving up.

    Returns
    -------
    WinternitzForgery

    Raises
    ------
    ValueError
        ``observed`` is empty or holds a signature that does not verify.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.winternitz_keygen(11, n=8)
    >>> seen = [(m, pqc.winternitz_sign(key, m)) for m in (b"a", b"b", b"c", b"d")]
    >>> forgery = pqc.winternitz_forge(key.public, seen)
    >>> pqc.winternitz_verify(key.public, forgery.message, forgery.signature)
    True
    """
    _validation.integer(max_tries, "max_tries", 1)
    if not observed:
        raise ValueError("observed must hold at least one signed message")
    return _forge_chains(public, observed, max_tries)


def winternitz_cost(n: int, w: int) -> WinternitzCost:
    r"""Chains, signature size and hashing work for an ``n``-byte hash and parameter ``w``.

    A larger :math:`w` signs more bits per chain, so signatures shrink about as
    :math:`1/\log_2 w`, while each chain gets :math:`w - 1` steps long.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.winternitz_cost(16, 16)
    WinternitzCost(w=16, chains=35, signature_bytes=560, keygen_hashes=525)
    """
    _check_hash_length(n)
    _check_width(w)
    chains = sum(_lengths(n, w))
    return WinternitzCost(w, chains, chains * n, chains * (w - 1))
