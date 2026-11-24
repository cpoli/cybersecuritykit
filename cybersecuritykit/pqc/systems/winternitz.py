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
from cybersecuritykit.pqc.utils import hash_trees

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

WINTERNITZ_WIDTHS = hash_trees.WIDTHS
"""The Winternitz parameters allowed; each digit is a whole number of bits dividing 8."""


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
    hash_trees.check_width(w)
    return hash_trees.digits(digest, w)


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
    hash_trees.check_hash_length(n)
    hash_trees.check_width(w)
    rng = random.Random(seed)
    secret_seed, public_seed = rng.randbytes(n), rng.randbytes(n)
    return hash_trees.wots_key(secret_seed, public_seed, b"", w)


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
    return hash_trees.wots_digest(public.public_seed, public.address, message)


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
    return hash_trees.wots_sign(key, winternitz_digest(key.public, message))


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
    recovered = hash_trees.wots_public(
        public.public_seed, public.address, public.w, digest, signature
    )
    return recovered is not None and recovered.chains == public.chains


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
    return hash_trees.forge_chains(public, observed, max_tries)


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
    hash_trees.check_hash_length(n)
    hash_trees.check_width(w)
    chains = sum(hash_trees.lengths(n, w))
    return WinternitzCost(w, chains, chains * n, chains * (w - 1))
