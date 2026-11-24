"""Tweakable hashing, Winternitz chains and Merkle trees shared by the hash-based signatures.

Every hash call is keyed by a public seed and an *address* naming where in the
scheme it happens (which key, chain, step or tree node), as in XMSS-T and
SPHINCS+, so that one hash output can never be reused in another position.
Winternitz chains follow WOTS+ in RFC 8391; a tree of Winternitz keys is the
XMSS tree, which SPHINCS stacks into a hypertree. Only :mod:`hashlib` is used.
"""

import hashlib
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.pqc.core.base import (
    WinternitzForgery,
    WinternitzKey,
    WinternitzPublicKey,
    WinternitzSignature,
    XMSSSignature,
)

__all__ = [
    "MAX_HEIGHT",
    "WIDTHS",
    "auth_path",
    "build_tree",
    "chain",
    "check_hash_length",
    "check_height",
    "check_width",
    "derive",
    "digits",
    "forge_chains",
    "leaf_address",
    "leaf_digest",
    "lengths",
    "root_from_path",
    "tree_levels",
    "tree_root",
    "tree_sign",
    "tweak_hash",
    "wots_digest",
    "wots_key",
    "wots_public",
    "wots_sign",
]

Levels = tuple[tuple[bytes, ...], ...]

WIDTHS = (2, 4, 16, 256)
"""The Winternitz parameters allowed; each digit is a whole number of bits dividing 8."""

MAX_HEIGHT = 10
"""Tallest tree allowed; its :math:`2^{10}` leaves keep key generation to seconds."""


def check_hash_length(n: int) -> None:
    """Validate a hash length in bytes, from 2 to 32."""
    _validation.integer(n, "n", 2)
    if n > 32:
        raise ValueError("n must be at most 32, the length of a SHA-256 digest")


def check_width(w: int) -> int:
    """Validate the Winternitz parameter and return its bits per digit."""
    _validation.integer(w, "w", 2)
    if w not in WIDTHS:
        raise ValueError(f"w must be one of {WIDTHS}")
    return w.bit_length() - 1


def check_height(height: int) -> None:
    """Validate a tree height, from 1 to ``MAX_HEIGHT``."""
    _validation.integer(height, "height", 1)
    if height > MAX_HEIGHT:
        raise ValueError(f"height must be at most {MAX_HEIGHT}")


def tweak_hash(public_seed: bytes, address: bytes, data: bytes) -> bytes:
    """SHA-256 of seed, address and data, truncated to ``len(public_seed)`` bytes."""
    return hashlib.sha256(public_seed + address + data).digest()[: len(public_seed)]


def derive(secret_seed: bytes, address: bytes) -> bytes:
    """A secret value for ``address``, as long as ``secret_seed``: a toy PRF."""
    return hashlib.sha256(b"secret" + secret_seed + address).digest()[: len(secret_seed)]


def _node(public_seed: bytes, tree: bytes, level: int, index: int, pair: bytes) -> bytes:
    address = tree + b"node" + level.to_bytes(1, "big") + index.to_bytes(4, "big")
    return tweak_hash(public_seed, address, pair)


def build_tree(public_seed: bytes, tree: bytes, leaves: Sequence[bytes]) -> Levels:
    """All levels of the Merkle tree over ``leaves`` (a power of two), leaves first."""
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        below = levels[-1]
        level = len(levels)
        levels.append(
            tuple(
                _node(public_seed, tree, level, i, below[2 * i] + below[2 * i + 1])
                for i in range(len(below) // 2)
            )
        )
    return tuple(levels)


def auth_path(levels: Sequence[Sequence[bytes]], index: int) -> tuple[bytes, ...]:
    """The sibling of each node on the way from leaf ``index`` to the root."""
    return tuple(level[(index >> h) ^ 1] for h, level in enumerate(levels[:-1]))


def root_from_path(
    public_seed: bytes, tree: bytes, leaf: bytes, index: int, path: Sequence[bytes]
) -> bytes:
    """Hash ``leaf`` up the tree with its authentication path and return the root."""
    node = leaf
    for h, sibling in enumerate(path):
        pair = node + sibling if (index >> h) & 1 == 0 else sibling + node
        node = _node(public_seed, tree, h + 1, index >> (h + 1), pair)
    return node


# Winternitz chains (WOTS+)


def lengths(n: int, w: int) -> tuple[int, int]:
    """Message digits and checksum digits for an ``n``-byte digest (RFC 8391, 3.1.1)."""
    bits = w.bit_length() - 1
    message = 8 * n // bits
    checksum, top = 1, message * (w - 1)
    while top >= w:
        top //= w
        checksum += 1
    return message, checksum


def digits(digest: bytes, w: int) -> tuple[int, ...]:
    """Base-``w`` digits of ``digest``, most significant first, then the checksum digits."""
    bits = w.bit_length() - 1
    message_count, checksum_count = lengths(len(digest), w)
    value = int.from_bytes(digest, "big")
    out = [(value >> (bits * i)) & (w - 1) for i in reversed(range(message_count))]
    checksum = sum(w - 1 - d for d in out)
    out += [(checksum >> (bits * i)) & (w - 1) for i in reversed(range(checksum_count))]
    return tuple(out)


def chain(
    public_seed: bytes, address: bytes, index: int, value: bytes, start: int, steps: int
) -> bytes:
    """Apply steps ``start + 1, ..., start + steps`` of chain ``index`` to ``value``."""
    for step in range(start, start + steps):
        tweak = address + b"chain" + index.to_bytes(2, "big") + step.to_bytes(1, "big")
        value = tweak_hash(public_seed, tweak, value)
    return value


def wots_key(secret_seed: bytes, public_seed: bytes, address: bytes, w: int) -> WinternitzKey:
    """The one-time key at ``address``, derived from ``secret_seed``."""
    count = sum(lengths(len(public_seed), w))
    secret = tuple(
        derive(secret_seed, address + b"wots" + i.to_bytes(2, "big")) for i in range(count)
    )
    chains = tuple(chain(public_seed, address, i, s, 0, w - 1) for i, s in enumerate(secret))
    return WinternitzKey(secret, WinternitzPublicKey(chains, public_seed, address, w))


def wots_digest(public_seed: bytes, address: bytes, message: bytes) -> bytes:
    """The ``n``-byte value the one-time key at ``address`` signs for ``message``."""
    return tweak_hash(public_seed, address + b"message", message)


def wots_sign(key: WinternitzKey, digest: bytes) -> WinternitzSignature:
    """Sign an ``n``-byte digest: move each chain forward by its digit."""
    public = key.public
    return WinternitzSignature(
        tuple(
            chain(public.public_seed, public.address, i, s, 0, d)
            for i, (s, d) in enumerate(zip(key.secret, digits(digest, public.w), strict=True))
        )
    )


def wots_public(
    public_seed: bytes, address: bytes, w: int, digest: bytes, signature: WinternitzSignature
) -> WinternitzPublicKey | None:
    """Finish every chain of a signature; ``None`` if it has the wrong number of chains."""
    ds = digits(digest, w)
    if len(signature.chains) != len(ds):
        return None
    chains = tuple(
        chain(public_seed, address, i, v, d, w - 1 - d)
        for i, (v, d) in enumerate(zip(signature.chains, ds, strict=True))
    )
    return WinternitzPublicKey(chains, public_seed, address, w)


def forge_chains(
    public: WinternitzPublicKey,
    observed: Sequence[tuple[bytes, WinternitzSignature]],
    max_tries: int,
) -> WinternitzForgery:
    """Search messages whose every digit is at least the smallest digit seen there.

    Raises :class:`ValueError` if an observed signature does not verify.
    """
    w, seed, address = public.w, public.public_seed, public.address
    lowest: list[tuple[int, bytes]] = []
    for message, signature in observed:
        _validation.byte_string(message, "message")
        digest = wots_digest(seed, address, message)
        recovered = wots_public(seed, address, w, digest, signature)
        if recovered is None or recovered.chains != public.chains:
            raise ValueError("every observed signature must verify under the public key")
        pairs = zip(digits(digest, w), signature.chains, strict=True)
        lowest = (
            list(pairs) if not lowest else [min(a, b) for a, b in zip(lowest, pairs, strict=True)]
        )
    signed = {message for message, _ in observed}
    for tested in range(1, max_tries + 1):
        candidate = b"forgery %d" % (tested - 1)
        ds = digits(wots_digest(seed, address, candidate), w)
        if candidate in signed or any(d < low for d, (low, _) in zip(ds, lowest, strict=True)):
            continue
        chains = tuple(
            chain(seed, address, i, value, low, d - low)
            for i, (d, (low, value)) in enumerate(zip(ds, lowest, strict=True))
        )
        return WinternitzForgery(candidate, WinternitzSignature(chains), tested)
    return WinternitzForgery(None, None, max_tries)


# Trees of Winternitz keys (XMSS, and each layer of the SPHINCS hypertree)


def leaf_address(tree: bytes, index: int) -> bytes:
    """The address of leaf ``index``'s one-time key in the tree at address ``tree``."""
    return tree + b"leaf" + index.to_bytes(4, "big")


def _leaf(public: WinternitzPublicKey) -> bytes:
    """Compress a Winternitz public key into one tree leaf."""
    return tweak_hash(public.public_seed, public.address + b"pk", b"".join(public.chains))


def leaf_digest(public_seed: bytes, tree: bytes, index: int, message: bytes) -> bytes:
    """The value leaf ``index`` signs for ``message``, as its Winternitz key would hash it."""
    return wots_digest(public_seed, leaf_address(tree, index), message)


def tree_levels(secret_seed: bytes, public_seed: bytes, tree: bytes, height: int, w: int) -> Levels:
    """Every level of the tree of one-time keys at address ``tree``, leaves first."""
    leaves = [
        _leaf(wots_key(secret_seed, public_seed, leaf_address(tree, i), w).public)
        for i in range(2**height)
    ]
    return build_tree(public_seed, tree, leaves)


def tree_sign(
    secret_seed: bytes,
    public_seed: bytes,
    tree: bytes,
    levels: Levels,
    w: int,
    index: int,
    digest: bytes,
) -> XMSSSignature:
    """Sign ``digest`` with leaf ``index`` of a tree and attach its authentication path."""
    key = wots_key(secret_seed, public_seed, leaf_address(tree, index), w)
    return XMSSSignature(index, wots_sign(key, digest), auth_path(levels, index))


def tree_root(
    public_seed: bytes, tree: bytes, w: int, digest: bytes, signature: XMSSSignature
) -> bytes | None:
    """The root a signature leads to; ``None`` if it is malformed."""
    address = leaf_address(tree, signature.index)
    public = wots_public(public_seed, address, w, digest, signature.wots)
    if public is None:
        return None
    return root_from_path(public_seed, tree, _leaf(public), signature.index, signature.auth_path)
