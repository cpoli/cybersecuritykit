"""Tweakable hashing and Merkle trees shared by the hash-based signatures.

Every hash call is keyed by a public seed and an *address* naming where in the
scheme it happens (which key, chain, step or tree node), as in XMSS-T and
SPHINCS+, so that one hash output can never be reused in another position.
Only :mod:`hashlib` is used.
"""

import hashlib
from collections.abc import Sequence

__all__ = ["auth_path", "build_tree", "derive", "root_from_path", "tweak_hash"]


def tweak_hash(public_seed: bytes, address: bytes, data: bytes) -> bytes:
    """SHA-256 of seed, address and data, truncated to ``len(public_seed)`` bytes."""
    return hashlib.sha256(public_seed + address + data).digest()[: len(public_seed)]


def derive(secret_seed: bytes, address: bytes) -> bytes:
    """A secret value for ``address``, as long as ``secret_seed``: a toy PRF."""
    return hashlib.sha256(b"secret" + secret_seed + address).digest()[: len(secret_seed)]


def _node(public_seed: bytes, tree: bytes, level: int, index: int, pair: bytes) -> bytes:
    address = tree + b"node" + level.to_bytes(1, "big") + index.to_bytes(4, "big")
    return tweak_hash(public_seed, address, pair)


def build_tree(
    public_seed: bytes, tree: bytes, leaves: Sequence[bytes]
) -> tuple[tuple[bytes, ...], ...]:
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
