r"""XMSS: a Merkle tree of Winternitz keys, signed with in order (Buchmann et al., 2011).

J. Buchmann, E. Dahmen and A. Hülsing, "XMSS -- a practical forward secure
signature scheme based on minimal security assumptions", *PQCrypto 2011*,
LNCS 7071, pp. 117-129; standardized as RFC 8391 (2018). Merkle's 1979 tree
turns :math:`2^h` one-time keys into one public key, the root. A signature is
one leaf's Winternitz signature with the :math:`h` sibling hashes that lead
from that leaf to the root. The signer must remember which leaves it has used:
the scheme is *stateful*, and restoring an old state reuses a one-time key.

The teaching version hashes each Winternitz public key into its leaf in one
call where XMSS uses an L-tree, keys every hash by an address as XMSS-T and
SPHINCS+ do instead of XOR bitmasks, and rebuilds the tree for each signature
instead of using a tree-traversal algorithm.
"""

import random
from collections.abc import Sequence
from functools import lru_cache

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    WinternitzPublicKey,
    XMSSForgery,
    XMSSKey,
    XMSSPublicKey,
    XMSSSignature,
    XMSSSigned,
)
from cybersecuritykit.pqc.systems.winternitz import (
    _check_hash_length,
    _check_width,
    _forge_chains,
    _wots_key,
    _wots_public,
    _wots_sign,
    winternitz_digest,
)
from cybersecuritykit.pqc.utils.hash_trees import (
    auth_path,
    build_tree,
    root_from_path,
    tweak_hash,
)

__all__ = ["xmss_forge", "xmss_keygen", "xmss_sign", "xmss_verify"]

MAX_HEIGHT = 10
"""Tallest tree allowed: :math:`2^{10}` leaves keep key generation to seconds."""


def _check_height(height: int) -> None:
    _validation.integer(height, "height", 1)
    if height > MAX_HEIGHT:
        raise ValueError(f"height must be at most {MAX_HEIGHT}")


def _leaf_address(tree: bytes, index: int) -> bytes:
    return tree + b"leaf" + index.to_bytes(4, "big")


def _leaf(public: WinternitzPublicKey) -> bytes:
    """Compress a Winternitz public key into one tree leaf."""
    return tweak_hash(public.public_seed, public.address + b"pk", b"".join(public.chains))


def _message_digest(public_seed: bytes, tree: bytes, index: int, message: bytes) -> bytes:
    """The value leaf ``index`` signs for ``message``, as its Winternitz key would hash it."""
    address = _leaf_address(tree, index)
    return winternitz_digest(WinternitzPublicKey((), public_seed, address, 0), message)


@lru_cache(maxsize=64)
def _tree(
    secret_seed: bytes, public_seed: bytes, tree: bytes, height: int, w: int
) -> tuple[tuple[bytes, ...], ...]:
    """Every level of the tree of one-time keys at address ``tree``."""
    leaves = [
        _leaf(_wots_key(secret_seed, public_seed, _leaf_address(tree, i), w).public)
        for i in range(2**height)
    ]
    return build_tree(public_seed, tree, leaves)


def _tree_sign(
    secret_seed: bytes,
    public_seed: bytes,
    tree: bytes,
    height: int,
    w: int,
    index: int,
    digest: bytes,
) -> XMSSSignature:
    """Sign ``digest`` with leaf ``index`` of a tree and attach its authentication path."""
    key = _wots_key(secret_seed, public_seed, _leaf_address(tree, index), w)
    path = auth_path(_tree(secret_seed, public_seed, tree, height, w), index)
    return XMSSSignature(index, _wots_sign(key, digest), path)


def _tree_root(
    public_seed: bytes, tree: bytes, height: int, w: int, digest: bytes, signature: XMSSSignature
) -> bytes | None:
    """The root a signature leads to; ``None`` if it is malformed."""
    public = _wots_public(public_seed, _leaf_address(tree, signature.index), w, digest,
                          signature.wots)  # fmt: skip
    if public is None:
        return None
    return root_from_path(public_seed, tree, _leaf(public), signature.index, signature.auth_path)


def _well_placed(signature: XMSSSignature, height: int) -> bool:
    return 0 <= signature.index < 2**height and len(signature.auth_path) == height


def xmss_keygen(seed: int = DEFAULT_SEED, *, height: int = 4, n: int = 16, w: int = 16) -> XMSSKey:
    r"""Make an XMSS key: :math:`2^h` Winternitz keys under one Merkle root.

    Each leaf hashes one Winternitz public key; each inner node hashes its two
    children, with an address naming its level :math:`j` and position :math:`i`:

    .. math::

       \mathrm{node}_{j,i} = H\bigl(\mathrm{seed}, (j, i),\,
       \mathrm{node}_{j-1,2i} \,\|\, \mathrm{node}_{j-1,2i+1}\bigr).

    Parameters
    ----------
    seed : int, optional
        Seeds the secret and public seeds; the same seed gives the same key.
    height : int, optional
        Tree height :math:`h`, from 1 to 10: the key signs :math:`2^h` messages.
    n : int, optional
        Hash length in bytes, from 2 to 32.
    w : int, optional
        The Winternitz parameter of the leaves.

    Returns
    -------
    XMSSKey
        With ``next_index`` 0.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.xmss_keygen(1, height=2)
    >>> key.next_index, len(key.public.root)
    (0, 16)
    """
    _validation.seed(seed)
    _check_height(height)
    _check_hash_length(n)
    _check_width(w)
    rng = random.Random(seed)
    secret_seed, public_seed = rng.randbytes(n), rng.randbytes(n)
    root = _tree(secret_seed, public_seed, b"", height, w)[-1][0]
    return XMSSKey(secret_seed, XMSSPublicKey(root, public_seed, height, w), 0)


def xmss_sign(key: XMSSKey, message: bytes) -> XMSSSigned:
    """Sign with the next unused leaf and return the signature and the advanced key.

    The old key must be discarded: signing with it again reuses a one-time
    key, which :func:`~cybersecuritykit.pqc.systems.xmss.xmss_forge` exploits.

    Raises
    ------
    ValueError
        Every leaf has been used.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.xmss_keygen(1, height=2)
    >>> signed = pqc.xmss_sign(key, b"hello")
    >>> signed.signature.index, signed.key.next_index
    (0, 1)
    """
    _validation.byte_string(message, "message")
    public = key.public
    index = key.next_index
    if index >= 2**public.height:
        raise ValueError("the key is spent: every one-time leaf has signed")
    seed = public.public_seed
    digest = _message_digest(seed, b"", index, message)
    signature = _tree_sign(key.secret_seed, seed, b"", public.height, public.w, index, digest)
    return XMSSSigned(signature, XMSSKey(key.secret_seed, public, index + 1))


def xmss_verify(public: XMSSPublicKey, message: bytes, signature: XMSSSignature) -> bool:
    """Check a signature: rebuild the leaf's key, hash up the path, compare with the root.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.xmss_keygen(1, height=2)
    >>> signature = pqc.xmss_sign(key, b"hello").signature
    >>> pqc.xmss_verify(key.public, b"hello", signature)
    True
    """
    _validation.byte_string(message, "message")
    if not _well_placed(signature, public.height):
        return False
    seed = public.public_seed
    digest = _message_digest(seed, b"", signature.index, message)
    return _tree_root(seed, b"", public.height, public.w, digest, signature) == public.root


def xmss_forge(
    public: XMSSPublicKey,
    observed: Sequence[tuple[bytes, XMSSSignature]],
    *,
    max_tries: int = 100_000,
) -> XMSSForgery:
    """Forge an XMSS signature from signatures that reused a leaf.

    The forger picks the leaf seen most often, recovers its Winternitz public
    key from a signature, runs
    :func:`~cybersecuritykit.pqc.systems.winternitz.winternitz_forge` against
    it, and reuses that leaf's authentication path. If no leaf was used twice
    the search fails, as it would against an honest signer.

    Parameters
    ----------
    public : XMSSPublicKey
        The victim's public key.
    observed : sequence of tuple
        ``(message, signature)`` pairs; at least one, all valid.
    max_tries : int, optional
        Candidate messages to try before giving up.

    Returns
    -------
    XMSSForgery

    Raises
    ------
    ValueError
        ``observed`` is empty or holds a signature that does not verify.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.xmss_keygen(9, height=2, n=8)
    >>> reused = [(m, pqc.xmss_sign(key, m).signature) for m in (b"a", b"b", b"c", b"d")]
    >>> forgery = pqc.xmss_forge(key.public, reused)
    >>> pqc.xmss_verify(key.public, forgery.message, forgery.signature)
    True
    """
    _validation.integer(max_tries, "max_tries", 1)
    if not observed:
        raise ValueError("observed must hold at least one signed message")
    by_leaf: dict[int, list[tuple[bytes, XMSSSignature]]] = {}
    for message, signature in observed:
        if not xmss_verify(public, message, signature):
            raise ValueError("every observed signature must verify under the public key")
        by_leaf.setdefault(signature.index, []).append((message, signature))
    index = max(sorted(by_leaf), key=lambda i: len(by_leaf[i]))
    seen = by_leaf[index]
    seed = public.public_seed
    first_message, first = seen[0]
    digest = _message_digest(seed, b"", index, first_message)
    leaf_key = _wots_public(seed, _leaf_address(b"", index), public.w, digest, first.wots)
    assert leaf_key is not None  # first verified above
    result = _forge_chains(leaf_key, [(m, s.wots) for m, s in seen], max_tries)
    if result.signature is None:
        return XMSSForgery(None, None, result.tested)
    signature = XMSSSignature(index, result.signature, first.auth_path)
    return XMSSForgery(result.message, signature, result.tested)
