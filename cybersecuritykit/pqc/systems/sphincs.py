r"""SPHINCS: stateless hash-based signatures from a hypertree and a few-time scheme (2015).

D. J. Bernstein, D. Hopwood, A. Hülsing, T. Lange, R. Niederhagen,
L. Papachristodoulou, M. Schneider, P. Schwabe and Z. Wilcox-O'Hearn,
"SPHINCS: practical stateless hash-based signatures", *EUROCRYPT 2015*,
LNCS 9056, pp. 368-397. Its successor SPHINCS+ is standardized as SLH-DSA in
FIPS 205 (2024). The few-time scheme is HORST, HORS with a tree, after
L. Reyzin and N. Reyzin, "Better than BiBa: short one-time signatures with
fast signing and verifying", *ACISP 2002*, LNCS 2384, pp. 144-153.

XMSS must remember which leaf it used. SPHINCS removes that state: the hash
of the message picks one of :math:`2^{dh}` HORST keys at random, and a
hypertree of :math:`d` layers of XMSS-style trees certifies it, each tree's
root signed by a Winternitz leaf of the tree above. Two messages may land on
the same HORST key; a few-time scheme tolerates that, its security falling
slowly with each reuse.

The teaching version derives every tree on demand from the seeds, uses
SHA-256 and SHAKE-256 truncated to :math:`n` bytes with toy parameters, signs
the HORST root directly instead of through the HORST-to-tree compression of
SPHINCS, and omits the FORS and tree-hash refinements of SPHINCS+.
"""

import hashlib
import math
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    HORSTForgery,
    HORSTKey,
    HORSTPublicKey,
    HORSTSignature,
    SPHINCSKey,
    SPHINCSPublicKey,
    SPHINCSSignature,
    XMSSSignature,
)
from cybersecuritykit.pqc.utils import hash_trees
from cybersecuritykit.pqc.utils.hash_trees import (
    auth_path,
    build_tree,
    derive,
    root_from_path,
    tweak_hash,
)

__all__ = [
    "few_time_security",
    "horst_forge",
    "horst_indices",
    "horst_keygen",
    "horst_sign",
    "horst_verify",
    "sphincs_keygen",
    "sphincs_sign",
    "sphincs_verify",
]

MAX_HORST_BITS = 12
"""Largest :math:`a` allowed: :math:`2^{12}` HORST leaves keep key generation quick."""

MAX_LAYERS = 4
"""Most hypertree layers allowed."""


def _check_horst(k: int, a: int) -> None:
    _validation.integer(k, "k", 1)
    _validation.integer(a, "a", 1)
    if a > MAX_HORST_BITS:
        raise ValueError(f"a must be at most {MAX_HORST_BITS}")


def _horst_leaf_address(address: bytes, index: int) -> bytes:
    return address + b"horst" + index.to_bytes(4, "big")


def _horst_tree(
    secret_seed: bytes, public_seed: bytes, address: bytes, a: int
) -> tuple[tuple[bytes, ...], ...]:
    """Every level of the tree over the hashed HORST secrets at ``address``."""
    leaves = []
    for i in range(2**a):
        leaf_address = _horst_leaf_address(address, i)
        leaves.append(tweak_hash(public_seed, leaf_address, derive(secret_seed, leaf_address)))
    return build_tree(public_seed, address + b"horst", leaves)


def _horst_key(secret_seed: bytes, public_seed: bytes, address: bytes, k: int, a: int) -> HORSTKey:
    root = _horst_tree(secret_seed, public_seed, address, a)[-1][0]
    return HORSTKey(secret_seed, HORSTPublicKey(root, public_seed, address, k, a))


def horst_keygen(seed: int = DEFAULT_SEED, *, k: int = 8, a: int = 6, n: int = 16) -> HORSTKey:
    r"""Make a HORST few-time key: :math:`t = 2^a` secrets under one Merkle root.

    Parameters
    ----------
    seed : int, optional
        Seeds the secret and public seeds; the same seed gives the same key.
    k : int, optional
        Secrets revealed per signature.
    a : int, optional
        Bits per index, from 1 to 12; the key holds :math:`2^a` secrets.
    n : int, optional
        Hash length in bytes, from 2 to 32.

    Returns
    -------
    HORSTKey

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.horst_keygen(1, k=4, a=4)
    >>> len(key.public.root), key.public.k, key.public.a
    (16, 4, 4)
    """
    _validation.seed(seed)
    _check_horst(k, a)
    hash_trees.check_hash_length(n)
    rng = random.Random(seed)
    secret_seed, public_seed = rng.randbytes(n), rng.randbytes(n)
    return _horst_key(secret_seed, public_seed, b"", k, a)


def horst_indices(public: HORSTPublicKey, message: bytes) -> tuple[int, ...]:
    r"""The :math:`k` leaves a message selects: its hash cut into :math:`a`-bit numbers.

    .. math::

       H(m) = i_1 \,\|\, i_2 \,\|\, \cdots \,\|\, i_k, \qquad 0 \le i_j < 2^a.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.horst_keygen(1, k=4, a=4)
    >>> len(pqc.horst_indices(key.public, b"hello"))
    4
    """
    _validation.byte_string(message, "message")
    k, a = public.k, public.a
    data = public.public_seed + public.address + b"indices" + message
    value = int.from_bytes(hashlib.shake_256(data).digest(math.ceil(k * a / 8)), "big")
    return tuple((value >> (a * (k - 1 - j))) & (2**a - 1) for j in range(k))


def horst_sign(key: HORSTKey, message: bytes) -> HORSTSignature:
    """Reveal the secret at each selected leaf with its authentication path.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.horst_keygen(1, k=4, a=4)
    >>> len(pqc.horst_sign(key, b"hello").secrets)
    4
    """
    public = key.public
    indices = horst_indices(public, message)
    levels = _horst_tree(key.secret_seed, public.public_seed, public.address, public.a)
    secrets = tuple(
        derive(key.secret_seed, _horst_leaf_address(public.address, i)) for i in indices
    )
    return HORSTSignature(secrets, tuple(auth_path(levels, i) for i in indices))


def _horst_root(public: HORSTPublicKey, message: bytes, signature: HORSTSignature) -> bytes | None:
    """The one root every revealed secret leads to; ``None`` if they disagree or are malformed."""
    indices = horst_indices(public, message)
    if len(signature.secrets) != public.k or len(signature.auth_paths) != public.k:
        return None
    seed, address = public.public_seed, public.address
    roots = set()
    for i, secret, path in zip(indices, signature.secrets, signature.auth_paths, strict=True):
        if len(path) != public.a:
            return None
        leaf = tweak_hash(seed, _horst_leaf_address(address, i), secret)
        roots.add(root_from_path(seed, address + b"horst", leaf, i, path))
    return roots.pop() if len(roots) == 1 else None


def horst_verify(public: HORSTPublicKey, message: bytes, signature: HORSTSignature) -> bool:
    """Check that every revealed secret hashes up its path to the root.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.horst_keygen(1, k=4, a=4)
    >>> pqc.horst_verify(key.public, b"hello", pqc.horst_sign(key, b"hello"))
    True
    """
    return _horst_root(public, message, signature) == public.root


def horst_forge(
    public: HORSTPublicKey,
    observed: Sequence[tuple[bytes, HORSTSignature]],
    *,
    max_tries: int = 100_000,
) -> HORSTForgery:
    """Forge a HORST signature from the secrets that earlier signatures revealed.

    Each signature reveals :math:`k` of the :math:`2^a` secrets with their
    paths. The forger searches for a new message whose every index is among
    those already revealed.

    Parameters
    ----------
    public : HORSTPublicKey
        The victim's public key.
    observed : sequence of tuple
        ``(message, signature)`` pairs; at least one, all valid.
    max_tries : int, optional
        Candidate messages to try before giving up.

    Returns
    -------
    HORSTForgery

    Raises
    ------
    ValueError
        ``observed`` is empty or holds a signature that does not verify.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.horst_keygen(1, k=2, a=3, n=8)
    >>> seen = [(m, pqc.horst_sign(key, m)) for m in (b"a", b"b", b"c", b"d")]
    >>> forgery = pqc.horst_forge(key.public, seen)
    >>> pqc.horst_verify(key.public, forgery.message, forgery.signature)
    True
    """
    _validation.integer(max_tries, "max_tries", 1)
    if not observed:
        raise ValueError("observed must hold at least one signed message")
    revealed: dict[int, tuple[bytes, tuple[bytes, ...]]] = {}
    for message, signature in observed:
        if not horst_verify(public, message, signature):
            raise ValueError("every observed signature must verify under the public key")
        pairs = zip(signature.secrets, signature.auth_paths, strict=True)
        revealed.update(zip(horst_indices(public, message), pairs, strict=True))
    signed = {message for message, _ in observed}
    for tested in range(1, max_tries + 1):
        candidate = b"forgery %d" % (tested - 1)
        indices = horst_indices(public, candidate)
        if candidate in signed or any(i not in revealed for i in indices):
            continue
        secrets = tuple(revealed[i][0] for i in indices)
        paths = tuple(revealed[i][1] for i in indices)
        return HORSTForgery(candidate, HORSTSignature(secrets, paths), tested)
    return HORSTForgery(None, None, max_tries)


def few_time_security(k: int, a: int, signatures: int) -> float:
    r"""Bits of security left against a random-message forgery after ``signatures`` uses.

    After :math:`r` signatures each leaf has been revealed with probability
    :math:`1 - (1 - 1/t)^{rk}`, :math:`t = 2^a`; a new message needs all
    :math:`k` of its leaves revealed:

    .. math::

       \text{bits} = -k \log_2\!\left(1 - \left(1 - 2^{-a}\right)^{rk}\right).

    Parameters
    ----------
    k, a : int
        HORST parameters.
    signatures : int
        Signatures :math:`r \ge 1` made with the key.

    Returns
    -------
    float

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.few_time_security(1, 1, 1)
    1.0
    """
    _validation.integer(k, "k", 1)
    _validation.integer(a, "a", 1)
    _validation.integer(signatures, "signatures", 1)
    revealed = -math.expm1(signatures * k * math.log1p(-(2.0**-a)))
    return -k * math.log2(revealed)


def _tree_address(layer: int, tree: int) -> bytes:
    return b"layer" + layer.to_bytes(1, "big") + tree.to_bytes(8, "big")


def _horst_address(index: int) -> bytes:
    return b"few" + index.to_bytes(8, "big")


def _randomizer(key: SPHINCSKey, message: bytes) -> bytes:
    n = len(key.prf_key)
    return hashlib.sha256(b"randomizer" + key.prf_key + message).digest()[:n]


def _select(public: SPHINCSPublicKey, randomizer: bytes, message: bytes) -> int:
    """The HORST key a message lands on, from its randomized hash."""
    data = randomizer + public.public_seed + public.root + message
    value = int.from_bytes(hashlib.shake_256(data).digest(8), "big")
    return value % (1 << (public.layers * public.height))


def sphincs_keygen(
    seed: int = DEFAULT_SEED,
    *,
    layers: int = 2,
    height: int = 3,
    k: int = 8,
    a: int = 6,
    n: int = 16,
    w: int = 16,
) -> SPHINCSKey:
    r"""Make a SPHINCS-style key: a hypertree of :math:`d` layers over :math:`2^{dh}` HORST keys.

    The public key is the root of the single tree on the top layer. Every other
    tree and every HORST key is derived from the secret seed when it is needed.

    Parameters
    ----------
    seed : int, optional
        Seeds the secret seed, the randomizer key and the public seed.
    layers : int, optional
        Hypertree layers :math:`d`, from 1 to 4.
    height : int, optional
        Height :math:`h` of each tree, from 1 to 10.
    k, a : int, optional
        Parameters of the HORST keys at the bottom.
    n : int, optional
        Hash length in bytes, from 2 to 32.
    w : int, optional
        The Winternitz parameter of the tree leaves.

    Returns
    -------
    SPHINCSKey

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.sphincs_keygen(1, layers=2, height=2, k=4, a=4)
    >>> key.public.layers * key.public.height
    4
    """
    _validation.seed(seed)
    _validation.integer(layers, "layers", 1)
    if layers > MAX_LAYERS:
        raise ValueError(f"layers must be at most {MAX_LAYERS}")
    hash_trees.check_height(height)
    _check_horst(k, a)
    hash_trees.check_hash_length(n)
    hash_trees.check_width(w)
    rng = random.Random(seed)
    secret_seed, prf_key, public_seed = rng.randbytes(n), rng.randbytes(n), rng.randbytes(n)
    top = _tree_address(layers - 1, 0)
    root = hash_trees.tree_levels(secret_seed, public_seed, top, height, w)[-1][0]
    public = SPHINCSPublicKey(root, public_seed, layers, height, w, k, a)
    return SPHINCSKey(secret_seed, prf_key, public)


def sphincs_sign(key: SPHINCSKey, message: bytes) -> SPHINCSSignature:
    """Sign with no state: the message picks a HORST key, the hypertree certifies it.

    The randomizer is a keyed hash of the message, so signing the same message
    twice gives the same signature and nothing has to be remembered.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.sphincs_keygen(1, layers=2, height=2, k=4, a=4)
    >>> len(pqc.sphincs_sign(key, b"hello").layers)
    2
    """
    _validation.byte_string(message, "message")
    public = key.public
    seed, h = public.public_seed, public.height
    randomizer = _randomizer(key, message)
    index = _select(public, randomizer, message)
    horst_key = _horst_key(key.secret_seed, seed, _horst_address(index), public.k, public.a)
    horst = horst_sign(horst_key, message)
    signed, position = horst_key.public.root, index
    layers: list[XMSSSignature] = []
    for layer in range(public.layers):
        tree, leaf = _tree_address(layer, position >> h), position % 2**h
        levels = hash_trees.tree_levels(key.secret_seed, seed, tree, h, public.w)
        digest = hash_trees.leaf_digest(seed, tree, leaf, signed)
        layers.append(
            hash_trees.tree_sign(key.secret_seed, seed, tree, levels, public.w, leaf, digest)
        )
        signed, position = levels[-1][0], position >> h
    return SPHINCSSignature(randomizer, index, horst, tuple(layers))


def sphincs_verify(public: SPHINCSPublicKey, message: bytes, signature: SPHINCSSignature) -> bool:
    """Check a signature: HORST root first, then each tree up to the public root.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.sphincs_keygen(1, layers=2, height=2, k=4, a=4)
    >>> pqc.sphincs_verify(key.public, b"hello", pqc.sphincs_sign(key, b"hello"))
    True
    """
    _validation.byte_string(message, "message")
    index = _select(public, signature.randomizer, message)
    if signature.index != index or len(signature.layers) != public.layers:
        return False
    seed, h = public.public_seed, public.height
    horst_public = HORSTPublicKey(public.root, seed, _horst_address(index), public.k, public.a)
    signed = _horst_root(horst_public, message, signature.horst)
    position = index
    for layer, tree_signature in enumerate(signature.layers):
        tree, leaf = _tree_address(layer, position >> h), position % 2**h
        if signed is None or tree_signature.index != leaf or len(tree_signature.auth_path) != h:
            return False
        digest = hash_trees.leaf_digest(seed, tree, leaf, signed)
        signed = hash_trees.tree_root(seed, tree, public.w, digest, tree_signature)
        position >>= h
    return signed == public.root
