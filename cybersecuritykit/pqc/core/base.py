"""Frozen result dataclasses for :mod:`cybersecuritykit.pqc`."""

from dataclasses import dataclass

__all__: list[str] = [
    # --- slice C ---
    "HORSTForgery",
    "HORSTKey",
    "HORSTPublicKey",
    "HORSTSignature",
    "SPHINCSKey",
    "SPHINCSPublicKey",
    "SPHINCSSignature",
    "WinternitzCost",
    "WinternitzForgery",
    "WinternitzKey",
    "WinternitzPublicKey",
    "WinternitzSignature",
    "XMSSForgery",
    "XMSSKey",
    "XMSSPublicKey",
    "XMSSSignature",
    "XMSSSigned",
    # --- end slice C ---
]


# --- slice C ---
@dataclass(frozen=True)
class WinternitzPublicKey:
    """The public half of a Winternitz one-time key.

    Attributes
    ----------
    chains : tuple of bytes
        The end of each hash chain, one per message and checksum digit.
    public_seed : bytes
        Seed of the tweakable hash; its length is the hash length :math:`n`.
    address : bytes
        Where the key sits in a larger scheme (a leaf of a tree); empty for a lone key.
    w : int
        The Winternitz parameter: each chain has :math:`w - 1` steps.
    """

    chains: tuple[bytes, ...]
    public_seed: bytes
    address: bytes
    w: int


@dataclass(frozen=True)
class WinternitzKey:
    """A Winternitz one-time key pair: sign one message with it, never two.

    Attributes
    ----------
    secret : tuple of bytes
        The start of each hash chain.
    public : WinternitzPublicKey
        The chain ends, published.
    """

    secret: tuple[bytes, ...]
    public: WinternitzPublicKey


@dataclass(frozen=True)
class WinternitzSignature:
    """A Winternitz signature: for each digit :math:`d`, the value :math:`d` steps along.

    Attributes
    ----------
    chains : tuple of bytes
        One intermediate chain value per message and checksum digit.
    """

    chains: tuple[bytes, ...]


@dataclass(frozen=True)
class WinternitzForgery:
    """Outcome of a forger who has seen several signatures from one Winternitz key.

    Attributes
    ----------
    message : bytes or None
        A new message the forger can sign, or ``None`` if the search failed.
    signature : WinternitzSignature or None
        A valid signature on ``message``, built only from the signatures seen.
    tested : int
        Candidate messages tested.
    """

    message: bytes | None
    signature: WinternitzSignature | None
    tested: int


@dataclass(frozen=True)
class WinternitzCost:
    """Size and work of a Winternitz key for one choice of :math:`w`.

    Attributes
    ----------
    w : int
        The Winternitz parameter.
    chains : int
        Message digits plus checksum digits.
    signature_bytes : int
        Bytes in a signature: one :math:`n`-byte value per chain.
    keygen_hashes : int
        Hash calls to make the public key, :math:`(w - 1)` per chain; signing and
        verifying together cost the same.
    """

    w: int
    chains: int
    signature_bytes: int
    keygen_hashes: int


@dataclass(frozen=True)
class XMSSPublicKey:
    """The public key of a Merkle tree of Winternitz keys: its root.

    Attributes
    ----------
    root : bytes
        Root of the tree over the :math:`2^h` one-time public keys.
    public_seed : bytes
        Seed of the tweakable hash; its length is the hash length :math:`n`.
    height : int
        Tree height :math:`h`.
    w : int
        The Winternitz parameter of the leaves.
    """

    root: bytes
    public_seed: bytes
    height: int
    w: int


@dataclass(frozen=True)
class XMSSKey:
    """A stateful XMSS key: the secret seed and the index of the next unused leaf.

    Attributes
    ----------
    secret_seed : bytes
        Every one-time secret is derived from it and a leaf address.
    public : XMSSPublicKey
        The published key.
    next_index : int
        The leaf the next signature uses; after :math:`2^h` signatures the key is spent.
    """

    secret_seed: bytes
    public: XMSSPublicKey
    next_index: int


@dataclass(frozen=True)
class XMSSSignature:
    """One leaf's Winternitz signature and the path that ties its key to the root.

    Attributes
    ----------
    index : int
        The leaf that signed.
    wots : WinternitzSignature
        The one-time signature.
    auth_path : tuple of bytes
        The sibling of each node from the leaf to the root, bottom first.
    """

    index: int
    wots: WinternitzSignature
    auth_path: tuple[bytes, ...]


@dataclass(frozen=True)
class XMSSSigned:
    """A signature and the updated key, which the signer must keep in place of the old one.

    Attributes
    ----------
    signature : XMSSSignature
        The signature.
    key : XMSSKey
        The key with ``next_index`` advanced by one.
    """

    signature: XMSSSignature
    key: XMSSKey


@dataclass(frozen=True)
class XMSSForgery:
    """Outcome of a forger who has seen XMSS signatures, some reusing a leaf.

    Attributes
    ----------
    message : bytes or None
        A new message the forger can sign, or ``None`` if the search failed.
    signature : XMSSSignature or None
        A signature on ``message`` that verifies under the victim's public key.
    tested : int
        Candidate messages tested.
    """

    message: bytes | None
    signature: XMSSSignature | None
    tested: int


@dataclass(frozen=True)
class HORSTPublicKey:
    """The public key of a HORST few-time key: a Merkle root over :math:`t = 2^a` secrets.

    Attributes
    ----------
    root : bytes
        Root of the tree over the hashed secrets.
    public_seed : bytes
        Seed of the tweakable hash; its length is the hash length :math:`n`.
    address : bytes
        Where the key sits in a hypertree; empty for a lone key.
    k : int
        Secrets revealed per signature.
    a : int
        Bits per index, so the tree has :math:`2^a` leaves.
    """

    root: bytes
    public_seed: bytes
    address: bytes
    k: int
    a: int


@dataclass(frozen=True)
class HORSTKey:
    """A HORST few-time key pair.

    Attributes
    ----------
    secret_seed : bytes
        Every secret is derived from it and its leaf index.
    public : HORSTPublicKey
        The published key.
    """

    secret_seed: bytes
    public: HORSTPublicKey


@dataclass(frozen=True)
class HORSTSignature:
    """A HORST signature: :math:`k` revealed secrets with their authentication paths.

    Attributes
    ----------
    secrets : tuple of bytes
        The secret at each index the message selects, in the order selected.
    auth_paths : tuple of tuple of bytes
        For each secret, the siblings from its leaf to the root.
    """

    secrets: tuple[bytes, ...]
    auth_paths: tuple[tuple[bytes, ...], ...]


@dataclass(frozen=True)
class HORSTForgery:
    """Outcome of a forger who has seen several signatures from one HORST key.

    Attributes
    ----------
    message : bytes or None
        A new message whose indices are all among the revealed ones, or ``None``.
    signature : HORSTSignature or None
        A valid signature on ``message``.
    tested : int
        Candidate messages tested.
    """

    message: bytes | None
    signature: HORSTSignature | None
    tested: int


@dataclass(frozen=True)
class SPHINCSPublicKey:
    """The public key of a SPHINCS-style hypertree: the root of its top tree.

    Attributes
    ----------
    root : bytes
        Root of the single tree on the top layer.
    public_seed : bytes
        Seed of the tweakable hash; its length is the hash length :math:`n`.
    layers : int
        Layers :math:`d` of Merkle trees.
    height : int
        Height of each tree, so the hypertree has :math:`2^{d h}` HORST keys at the bottom.
    w : int
        The Winternitz parameter of the tree leaves.
    k, a : int
        Parameters of the HORST keys at the bottom.
    """

    root: bytes
    public_seed: bytes
    layers: int
    height: int
    w: int
    k: int
    a: int


@dataclass(frozen=True)
class SPHINCSKey:
    """A stateless SPHINCS-style key: two secret seeds and nothing that changes.

    Attributes
    ----------
    secret_seed : bytes
        Every one-time and few-time secret is derived from it and an address.
    prf_key : bytes
        Derives the per-message randomizer, and through it the HORST key used.
    public : SPHINCSPublicKey
        The published key.
    """

    secret_seed: bytes
    prf_key: bytes
    public: SPHINCSPublicKey


@dataclass(frozen=True)
class SPHINCSSignature:
    """A HORST signature on the message and a chain of tree signatures up to the root.

    Attributes
    ----------
    randomizer : bytes
        Mixed into the message hash; it fixes which HORST key signs.
    index : int
        The HORST key used, numbered across the whole bottom layer.
    horst : HORSTSignature
        The few-time signature on the message.
    layers : tuple of XMSSSignature
        For each layer from the bottom, a leaf's signature on the root below it.
    """

    randomizer: bytes
    index: int
    horst: HORSTSignature
    layers: tuple[XMSSSignature, ...]


# --- end slice C ---
