"""Frozen result dataclasses for :mod:`cybersecuritykit.pqc`."""

from dataclasses import dataclass

__all__: list[str] = []

# --- slice A: lattices and the quantum threat ---
__all__ += [
    "AjtaiKey",
    "GroverResult",
    "KyberCiphertext",
    "KyberEncapsulation",
    "KyberKeyPair",
    "KyberPublicKey",
    "LLLResult",
    "LWEAttackResult",
    "LWECiphertext",
    "LWEKeyPair",
    "LWEPublicKey",
    "LyubashevskyKeyPair",
    "LyubashevskyPublicKey",
    "LyubashevskySignature",
    "NTRUAttackResult",
    "NTRUKeyPair",
    "NTRUPublicKey",
    "RingLWECiphertext",
    "RingLWEKeyPair",
    "RingLWEPublicKey",
    "SISCollision",
    "ShorResult",
    "SignatureLeakage",
]


@dataclass(frozen=True)
class LLLResult:
    """A lattice basis after LLL reduction.

    Attributes
    ----------
    basis : tuple of tuple of int
        The reduced basis, one row per vector; it spans the same lattice as the input.
    swaps : int
        Neighbour swaps made, each one a failure of the Lovász condition.
    norms_before : tuple of float
        Lengths of the Gram-Schmidt vectors of the input basis.
    norms_after : tuple of float
        Lengths of the Gram-Schmidt vectors of the reduced basis; their product,
        the lattice volume, is unchanged.
    """

    basis: tuple[tuple[int, ...], ...]
    swaps: int
    norms_before: tuple[float, ...]
    norms_after: tuple[float, ...]


@dataclass(frozen=True)
class AjtaiKey:
    r"""The public matrix of Ajtai's hash function.

    Attributes
    ----------
    matrix : tuple of tuple of int
        :math:`n` rows of :math:`m` entries in :math:`[0, q)`.
    q : int
        The modulus.
    """

    matrix: tuple[tuple[int, ...], ...]
    q: int


@dataclass(frozen=True)
class SISCollision:
    """Two bit vectors with the same Ajtai hash.

    Attributes
    ----------
    x, y : tuple of int
        The colliding inputs, bits in counting order.
    difference : tuple of int
        ``x - y``, entries in {-1, 0, 1}: a short nonzero vector the matrix sends to zero.
    tested : int
        Inputs hashed until the collision appeared.
    """

    x: tuple[int, ...]
    y: tuple[int, ...]
    difference: tuple[int, ...]
    tested: int


@dataclass(frozen=True)
class NTRUPublicKey:
    r"""An NTRU public key in :math:`\mathbb{Z}_q[x]/(x^N - 1)`.

    Attributes
    ----------
    n : int
        The ring degree :math:`N`.
    p, q : int
        The small and large moduli.
    h : tuple of int
        :math:`h = f_q \star g \bmod q`, constant term first.
    """

    n: int
    p: int
    q: int
    h: tuple[int, ...]


@dataclass(frozen=True)
class NTRUKeyPair:
    """An NTRU private key with its public key.

    Attributes
    ----------
    public : NTRUPublicKey
        The public key.
    f, g : tuple of int
        The small private polynomials.
    f_p : tuple of int
        The inverse of ``f`` mod ``p``, used to finish decryption.
    """

    public: NTRUPublicKey
    f: tuple[int, ...]
    g: tuple[int, ...]
    f_p: tuple[int, ...]


@dataclass(frozen=True)
class NTRUAttackResult:
    """A private key recovered from an NTRU public key by lattice reduction.

    Attributes
    ----------
    keypair : NTRUKeyPair
        A key that decrypts, usually a rotation of :math:`\\pm f`.
    dimension : int
        Dimension :math:`2N` of the reduced lattice.
    swaps : int
        LLL swaps made.
    """

    keypair: NTRUKeyPair
    dimension: int
    swaps: int


@dataclass(frozen=True)
class LWEPublicKey:
    r"""Regev LWE samples :math:`(a_i, b_i = \langle a_i, s \rangle + e_i \bmod q)`.

    Attributes
    ----------
    n : int
        Dimension of the secret.
    q : int
        The modulus.
    a : tuple of tuple of int
        One row :math:`a_i` per sample.
    b : tuple of int
        One noisy inner product per sample.
    """

    n: int
    q: int
    a: tuple[tuple[int, ...], ...]
    b: tuple[int, ...]


@dataclass(frozen=True)
class LWEKeyPair:
    """An LWE secret with its public samples.

    Attributes
    ----------
    public : LWEPublicKey
        The samples.
    secret : tuple of int
        The vector :math:`s`.
    """

    public: LWEPublicKey
    secret: tuple[int, ...]


@dataclass(frozen=True)
class LWECiphertext:
    """One bit encrypted under Regev's scheme.

    Attributes
    ----------
    u : tuple of int
        Sum of the chosen rows :math:`a_i`.
    v : int
        Sum of the chosen :math:`b_i`, plus :math:`\\lfloor q/2 \\rfloor` for a 1.
    """

    u: tuple[int, ...]
    v: int


@dataclass(frozen=True)
class LWEAttackResult:
    """The secret read off LWE samples by Gaussian elimination.

    Attributes
    ----------
    secret : tuple of int
        The solution of the first :math:`n` independent samples.
    consistent : int
        Samples it satisfies exactly: all of them only when there is no error.
    """

    secret: tuple[int, ...]
    consistent: int


@dataclass(frozen=True)
class RingLWEPublicKey:
    r"""A Ring-LWE sample :math:`(a, b = a s + e)` in :math:`\mathbb{Z}_q[x]/(x^n + 1)`.

    Attributes
    ----------
    n : int
        Ring degree, a power of two.
    q : int
        The modulus.
    a : tuple of int
        The uniform polynomial, constant term first.
    b : tuple of int
        :math:`a s + e \bmod q`.
    """

    n: int
    q: int
    a: tuple[int, ...]
    b: tuple[int, ...]


@dataclass(frozen=True)
class RingLWEKeyPair:
    """A small secret polynomial with its Ring-LWE public key.

    Attributes
    ----------
    public : RingLWEPublicKey
        The public sample.
    secret : tuple of int
        The small polynomial :math:`s`.
    """

    public: RingLWEPublicKey
    secret: tuple[int, ...]


@dataclass(frozen=True)
class RingLWECiphertext:
    r"""An LPR ciphertext of :math:`n` bits.

    Attributes
    ----------
    u : tuple of int
        :math:`a r + e_1`.
    v : tuple of int
        :math:`b r + e_2 + \lfloor q/2 \rfloor m`.
    """

    u: tuple[int, ...]
    v: tuple[int, ...]


@dataclass(frozen=True)
class KyberPublicKey:
    r"""A Kyber-like encapsulation key :math:`(t = A s + e, \rho)`.

    Attributes
    ----------
    k : int
        Module rank: :math:`A` is :math:`k \times k` over :math:`R_q`.
    n : int
        Ring degree, a power of two (256 in FIPS 203).
    t : tuple of tuple of int
        The :math:`k` polynomials of :math:`t`.
    rho : bytes
        The 32-byte seed from which :math:`A` is expanded.
    """

    k: int
    n: int
    t: tuple[tuple[int, ...], ...]
    rho: bytes


@dataclass(frozen=True)
class KyberKeyPair:
    """A Kyber-like decapsulation key.

    Attributes
    ----------
    public : KyberPublicKey
        The encapsulation key.
    s : tuple of tuple of int
        The small secret vector.
    z : bytes
        32 secret bytes for implicit rejection.
    """

    public: KyberPublicKey
    s: tuple[tuple[int, ...], ...]
    z: bytes


@dataclass(frozen=True)
class KyberCiphertext:
    r"""A compressed Kyber-like ciphertext.

    Attributes
    ----------
    u : tuple of tuple of int
        :math:`\mathrm{Compress}_{d_u}(A^T r + e_1)`, :math:`k` polynomials.
    v : tuple of int
        :math:`\mathrm{Compress}_{d_v}(t^T r + e_2 + \lceil q/2 \rfloor m)`.
    """

    u: tuple[tuple[int, ...], ...]
    v: tuple[int, ...]


@dataclass(frozen=True)
class KyberEncapsulation:
    """What the sender of a Kyber-like KEM gets.

    Attributes
    ----------
    ciphertext : KyberCiphertext
        Sent to the key holder.
    shared_key : bytes
        The 32-byte shared secret.
    """

    ciphertext: KyberCiphertext
    shared_key: bytes


@dataclass(frozen=True)
class LyubashevskyPublicKey:
    r"""Public key :math:`(a, t = a s_1 + s_2)` of the Fiat-Shamir with aborts signature.

    Attributes
    ----------
    n : int
        Ring degree of :math:`\mathbb{Z}_q[x]/(x^n + 1)`.
    q : int
        The modulus.
    kappa : int
        Number of :math:`\pm 1` coefficients in a challenge.
    bound : int
        Masking coefficients are uniform in :math:`[-B, B]`.
    a : tuple of int
        The uniform polynomial.
    t : tuple of int
        :math:`a s_1 + s_2 \bmod q`.
    """

    n: int
    q: int
    kappa: int
    bound: int
    a: tuple[int, ...]
    t: tuple[int, ...]


@dataclass(frozen=True)
class LyubashevskyKeyPair:
    """Ternary secrets :math:`(s_1, s_2)` with their public key.

    Attributes
    ----------
    public : LyubashevskyPublicKey
        The public key.
    s1 : tuple of int
        Secret polynomial multiplied by :math:`a`.
    s2 : tuple of int
        Secret polynomial added as error.
    """

    public: LyubashevskyPublicKey
    s1: tuple[int, ...]
    s2: tuple[int, ...]


@dataclass(frozen=True)
class LyubashevskySignature:
    """A signature :math:`(z_1, z_2, c)` and how many tries it took.

    Attributes
    ----------
    z1 : tuple of int
        :math:`y_1 + c s_1`, centered.
    z2 : tuple of int
        :math:`y_2 + c s_2`, centered.
    c : tuple of int
        The challenge polynomial.
    attempts : int
        Masks drawn before one passed the rejection step.
    """

    z1: tuple[int, ...]
    z2: tuple[int, ...]
    c: tuple[int, ...]
    attempts: int


@dataclass(frozen=True)
class SignatureLeakage:
    """An estimate of :math:`s_1` averaged from signatures.

    Attributes
    ----------
    estimate : tuple of float
        Mean of :math:`c^* z_1 / \\kappa` over the signatures.
    secret_guess : tuple of int
        The estimate rounded to :math:`\\{-1, 0, 1\\}`.
    signatures : int
        How many signatures were averaged.
    """

    estimate: tuple[float, ...]
    secret_guess: tuple[int, ...]
    signatures: int


@dataclass(frozen=True)
class ShorResult:
    """One run of Shor's algorithm on a simulated state vector.

    Attributes
    ----------
    n : int
        The number to factor.
    base : int
        The base :math:`a`, coprime to :math:`n`.
    qubits : int
        Qubits of the first register, :math:`Q = 2^{\\text{qubits}}` outcomes.
    period : int or None
        The order :math:`r` of :math:`a` mod :math:`n`, or None if the shots missed it.
    factors : tuple of int or None
        :math:`(p, q)` with :math:`p q = n`, or None when :math:`r` is odd,
        :math:`a^{r/2} \\equiv -1`, or the period was missed.
    measurements : tuple of int
        Outcomes :math:`y` read from the first register.
    distribution : tuple of float
        Probability of each outcome.
    """

    n: int
    base: int
    qubits: int
    period: int | None
    factors: tuple[int, int] | None
    measurements: tuple[int, ...]
    distribution: tuple[float, ...]


@dataclass(frozen=True)
class GroverResult:
    """One run of Grover's search on a simulated state vector.

    Attributes
    ----------
    qubits : int
        Register size: the search space has :math:`2^{\\text{qubits}}` items.
    marked : tuple of int
        The items the oracle flags.
    iterations : int
        Grover iterations applied.
    success : tuple of float
        Probability of measuring a marked item after 0, 1, ..., ``iterations`` steps.
    measured : int
        The item finally measured.
    found : bool
        Whether it is marked.
    """

    qubits: int
    marked: tuple[int, ...]
    iterations: int
    success: tuple[float, ...]
    measured: int
    found: bool


# --- end slice A ---
