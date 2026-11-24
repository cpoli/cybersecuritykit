"""Frozen result dataclasses for :mod:`cybersecuritykit.pqc`."""

from collections.abc import Sequence
from dataclasses import dataclass

__all__: list[str] = [
    # --- slice A ---
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
    # --- end slice A ---
    # --- slice B: codes and multivariate ---
    "GoppaCode",
    "ISDResult",
    "LinearizationResult",
    "MatsumotoImaiKeyPair",
    "MatsumotoImaiPrivateKey",
    "McElieceBreakResult",
    "McElieceKeyPair",
    "McEliecePrivateKey",
    "McEliecePublicKey",
    "NiederreiterKeyPair",
    "NiederreiterPrivateKey",
    "NiederreiterPublicKey",
    "OilVinegarKeyPair",
    "OilVinegarPrivateKey",
    "QuadraticMap",
    "RainbowBreakResult",
    # --- end slice B ---
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


# --- slice A ---
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
# --- slice B: codes and multivariate ---
Bits = tuple[int, ...]
BitMatrix = tuple[Bits, ...]


@dataclass(frozen=True)
class ISDResult:
    """An error vector found by information-set decoding.

    Attributes
    ----------
    error : tuple of int
        The error, ``n`` bits, of weight at most ``t``.
    iterations : int
        Column sets tried, the successful one included.
    columns : tuple of int
        The ``n - k`` positions, sorted, that held every error.
    """

    error: Bits
    iterations: int
    columns: tuple[int, ...]


@dataclass(frozen=True)
class GoppaCode:
    """A binary Goppa code ``Gamma(L, g)`` with its generator and parity-check matrices.

    Attributes
    ----------
    m : int
        The code lives over GF(2) but its support is in GF(2^m).
    t : int
        Degree of the Goppa polynomial and number of errors the code corrects.
    field_modulus : int
        The primitive polynomial that defines GF(2^m), bit ``i`` the coefficient of ``x^i``.
    support : tuple of int
        The ``n`` distinct field elements ``alpha_i`` that index the coordinates.
    polynomial : tuple of int
        The monic Goppa polynomial ``g``, constant term first; squarefree, no root in ``support``.
    generator : tuple of tuple of int
        A ``k x n`` generator matrix in reduced row echelon form.
    parity_check : tuple of tuple of int
        An ``(n - k) x n`` parity-check matrix of full rank, in reduced row echelon form.
    """

    m: int
    t: int
    field_modulus: int
    support: tuple[int, ...]
    polynomial: tuple[int, ...]
    generator: BitMatrix
    parity_check: BitMatrix

    @property
    def n(self) -> int:
        """Code length."""
        return len(self.support)

    @property
    def k(self) -> int:
        """Code dimension."""
        return len(self.generator)


@dataclass(frozen=True)
class McEliecePublicKey:
    """A McEliece public key: a scrambled, permuted Goppa generator matrix.

    Attributes
    ----------
    generator : tuple of tuple of int
        ``G' = S G P``, a ``k x n`` binary matrix.
    t : int
        Number of errors added to each ciphertext.
    """

    generator: BitMatrix
    t: int


@dataclass(frozen=True)
class McEliecePrivateKey:
    """A McEliece private key: the Goppa code and the two matrices that hide it.

    Attributes
    ----------
    code : GoppaCode
        The secret code, whose decoder corrects ``t`` errors.
    scrambler : tuple of tuple of int
        The invertible ``k x k`` matrix ``S``.
    permutation : tuple of int
        ``P`` as a list: column ``j`` of ``G'`` is column ``permutation[j]`` of ``S G``.
    """

    code: GoppaCode
    scrambler: BitMatrix
    permutation: tuple[int, ...]


@dataclass(frozen=True)
class McElieceKeyPair:
    """A McEliece public and private key.

    Attributes
    ----------
    public : McEliecePublicKey
    private : McEliecePrivateKey
    """

    public: McEliecePublicKey
    private: McEliecePrivateKey


@dataclass(frozen=True)
class NiederreiterPublicKey:
    """A Niederreiter public key: a scrambled, permuted Goppa parity-check matrix.

    Attributes
    ----------
    parity_check : tuple of tuple of int
        ``H' = S H P``, an ``(n - k) x n`` binary matrix.
    t : int
        The largest weight of a plaintext error vector.
    """

    parity_check: BitMatrix
    t: int


@dataclass(frozen=True)
class NiederreiterPrivateKey:
    """A Niederreiter private key.

    Attributes
    ----------
    code : GoppaCode
        The secret code.
    scrambler : tuple of tuple of int
        The invertible ``(n - k) x (n - k)`` matrix ``S``.
    permutation : tuple of int
        Column ``j`` of ``H'`` is column ``permutation[j]`` of ``S H``.
    """

    code: GoppaCode
    scrambler: BitMatrix
    permutation: tuple[int, ...]


@dataclass(frozen=True)
class NiederreiterKeyPair:
    """A Niederreiter public and private key.

    Attributes
    ----------
    public : NiederreiterPublicKey
    private : NiederreiterPrivateKey
    """

    public: NiederreiterPublicKey
    private: NiederreiterPrivateKey


@dataclass(frozen=True)
class McElieceBreakResult:
    """A McEliece plaintext recovered from the public key alone.

    Attributes
    ----------
    message : tuple of int
        The recovered ``k``-bit message.
    error : tuple of int
        The weight-``t`` error that information-set decoding removed.
    iterations : int
        Prange iterations used.
    """

    message: Bits
    error: Bits
    iterations: int


@dataclass(frozen=True)
class QuadraticMap:
    """A system of quadratic polynomials over a prime field GF(q).

    Polynomial ``k`` is ``sum_{i <= j} Q_k[i][j] x_i x_j + sum_i L_k[i] x_i + c_k``.

    Attributes
    ----------
    q : int
        The field size, a prime.
    quadratic : tuple of tuple of tuple of int
        One upper-triangular ``n x n`` matrix ``Q_k`` per polynomial (zero below the
        diagonal; over GF(2) the diagonal is zero too, since ``x^2 = x``).
    linear : tuple of tuple of int
        One coefficient vector ``L_k`` per polynomial.
    constant : tuple of int
        The constant terms ``c_k``.
    """

    q: int
    quadratic: tuple[tuple[tuple[int, ...], ...], ...]
    linear: tuple[tuple[int, ...], ...]
    constant: tuple[int, ...]

    @property
    def n_vars(self) -> int:
        """Number of variables."""
        return len(self.linear[0])

    @property
    def n_polys(self) -> int:
        """Number of polynomials."""
        return len(self.constant)

    def evaluate(self, x: Sequence[int]) -> tuple[int, ...]:
        """Evaluate every polynomial at ``x``, a vector of ``n_vars`` field elements.

        Examples
        --------
        >>> from cybersecuritykit import pqc
        >>> f = pqc.QuadraticMap(5, (((1, 2), (0, 0)),), ((0, 1),), (3,))
        >>> f.evaluate((1, 1))  # 1 + 2 + 1 + 3
        (2,)
        """
        if len(x) != self.n_vars:
            raise ValueError(f"x must have length {self.n_vars}")
        q = self.q
        out = []
        for quad, lin, c in zip(self.quadratic, self.linear, self.constant, strict=True):
            total = c + sum(a * xi for a, xi in zip(lin, x, strict=True))
            for i, row in enumerate(quad):
                total += x[i] * sum(a * xj for a, xj in zip(row, x, strict=True))
            out.append(total % q)
        return tuple(out)


@dataclass(frozen=True)
class MatsumotoImaiPrivateKey:
    """The secret affine maps and exponent of a Matsumoto-Imai key.

    The public map is ``P = T o F o S`` with ``F(X) = X^(2^theta + 1)`` on GF(2^n).

    Attributes
    ----------
    n : int
        Number of variables, and degree of the extension field.
    theta : int
        The exponent parameter, with ``gcd(2^theta + 1, 2^n - 1) = 1``.
    s_matrix, t_matrix : tuple of tuple of int
        Invertible ``n x n`` matrices over GF(2).
    s_offset, t_offset : tuple of int
        Translation vectors: ``S(x) = A x + a`` and ``T(y) = B y + b``.
    """

    n: int
    theta: int
    s_matrix: BitMatrix
    s_offset: Bits
    t_matrix: BitMatrix
    t_offset: Bits


@dataclass(frozen=True)
class MatsumotoImaiKeyPair:
    """A Matsumoto-Imai public quadratic map and its private key.

    Attributes
    ----------
    public : QuadraticMap
    private : MatsumotoImaiPrivateKey
    """

    public: QuadraticMap
    private: MatsumotoImaiPrivateKey


@dataclass(frozen=True)
class LinearizationResult:
    """A Matsumoto-Imai plaintext recovered by Patarin's linearization equations.

    Attributes
    ----------
    plaintext : tuple of int
        The recovered plaintext bits.
    relations : int
        Dimension of the space of bilinear relations found from the pairs.
    candidates : int
        Plaintexts left after substituting the ciphertext into the relations.
    pairs_used : int
        Plaintext and ciphertext pairs computed with the public key.
    """

    plaintext: Bits
    relations: int
    candidates: int
    pairs_used: int


@dataclass(frozen=True)
class OilVinegarPrivateKey:
    """The secret layered central map and linear maps of a UOV or Rainbow key.

    The public map is ``P = T o F o S``; UOV has one layer and ``T`` the identity.

    Attributes
    ----------
    q : int
        The field size, an odd prime.
    layers : tuple of tuple of int
        ``(v_l, o_l)`` per layer: layer ``l`` has ``o_l`` polynomials in the first
        ``v_l + o_l`` variables, with no product of two of its own oil variables.
    central : QuadraticMap
        The central map ``F``.
    s_matrix, t_matrix : tuple of tuple of int
        Invertible matrices over GF(q) of size ``n`` and ``m``.
    """

    q: int
    layers: tuple[tuple[int, int], ...]
    central: QuadraticMap
    s_matrix: tuple[tuple[int, ...], ...]
    t_matrix: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class OilVinegarKeyPair:
    """A UOV or Rainbow public quadratic map and its private key.

    Attributes
    ----------
    public : QuadraticMap
    private : OilVinegarPrivateKey
    """

    public: QuadraticMap
    private: OilVinegarPrivateKey


@dataclass(frozen=True)
class RainbowBreakResult:
    """The secret oil subspace of a Rainbow key recovered from the public key.

    Attributes
    ----------
    oil_vector : tuple of int
        A non-zero vector of the last-layer oil space ``O2``.
    oil_subspace : tuple of tuple of int
        A basis of ``O2``.
    w_subspace : tuple of tuple of int
        A basis of ``W``, the space that the polar form maps ``O2`` into.
    guesses : int
        Random points ``x`` tried before ``ker D_x`` met ``O2``.
    evaluations : int
        Kernel vectors tested, over all guesses.
    """

    oil_vector: tuple[int, ...]
    oil_subspace: tuple[tuple[int, ...], ...]
    w_subspace: tuple[tuple[int, ...], ...]
    guesses: int
    evaluations: int


# --- end slice B ---


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
