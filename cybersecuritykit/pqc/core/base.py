"""Frozen result dataclasses for :mod:`cybersecuritykit.pqc`."""

from collections.abc import Sequence
from dataclasses import dataclass

__all__: list[str] = []

# --- slice B: codes and multivariate ---

__all__ += [
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
]

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
