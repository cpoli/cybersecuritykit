"""Frozen result dataclasses for :mod:`cybersecuritykit.pqc`."""

from dataclasses import dataclass

__all__: list[str] = []

# --- slice B: codes and multivariate ---

__all__ += [
    "GoppaCode",
    "ISDResult",
    "McElieceBreakResult",
    "McElieceKeyPair",
    "McEliecePrivateKey",
    "McEliecePublicKey",
    "NiederreiterKeyPair",
    "NiederreiterPrivateKey",
    "NiederreiterPublicKey",
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


# --- end slice B ---
