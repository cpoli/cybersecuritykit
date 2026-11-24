"""Binary Goppa codes, McEliece encryption (1978) and Niederreiter's dual form (1986).

R. J. McEliece, "A public-key cryptosystem based on algebraic coding theory", *DSN
Progress Report* 42-44, Jet Propulsion Laboratory, 1978. The private key is a binary
Goppa code with an efficient decoder; the public key ``G' = S G P`` hides it behind a
random invertible ``S`` and a column permutation ``P``. A ciphertext is a codeword
``m G'`` plus ``t`` random errors, which only the owner of the decoder can remove.

H. Niederreiter, "Knapsack-type cryptosystems and algebraic coding theory", *Problems
of Control and Information Theory* 15(2), 1986. The dual form publishes a scrambled
parity-check matrix ``H' = S H P`` and encrypts a weight-``t`` vector ``e`` as its
syndrome ``H' e``. Niederreiter proposed generalized Reed-Solomon codes, which
Sidelnikov and Shestakov broke in 1992; with Goppa codes the two systems are equally
secure (Li, Deng and Wang, 1994).

Goppa codes follow V. D. Goppa, "A new class of linear correcting codes", *Problemy
Peredachi Informatsii* 6(3), 1970. Decoding uses ``Gamma(L, g) = Gamma(L, g^2)`` for
squarefree ``g`` and solves the key equation with the extended Euclidean algorithm
(Sugiyama, Kasahara, Hirasawa and Namekawa, 1975) instead of Patterson's algorithm.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.pqc.core.base import (
    GoppaCode,
    ISDResult,
    McElieceBreakResult,
    McElieceKeyPair,
    McEliecePrivateKey,
    McEliecePublicKey,
    NiederreiterKeyPair,
    NiederreiterPrivateKey,
    NiederreiterPublicKey,
)
from cybersecuritykit.pqc.systems.isd import prange_isd
from cybersecuritykit.pqc.utils import binary
from cybersecuritykit.pqc.utils.galois import (
    MODULI,
    Poly,
    gf_inv,
    gf_mul,
    gf_pow,
    poly_add,
    poly_deriv,
    poly_divmod,
    poly_eval,
    poly_gcd,
    poly_mul,
    poly_scale,
)

__all__ = [
    "break_mceliece",
    "break_niederreiter",
    "goppa_code",
    "goppa_decode",
    "mceliece_decrypt",
    "mceliece_encrypt",
    "mceliece_keygen",
    "niederreiter_decrypt",
    "niederreiter_encrypt",
    "niederreiter_keygen",
]


def _check_field(m: int, t: int) -> None:
    _validation.integer(m, "m", minimum=2)
    if m not in MODULI:
        raise ValueError(f"m must be at most {max(MODULI)}")
    _validation.integer(t, "t", minimum=1)


def goppa_code(m: int, t: int, *, seed: int, n: int | None = None) -> GoppaCode:
    """Draw a random binary Goppa code of length ``n`` correcting ``t`` errors.

    Parameters
    ----------
    m : int
        Extension degree, ``2 <= m <= 12``; the support lies in GF(2^m).
    t : int
        Degree of the Goppa polynomial, at least 2.
    seed : int
        Seed for the support order and the polynomial.
    n : int, optional
        Code length, ``m t < n <= 2^m``; defaults to ``2^m``.

    Returns
    -------
    GoppaCode
        A code of dimension ``k >= n - m t`` and minimum distance at least ``2 t + 1``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> code = pqc.goppa_code(4, 2, seed=2026)
    >>> code.n, code.k
    (16, 8)
    """
    _check_field(m, t)
    _validation.seed(seed)
    size = 2**m
    if n is None:
        n = size
    _validation.integer(n, "n", minimum=1)
    if not m * t < n <= size:
        raise ValueError("n must satisfy m t < n <= 2^m")
    rng = random.Random(seed)
    elements = list(range(size))
    rng.shuffle(elements)
    support = tuple(elements[:n])
    while True:
        g = [rng.randrange(size) for _ in range(t)] + [1]
        squarefree = poly_gcd(g, poly_deriv(g), m) == [1]
        if squarefree and all(poly_eval(g, a, m) for a in support):
            break
    # Parity checks over GF(2^m): H[i][j] = alpha_j^i / g(alpha_j), each entry m bits.
    columns = [
        [gf_mul(gf_pow(a, i, m), gf_inv(poly_eval(g, a, m), m), m) for i in range(t)]
        for a in support
    ]
    rows = [
        sum(((columns[j][i] >> b) & 1) << j for j in range(n)) for i in range(t) for b in range(m)
    ]
    reduced, pivots = binary.rref(rows, range(n))
    parity = reduced[: len(pivots)]
    generator = binary.rref(binary.nullspace(parity, n), range(n))[0]
    return GoppaCode(
        m,
        t,
        MODULI[m],
        support,
        tuple(g),
        binary.unpack_matrix(generator, n),
        binary.unpack_matrix(parity, n),
    )


def _decode(code: GoppaCode, word: int) -> int:
    m, t = code.m, code.t
    g2 = poly_mul(list(code.polynomial), list(code.polynomial), m)
    s: Poly = []
    for j, a in enumerate(code.support):
        if (word >> j) & 1:
            # (x + a)^-1 mod g^2 is (g^2(x) - g^2(a)) / (x + a), divided by g^2(a).
            quotient, remainder = poly_divmod(g2, [a, 1], m)
            s = poly_add(s, poly_scale(quotient, gf_inv(remainder[0], m), m))
    # Key equation sigma S = omega mod g^2, deg omega < t: stop Euclid below degree t.
    r0, r1 = g2, s
    u0: Poly = []
    u1: Poly = [1]
    while len(r1) > t:
        quotient, remainder = poly_divmod(r0, r1, m)
        r0, r1 = r1, remainder
        u0, u1 = u1, poly_add(u0, poly_mul(quotient, u1, m))
    error = sum(1 << j for j, a in enumerate(code.support) if poly_eval(u1, a, m) == 0)
    parity = [binary.pack(row) for row in code.parity_check]
    if binary.mat_vec(parity, word ^ error):
        raise ValueError(f"word is more than {t} errors from every codeword")
    return error


def goppa_decode(code: GoppaCode, word: Sequence[int]) -> tuple[int, ...]:
    """Return the error of weight at most ``t`` that separates ``word`` from a codeword.

    Raises
    ------
    ValueError
        The decoder found no codeword within ``t`` errors.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> code = pqc.goppa_code(4, 2, seed=2026)
    >>> received = list(code.generator[0])
    >>> received[3] ^= 1
    >>> pqc.goppa_decode(code, received).index(1)
    3
    """
    bits = binary.check_vector(word, code.n, "word")
    return binary.unpack(_decode(code, binary.pack(bits)), code.n)


def _packed(matrix: Sequence[Sequence[int]]) -> list[int]:
    return [binary.pack(row) for row in matrix]


def _hide(rows: list[int], n: int, rng: random.Random) -> tuple[list[int], list[int], list[int]]:
    """Return ``S``, ``P`` and ``S M P`` for random invertible ``S`` and permutation ``P``."""
    scrambler = binary.random_invertible(len(rows), rng)
    permutation = rng.sample(range(n), n)
    mixed = [binary.vec_mat(s_row, rows) for s_row in scrambler]
    return scrambler, permutation, binary.permute_columns(mixed, permutation)


def mceliece_keygen(m: int, t: int, *, seed: int) -> McElieceKeyPair:
    """Generate a toy McEliece key pair on a Goppa code of length ``2^m``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.mceliece_keygen(4, 2, seed=2026)
    >>> len(keys.public.generator), len(keys.public.generator[0])
    (8, 16)
    """
    _check_field(m, t)
    _validation.seed(seed)
    rng = random.Random(seed)
    code = goppa_code(m, t, seed=rng.getrandbits(64))
    scrambler, permutation, public = _hide(_packed(code.generator), code.n, rng)
    return McElieceKeyPair(
        McEliecePublicKey(binary.unpack_matrix(public, code.n), t),
        McEliecePrivateKey(code, binary.unpack_matrix(scrambler, code.k), tuple(permutation)),
    )


def mceliece_encrypt(
    public: McEliecePublicKey, message: Sequence[int], *, seed: int
) -> tuple[int, ...]:
    """Encrypt ``k`` message bits as ``m G' + e`` with a random error of weight ``t``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.mceliece_keygen(4, 2, seed=2026)
    >>> ciphertext = pqc.mceliece_encrypt(keys.public, (1, 0, 1, 1, 0, 0, 1, 0), seed=1)
    >>> pqc.mceliece_decrypt(keys.private, ciphertext)
    (1, 0, 1, 1, 0, 0, 1, 0)
    """
    rows = _packed(public.generator)
    n = len(public.generator[0])
    x = binary.pack(binary.check_vector(message, len(rows), "message"))
    _validation.seed(seed)
    error = sum(1 << j for j in random.Random(seed).sample(range(n), public.t))
    return binary.unpack(binary.vec_mat(x, rows) ^ error, n)


def _coefficients(rows: list[int], n: int, codeword: int) -> int:
    """The ``x`` with ``x M = codeword`` for a full-rank ``M`` with ``n`` columns."""
    k = len(rows)
    reduced, pivots = binary.rref([row | (1 << (n + i)) for i, row in enumerate(rows)], range(n))
    z = sum(((codeword >> col) & 1) << i for i, col in enumerate(pivots))
    return binary.vec_mat(z, [row >> n for row in reduced[:k]])


def mceliece_decrypt(private: McEliecePrivateKey, ciphertext: Sequence[int]) -> tuple[int, ...]:
    """Undo the permutation, decode the Goppa code, then undo the scrambler."""
    code = private.code
    c = binary.pack(binary.check_vector(ciphertext, code.n, "ciphertext"))
    unpermuted = sum(((c >> j) & 1) << p for j, p in enumerate(private.permutation))
    codeword = unpermuted ^ _decode(code, unpermuted)
    scrambled = _coefficients(_packed(code.generator), code.n, codeword)
    inverse = binary.inverse(_packed(private.scrambler), code.k)
    assert inverse is not None  # the scrambler is invertible by construction
    return binary.unpack(binary.vec_mat(scrambled, inverse), code.k)


def break_mceliece(
    public: McEliecePublicKey,
    ciphertext: Sequence[int],
    *,
    seed: int,
    max_iterations: int = 100_000,
) -> McElieceBreakResult:
    """Recover a McEliece plaintext from the public key with Prange's decoder.

    The dual of ``G'`` gives a public parity-check matrix ``H'``; information-set
    decoding finds the weight-``t`` error with syndrome ``H' c``, and the codeword
    ``c - e`` gives the message by linear algebra.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.mceliece_keygen(4, 2, seed=2026)
    >>> ciphertext = pqc.mceliece_encrypt(keys.public, (1, 0, 1, 1, 0, 0, 1, 0), seed=1)
    >>> pqc.break_mceliece(keys.public, ciphertext, seed=3).message
    (1, 0, 1, 1, 0, 0, 1, 0)
    """
    rows = _packed(public.generator)
    n = len(public.generator[0])
    c = binary.pack(binary.check_vector(ciphertext, n, "ciphertext"))
    dual = binary.nullspace(rows, n)
    target = binary.unpack(binary.mat_vec(dual, c), len(dual))
    found = prange_isd(
        binary.unpack_matrix(dual, n),
        target,
        public.t,
        seed=seed,
        max_iterations=max_iterations,
    )
    x = _coefficients(rows, n, c ^ binary.pack(found.error))
    return McElieceBreakResult(binary.unpack(x, len(rows)), found.error, found.iterations)


def niederreiter_keygen(m: int, t: int, *, seed: int) -> NiederreiterKeyPair:
    """Generate a toy Niederreiter key pair on a Goppa code of length ``2^m``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.niederreiter_keygen(4, 2, seed=2026)
    >>> len(keys.public.parity_check), len(keys.public.parity_check[0])
    (8, 16)
    """
    _check_field(m, t)
    _validation.seed(seed)
    rng = random.Random(seed)
    code = goppa_code(m, t, seed=rng.getrandbits(64))
    scrambler, permutation, public = _hide(_packed(code.parity_check), code.n, rng)
    return NiederreiterKeyPair(
        NiederreiterPublicKey(binary.unpack_matrix(public, code.n), t),
        NiederreiterPrivateKey(
            code, binary.unpack_matrix(scrambler, len(scrambler)), tuple(permutation)
        ),
    )


def niederreiter_encrypt(public: NiederreiterPublicKey, error: Sequence[int]) -> tuple[int, ...]:
    """Encrypt an error vector of weight at most ``t`` as its syndrome ``H' e``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.niederreiter_keygen(4, 2, seed=2026)
    >>> e = (0, 1) + (0,) * 12 + (1, 0)
    >>> pqc.niederreiter_decrypt(keys.private, pqc.niederreiter_encrypt(keys.public, e)) == e
    True
    """
    rows = _packed(public.parity_check)
    e = binary.check_vector(error, len(public.parity_check[0]), "error")
    if sum(e) > public.t:
        raise ValueError(f"error must have weight at most {public.t}")
    return binary.unpack(binary.mat_vec(rows, binary.pack(e)), len(rows))


def niederreiter_decrypt(
    private: NiederreiterPrivateKey, ciphertext: Sequence[int]
) -> tuple[int, ...]:
    """Unscramble the syndrome, lift it to a word, decode, and undo the permutation."""
    code = private.code
    r = len(private.scrambler)
    s = binary.pack(binary.check_vector(ciphertext, r, "ciphertext"))
    inverse = binary.inverse(_packed(private.scrambler), r)
    assert inverse is not None  # the scrambler is invertible by construction
    unscrambled = binary.mat_vec(inverse, s)
    # H is in reduced row echelon form: put syndrome bit i on the pivot of row i.
    _, pivots = binary.rref(_packed(code.parity_check), range(code.n))
    word = sum(((unscrambled >> i) & 1) << col for i, col in enumerate(pivots))
    permuted = _decode(code, word)
    return binary.unpack(binary.permute_columns([permuted], private.permutation)[0], code.n)


def break_niederreiter(
    public: NiederreiterPublicKey,
    ciphertext: Sequence[int],
    *,
    seed: int,
    max_iterations: int = 100_000,
) -> ISDResult:
    """Recover a Niederreiter plaintext from the public key with Prange's decoder.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.niederreiter_keygen(4, 2, seed=2026)
    >>> e = (0, 1) + (0,) * 12 + (1, 0)
    >>> ciphertext = pqc.niederreiter_encrypt(keys.public, e)
    >>> pqc.break_niederreiter(keys.public, ciphertext, seed=1).error == e
    True
    """
    return prange_isd(
        public.parity_check, ciphertext, public.t, seed=seed, max_iterations=max_iterations
    )
