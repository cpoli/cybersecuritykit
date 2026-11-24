"""NTRU, the ring-based public-key cryptosystem (1998), and its lattice attack.

J. Hoffstein, J. Pipher and J. H. Silverman, "NTRU: a ring-based public key
cryptosystem", *Algorithmic Number Theory (ANTS-III)*, LNCS 1423, 267-288
(1998). Work in :math:`R = \\mathbb{Z}[x]/(x^N - 1)`. The private key is a
small ternary :math:`f` invertible mod :math:`p` and mod :math:`q`; the public
key is :math:`h = f_q \\star g \\bmod q` for another small :math:`g`. A
ciphertext :math:`e = p\\, r \\star h + m` hides the small message :math:`m`
behind the blinding :math:`r`; multiplying by :math:`f` gives
:math:`p\\, r \\star g + f \\star m`, small enough not to wrap mod :math:`q`,
and :math:`f_p` then strips :math:`f` mod :math:`p`.

D. Coppersmith and A. Shamir, "Lattice attacks on NTRU", *EUROCRYPT '97*,
LNCS 1233, 52-61 (1997), observed that :math:`(f, g)` is an unusually short
vector of the lattice :math:`\\{(u, u \\star h \\bmod q)\\}` of dimension
:math:`2N`, so lattice reduction recovers the key when :math:`N` is small.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import NTRUAttackResult, NTRUKeyPair, NTRUPublicKey
from cybersecuritykit.pqc.systems.lattice import lll_reduce
from cybersecuritykit.pqc.utils.rings import Poly, centered, int_vector, multiply

__all__ = ["ntru_decrypt", "ntru_encrypt", "ntru_keygen", "ntru_keypair", "ntru_lattice_attack"]


def _smallest_factor(n: int) -> int:
    d = 2
    while d * d <= n:
        if n % d == 0:
            return d
        d += 1
    return n


def _parameters(n: int, p: int, q: int) -> int:
    """Validate the ring and moduli; return the prime whose power ``q`` is."""
    _validation.integer(n, "n", minimum=2)
    _validation.integer(p, "p", minimum=2)
    _validation.integer(q, "q", minimum=2)
    if _smallest_factor(p) != p:
        raise ValueError("p must be prime")
    prime = _smallest_factor(q)
    power = q
    while power % prime == 0:
        power //= prime
    if power != 1:
        raise ValueError("q must be a prime power")
    if prime == p or q <= p:
        raise ValueError("q must be coprime to p and larger than it")
    return prime


def _invert_mod_prime(a: Poly, prime: int) -> Poly | None:
    """Inverse of ``a`` in Z_prime[x]/(x^n - 1) by Gaussian elimination, or None."""
    n = len(a)
    # Column j of the multiplication matrix is a * x^j; solve M b = 1.
    rows = [[a[(i - j) % n] % prime for j in range(n)] + [int(i == 0)] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if rows[r][col]), None)
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        scale = pow(rows[col][col], -1, prime)
        rows[col] = [x * scale % prime for x in rows[col]]
        for r in range(n):
            if r != col and rows[r][col]:
                factor = rows[r][col]
                rows[r] = [
                    (x - factor * y) % prime for x, y in zip(rows[r], rows[col], strict=True)
                ]
    return tuple(row[n] for row in rows)


def _invert(a: Poly, prime: int, q: int) -> Poly | None:
    """Inverse mod a prime power ``q``, lifted from mod ``prime`` by Newton's iteration."""
    b = _invert_mod_prime(a, prime)
    if b is None:
        return None
    modulus = prime
    while modulus < q:
        modulus = min(modulus * modulus, q)
        ab = multiply(a, b, modulus, 1)
        two_minus = tuple((2 * (i == 0) - x) % modulus for i, x in enumerate(ab))
        b = multiply(b, two_minus, modulus, 1)
    return b


def _pair(f: Poly, g: Poly, p: int, q: int, prime: int) -> NTRUKeyPair | None:
    f_p = _invert_mod_prime(f, p)
    f_q = _invert(f, prime, q)
    if f_p is None or f_q is None:
        return None
    h = multiply(f_q, g, q, 1)
    return NTRUKeyPair(NTRUPublicKey(len(f), p, q, h), f, g, f_p)


def ntru_keypair(f: Sequence[int], g: Sequence[int], p: int, q: int) -> NTRUKeyPair:
    r"""Build an NTRU key pair from chosen private polynomials.

    Parameters
    ----------
    f, g : sequence of int
        Coefficients of the private polynomials, constant term first; their
        common length is :math:`N`.
    p : int
        The small prime modulus.
    q : int
        The large modulus, a prime power coprime to :math:`p`.

    Returns
    -------
    NTRUKeyPair
        With :math:`h = f_q \star g \bmod q` and :math:`f_p = f^{-1} \bmod p`.

    Raises
    ------
    ValueError
        Bad moduli, mismatched lengths, or :math:`f` not invertible mod
        :math:`p` or mod :math:`q`.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ntru_keypair((-1, 0, 1, 1, -1, 0, 1), (0, -1, -1, 0, 1, 0, 1), 3, 41)
    >>> keys.public.h
    (30, 26, 8, 38, 2, 40, 20)
    """
    small_f = int_vector(f, "f")
    prime = _parameters(len(small_f), p, q)
    small_g = int_vector(g, "g", len(small_f))
    keys = _pair(small_f, small_g, p, q, prime)
    if keys is None:
        raise ValueError("f must be invertible mod p and mod q")
    return keys


def _ternary(rng: random.Random, n: int, ones: int, minus: int) -> Poly:
    coefficients = [1] * ones + [-1] * minus + [0] * (n - ones - minus)
    rng.shuffle(coefficients)
    return tuple(coefficients)


def ntru_keygen(n: int, p: int, q: int, d: int, seed: int = DEFAULT_SEED) -> NTRUKeyPair:
    """Draw a random NTRU key pair.

    :math:`f` has :math:`d + 1` coefficients 1 and :math:`d` coefficients -1
    (redrawn until invertible); :math:`g` has :math:`d` of each.

    Parameters
    ----------
    n : int
        The ring degree :math:`N`.
    p, q : int
        The moduli, as in :func:`ntru_keypair`.
    d : int
        The weight parameter, with :math:`2d + 1 \\le N`.
    seed : int, optional
        Seed of the private polynomials.

    Returns
    -------
    NTRUKeyPair

    Raises
    ------
    ValueError
        Bad parameters.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ntru_keygen(11, 3, 64, 3, seed=1)
    >>> sum(keys.f)
    1
    """
    prime = _parameters(n, p, q)
    _validation.integer(d, "d", minimum=1)
    _validation.seed(seed)
    if 2 * d + 1 > n:
        raise ValueError("need 2d + 1 <= n")
    rng = random.Random(seed)
    while True:
        f = _ternary(rng, n, d + 1, d)
        keys = _pair(f, _ternary(rng, n, d, d), p, q, prime)
        if keys is not None:
            return keys


def _public(public: NTRUPublicKey) -> None:
    if not isinstance(public, NTRUPublicKey):
        raise TypeError("public must be an NTRUPublicKey")


def _small(values: Sequence[int], name: str, n: int, p: int) -> Poly:
    vector = int_vector(values, name, n)
    if any(centered(x, p) != x for x in vector):
        raise ValueError(f"{name} coefficients must lie in (-p/2, p/2]")
    return vector


def ntru_encrypt(
    public: NTRUPublicKey,
    message: Sequence[int],
    seed: int = DEFAULT_SEED,
    blinding: Sequence[int] | None = None,
) -> Poly:
    r"""Encrypt :math:`e = p\, r \star h + m \bmod q`.

    Parameters
    ----------
    public : NTRUPublicKey
        The recipient's key.
    message : sequence of int
        :math:`N` coefficients in :math:`(-p/2, p/2]`.
    seed : int, optional
        Seed of the blinding polynomial, which has :math:`\lfloor N/3 \rfloor`
        coefficients 1 and as many -1.
    blinding : sequence of int, optional
        An explicit blinding polynomial :math:`r`, overriding ``seed``.

    Returns
    -------
    tuple of int
        The ciphertext coefficients in :math:`[0, q)`.

    Raises
    ------
    TypeError
        ``public`` is not an :class:`~cybersecuritykit.pqc.core.base.NTRUPublicKey`.
    ValueError
        A message or blinding polynomial of the wrong length or range.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ntru_keygen(11, 3, 64, 3, seed=1)
    >>> m = (1, 0, -1, 1, 1, 0, 0, -1, 0, 1, 0)
    >>> pqc.ntru_decrypt(keys, pqc.ntru_encrypt(keys.public, m, seed=2)) == m
    True
    """
    _public(public)
    m = _small(message, "message", public.n, public.p)
    _validation.seed(seed)
    if blinding is None:
        r = _ternary(random.Random(seed), public.n, public.n // 3, public.n // 3)
    else:
        r = int_vector(blinding, "blinding", public.n)
    prh = multiply(r, tuple(public.p * x for x in public.h), public.q, 1)
    return tuple((x + y) % public.q for x, y in zip(prh, m, strict=True))


def ntru_decrypt(keypair: NTRUKeyPair, ciphertext: Sequence[int]) -> Poly:
    r"""Decrypt: centre :math:`a = f \star e \bmod q`, then :math:`m = f_p \star a \bmod p`.

    Parameters
    ----------
    keypair : NTRUKeyPair
        The private key.
    ciphertext : sequence of int
        :math:`N` coefficients.

    Returns
    -------
    tuple of int
        The message, coefficients in :math:`(-p/2, p/2]`. It is wrong when a
        coefficient of :math:`p\, r \star g + f \star m` wraps mod :math:`q`.

    Raises
    ------
    TypeError
        ``keypair`` is not an :class:`~cybersecuritykit.pqc.core.base.NTRUKeyPair`.
    ValueError
        A ciphertext of the wrong length.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ntru_keypair((-1, 0, 1, 1, -1, 0, 1), (0, -1, -1, 0, 1, 0, 1), 3, 41)
    >>> pqc.ntru_decrypt(keys, (25, 3, 40, 2, 4, 19, 31))
    (1, -1, 1, 1, 0, -1, 0)
    """
    if not isinstance(keypair, NTRUKeyPair):
        raise TypeError("keypair must be an NTRUKeyPair")
    public = keypair.public
    e = int_vector(ciphertext, "ciphertext", public.n)
    a = tuple(centered(x, public.q) for x in multiply(keypair.f, e, public.q, 1))
    return tuple(centered(x, public.p) for x in multiply(keypair.f_p, a, public.p, 1))


def ntru_lattice_attack(public: NTRUPublicKey) -> NTRUAttackResult:
    r"""Recover a working private key with LLL (Coppersmith and Shamir, 1997).

    Reduce the basis :math:`\begin{pmatrix} I & H \\ 0 & qI \end{pmatrix}`,
    whose row :math:`i` of the top half is :math:`(x^i, x^i \star h)`. The
    lattice holds :math:`(f, g)` and its rotations; any reduced row whose first
    half is invertible mod :math:`p` and mod :math:`q` is taken as the key.
    The rows are tried shortest first, which skips the even shorter
    :math:`(1, \dots, 1, 0, \dots, 0)`, never invertible since
    :math:`(1 + \dots + x^{N-1})(1 - x) = 0`.

    Parameters
    ----------
    public : NTRUPublicKey
        The key under attack, with :math:`N` small (7 runs in well under a second).

    Returns
    -------
    NTRUAttackResult

    Raises
    ------
    TypeError
        ``public`` is not an :class:`~cybersecuritykit.pqc.core.base.NTRUPublicKey`.
    ValueError
        No reduced row gives an invertible :math:`f`.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ntru_keygen(7, 3, 41, 2, seed=3)
    >>> attack = pqc.ntru_lattice_attack(keys.public)
    >>> attack.keypair.public == keys.public
    True
    """
    _public(public)
    n, p, q = public.n, public.p, public.q
    prime = _parameters(n, p, q)
    basis = [
        tuple(int(i == j) for j in range(n)) + tuple(public.h[(j - i) % n] for j in range(n))
        for i in range(n)
    ] + [(0,) * n + tuple(q * int(i == j) for j in range(n)) for i in range(n)]
    reduction = lll_reduce(basis)
    for row in sorted(reduction.basis, key=lambda v: sum(x * x for x in v)):
        f = row[:n]
        keys = _pair(f, row[n:], p, q, prime)
        if keys is not None:
            return NTRUAttackResult(keys, 2 * n, reduction.swaps)
    raise ValueError("no reduced vector gives an invertible f")
