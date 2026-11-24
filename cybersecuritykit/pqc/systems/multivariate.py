"""Matsumoto-Imai encryption (1988) and Patarin's linearization attack (1995).

T. Matsumoto and H. Imai, "Public quadratic polynomial-tuples for efficient
signature-verification and message-encryption", *EUROCRYPT 1988*, LNCS 330. Identify
GF(2)^n with GF(2^n); the central map ``F(X) = X^(2^theta + 1)`` is a product of two
Frobenius powers, so its coordinates are quadratic over GF(2), and it is a permutation
when ``gcd(2^theta + 1, 2^n - 1) = 1``. Hidden between secret affine maps ``S`` and
``T``, the public key ``P = T o F o S`` is ``n`` quadratic polynomials in ``n`` bits.

J. Patarin, "Cryptanalysis of the Matsumoto and Imai public key scheme of Eurocrypt'88",
*CRYPTO 1995*, LNCS 963. With ``Y = X^(2^theta + 1)``,

    X * Y^(2^theta) = X^(2^(2 theta)) * Y,

and both sides are bilinear in the bits of ``X`` and ``Y``. Through ``S`` and ``T`` this
gives relations ``sum a_ij u_i v_j + sum b_i u_i + sum c_j v_j + d = 0`` between every
plaintext ``u`` and its ciphertext ``v``. The attacker finds them by linear algebra on
pairs computed with the public key, substitutes a target ciphertext and solves a linear
system for the plaintext.
"""

import itertools
import math
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.pqc.core.base import (
    LinearizationResult,
    MatsumotoImaiKeyPair,
    MatsumotoImaiPrivateKey,
    QuadraticMap,
)
from cybersecuritykit.pqc.utils import binary, prime_field
from cybersecuritykit.pqc.utils.galois import MODULI, gf_pow
from cybersecuritykit.pqc.utils.quadratic import interpolate

__all__ = [
    "matsumoto_imai_decrypt",
    "matsumoto_imai_encrypt",
    "matsumoto_imai_keygen",
    "patarin_linearization",
]


def _affine(matrix: Sequence[Sequence[int]], offset: Sequence[int], x: Sequence[int]) -> list[int]:
    return [(y + a) % 2 for y, a in zip(prime_field.mat_vec(matrix, x, 2), offset, strict=True)]


def _power(x: Sequence[int], exponent: int, n: int) -> list[int]:
    return list(binary.unpack(gf_pow(binary.pack(x), exponent, n), n))


def matsumoto_imai_keygen(n: int, theta: int, *, seed: int) -> MatsumotoImaiKeyPair:
    """Generate a toy Matsumoto-Imai key over GF(2^n).

    Parameters
    ----------
    n : int
        Number of plaintext bits, ``2 <= n <= 12``.
    theta : int
        ``1 <= theta < n`` with ``gcd(2^theta + 1, 2^n - 1) = 1``.
    seed : int
        Seed for the secret affine maps.

    Returns
    -------
    MatsumotoImaiKeyPair
        The public map is interpolated from ``T o F o S``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.matsumoto_imai_keygen(5, 2, seed=2026)
    >>> ciphertext = pqc.matsumoto_imai_encrypt(keys.public, (1, 0, 1, 1, 0))
    >>> pqc.matsumoto_imai_decrypt(keys.private, ciphertext)
    (1, 0, 1, 1, 0)
    """
    _validation.integer(n, "n", minimum=2)
    if n not in MODULI:
        raise ValueError(f"n must be at most {max(MODULI)}")
    _validation.integer(theta, "theta", minimum=1)
    if theta >= n or math.gcd(2**theta + 1, 2**n - 1) != 1:
        raise ValueError("theta must satisfy theta < n and gcd(2^theta + 1, 2^n - 1) = 1")
    _validation.seed(seed)
    rng = random.Random(seed)
    s, t = (prime_field.random_invertible(n, 2, rng) for _ in range(2))
    a, b = ([rng.randrange(2) for _ in range(n)] for _ in range(2))
    exponent = 2**theta + 1

    def forward(x: list[int]) -> list[int]:
        return _affine(t, b, _power(_affine(s, a, x), exponent, n))

    private = MatsumotoImaiPrivateKey(
        n,
        theta,
        tuple(tuple(row) for row in s),
        tuple(a),
        tuple(tuple(row) for row in t),
        tuple(b),
    )
    return MatsumotoImaiKeyPair(interpolate(forward, n, 2), private)


def matsumoto_imai_encrypt(public: QuadraticMap, plaintext: Sequence[int]) -> tuple[int, ...]:
    """Evaluate the public quadratic map on the plaintext bits."""
    return public.evaluate(binary.check_vector(plaintext, public.n_vars, "plaintext"))


def matsumoto_imai_decrypt(
    private: MatsumotoImaiPrivateKey, ciphertext: Sequence[int]
) -> tuple[int, ...]:
    """Invert ``T``, raise to ``h = (2^theta + 1)^-1 mod 2^n - 1``, then invert ``S``."""
    n = private.n
    y = binary.check_vector(ciphertext, n, "ciphertext")
    t_inverse = prime_field.inverse(private.t_matrix, 2)
    s_inverse = prime_field.inverse(private.s_matrix, 2)
    assert t_inverse is not None and s_inverse is not None  # invertible by construction
    y_central = prime_field.mat_vec(t_inverse, _affine(_identity(n), private.t_offset, y), 2)
    x_central = _power(y_central, pow(2**private.theta + 1, -1, 2**n - 1), n)
    x = prime_field.mat_vec(s_inverse, _affine(_identity(n), private.s_offset, x_central), 2)
    return tuple(x)


def _identity(n: int) -> list[list[int]]:
    return [[int(i == j) for j in range(n)] for i in range(n)]


def patarin_linearization(
    public: QuadraticMap, ciphertext: Sequence[int], *, seed: int, pairs: int | None = None
) -> LinearizationResult:
    """Decrypt a Matsumoto-Imai ciphertext from the public key with Patarin's relations.

    Parameters
    ----------
    public : QuadraticMap
        A Matsumoto-Imai public key over GF(2).
    ciphertext : sequence of int
        The target ciphertext bits.
    seed : int
        Seed for choosing the plaintexts of the known pairs.
    pairs : int, optional
        How many pairs to compute, at most ``2^n``; defaults to ``2 (n + 1)^2``.

    Raises
    ------
    RuntimeError
        Too few pairs: a spurious relation excluded the plaintext.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.matsumoto_imai_keygen(5, 2, seed=2026)
    >>> ciphertext = pqc.matsumoto_imai_encrypt(keys.public, (1, 0, 1, 1, 0))
    >>> pqc.patarin_linearization(keys.public, ciphertext, seed=1).plaintext
    (1, 0, 1, 1, 0)
    """
    if public.q != 2:
        raise ValueError("public must be a map over GF(2)")
    n = public.n_vars
    target = binary.check_vector(ciphertext, public.n_polys, "ciphertext")
    _validation.seed(seed)
    if pairs is None:
        pairs = 2 * (n + 1) ** 2
    _validation.integer(pairs, "pairs", minimum=1)
    sample = random.Random(seed).sample(range(2**n), min(pairs, 2**n))
    rows = []
    for value in sample:
        u = binary.unpack(value, n)
        v = public.evaluate(u)
        rows.append([ui * vj for ui in u for vj in v] + list(u) + list(v) + [1])
    relations = prime_field.nullspace(rows, (n + 1) ** 2, 2)
    # Substitute v = target: each relation is linear in u.
    nn = n * n
    system = [
        [(sum(r[i * n + j] * target[j] for j in range(n)) + r[nn + i]) % 2 for i in range(n)]
        for r in relations
    ]
    rhs = [(sum(r[nn + n + j] * target[j] for j in range(n)) + r[-1]) % 2 for r in relations]
    particular, kernel = prime_field.solve(system, rhs, n, 2)
    bases = [] if particular is None else [particular]
    candidates = [
        tuple(
            (p + sum(c * k[i] for c, k in zip(coeffs, kernel, strict=True))) % 2
            for i, p in enumerate(base)
        )
        for base in bases
        for coeffs in itertools.product((0, 1), repeat=len(kernel))
    ]
    matches = [u for u in candidates if public.evaluate(u) == target]
    if not matches:
        raise RuntimeError("too few pairs: the relations exclude the plaintext")
    return LinearizationResult(matches[0], len(relations), len(candidates), len(sample))
