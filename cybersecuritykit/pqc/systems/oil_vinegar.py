"""Oil and vinegar signatures (1997-1999), Rainbow (2005) and Beullens's break (2022).

J. Patarin, "The oil and vinegar signature scheme", Dagstuhl workshop on cryptography,
1997, proposed a central map in which no polynomial multiplies two *oil* variables:
fix the *vinegar* variables at random and the equations become linear in the oils.
A. Kipnis and A. Shamir, "Cryptanalysis of the oil and vinegar signature scheme",
*CRYPTO 1998*, broke the balanced case (as many vinegar as oil variables); A. Kipnis,
J. Patarin and L. Goubin, "Unbalanced oil and vinegar signature schemes", *EUROCRYPT
1999*, repaired it with more vinegar than oil (UOV). The public key is ``P = F o S``.

J. Ding and D. Schmidt, "Rainbow, a new multivariable polynomial signature scheme",
*ACNS 2005*, stacked oil and vinegar layers: the oils of one layer are vinegars of the
next, and an output map ``T`` mixes the layers, ``P = T o F o S``.

W. Beullens, "Breaking Rainbow takes a weekend on a laptop", *CRYPTO 2022*. Let
``O2 = S^-1(span of the last-layer oils)``. The polar form
``D(x, y) = P(x + y) - P(x) - P(y) + P(0)`` maps ``O2`` into a space ``W`` of dimension
``o2``, for every ``x``, and ``P`` vanishes on ``O2``'s quadratic part. For a random
``x`` the kernel of ``D_x`` meets ``O2`` with probability about ``1/q``; a vector there
satisfies ``P_h(y) = 0`` and ``rank D_y <= o2``. Beullens solved that system with a
Groebner basis; on toy sizes this module enumerates the kernel. One oil vector reveals
``W = image(D_y)`` and then all of ``O2`` by linear algebra.
"""

import hashlib
import itertools
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.pqc.core.base import (
    OilVinegarKeyPair,
    OilVinegarPrivateKey,
    QuadraticMap,
    RainbowBreakResult,
)
from cybersecuritykit.pqc.utils import prime_field
from cybersecuritykit.pqc.utils.quadratic import interpolate, polar_matrix, symmetric_forms

__all__ = [
    "beullens_rainbow_attack",
    "oil_vinegar_sign",
    "oil_vinegar_verify",
    "rainbow_keygen",
    "uov_keygen",
]


def _check_field(q: int) -> None:
    _validation.integer(q, "q")
    if q % 2 == 0 or not prime_field.is_prime(q):
        raise ValueError("q must be an odd prime")


def _central_map(
    q: int, layers: Sequence[tuple[int, int]], n: int, rng: random.Random
) -> QuadraticMap:
    quadratic, linear, constant = [], [], []
    for v, o in layers:
        for _ in range(o):
            quad = [[0] * n for _ in range(n)]
            for i in range(v):
                for j in range(i, v + o):
                    quad[i][j] = rng.randrange(q)
            lin = [rng.randrange(q) if i < v + o else 0 for i in range(n)]
            quadratic.append(tuple(tuple(row) for row in quad))
            linear.append(tuple(lin))
            constant.append(rng.randrange(q))
    return QuadraticMap(q, tuple(quadratic), tuple(linear), tuple(constant))


def _keygen(q: int, layers: list[tuple[int, int]], mix: bool, seed: int) -> OilVinegarKeyPair:
    _validation.seed(seed)
    rng = random.Random(seed)
    n = layers[-1][0] + layers[-1][1]
    m = sum(o for _, o in layers)
    central = _central_map(q, layers, n, rng)
    s = prime_field.random_invertible(n, q, rng)
    identity = [[int(i == j) for j in range(m)] for i in range(m)]
    t = prime_field.random_invertible(m, q, rng) if mix else identity

    def public(x: list[int]) -> list[int]:
        return prime_field.mat_vec(t, list(central.evaluate(prime_field.mat_vec(s, x, q))), q)

    private = OilVinegarPrivateKey(
        q,
        tuple(layers),
        central,
        tuple(tuple(row) for row in s),
        tuple(tuple(row) for row in t),
    )
    return OilVinegarKeyPair(interpolate(public, n, q), private)


def uov_keygen(q: int, *, vinegar: int, oil: int, seed: int) -> OilVinegarKeyPair:
    """Generate a toy unbalanced oil and vinegar key over GF(q).

    Parameters
    ----------
    q : int
        An odd prime.
    vinegar, oil : int
        Numbers of vinegar and oil variables; the key has ``oil`` polynomials in
        ``vinegar + oil`` variables (Kipnis, Patarin and Goubin recommend
        ``vinegar >= 2 oil``).
    seed : int
        Seed for the central map and ``S``.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.uov_keygen(7, vinegar=6, oil=3, seed=2026)
    >>> signature = pqc.oil_vinegar_sign(keys.private, b"hello", seed=1)
    >>> pqc.oil_vinegar_verify(keys.public, b"hello", signature)
    True
    """
    _check_field(q)
    _validation.integer(vinegar, "vinegar", minimum=1)
    _validation.integer(oil, "oil", minimum=1)
    return _keygen(q, [(vinegar, oil)], False, seed)


def rainbow_keygen(q: int, v1: int, o1: int, o2: int, *, seed: int) -> OilVinegarKeyPair:
    """Generate a toy two-layer Rainbow key over GF(q).

    Layer 1 has ``o1`` polynomials in the first ``v1 + o1`` variables; layer 2 has
    ``o2`` polynomials in all ``n = v1 + o1 + o2`` variables, with the first
    ``v1 + o1`` as vinegars.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.rainbow_keygen(7, 3, 2, 2, seed=2026)
    >>> signature = pqc.oil_vinegar_sign(keys.private, b"hello", seed=1)
    >>> pqc.oil_vinegar_verify(keys.public, b"hello", signature)
    True
    """
    _check_field(q)
    _validation.integer(v1, "v1", minimum=1)
    _validation.integer(o1, "o1", minimum=1)
    _validation.integer(o2, "o2", minimum=1)
    return _keygen(q, [(v1, o1), (v1 + o1, o2)], True, seed)


def _digest(message: bytes, m: int, q: int) -> list[int]:
    """Hash to GF(q)^m with SHAKE-256 (two bytes per element; the bias is a toy's)."""
    data = hashlib.shake_256(message).digest(2 * m)
    return [int.from_bytes(data[2 * i : 2 * i + 2], "big") % q for i in range(m)]


def oil_vinegar_sign(
    private: OilVinegarPrivateKey, message: bytes, *, seed: int
) -> tuple[int, ...]:
    """Sign by inverting the central map one layer at a time.

    Random vinegar values turn each layer into a linear system in its oils; when that
    system has no solution, signing starts again with new vinegars.
    """
    _validation.byte_string(message, "message")
    _validation.seed(seed)
    q, central = private.q, private.central
    n, m = central.n_vars, central.n_polys
    rng = random.Random(seed)
    t_inverse = prime_field.inverse(private.t_matrix, q)
    s_inverse = prime_field.inverse(private.s_matrix, q)
    assert t_inverse is not None and s_inverse is not None  # invertible by construction
    target = prime_field.mat_vec(t_inverse, _digest(message, m, q), q)
    v1 = private.layers[0][0]
    while True:
        z = [rng.randrange(q) for _ in range(v1)] + [0] * (n - v1)
        first = 0
        for v, o in private.layers:
            rows = range(first, first + o)
            # With the oils of this layer at zero, the layer is linear in them.
            base = central.evaluate(z)
            a = [
                [
                    (
                        central.linear[k][j]
                        + sum(central.quadratic[k][i][j] * z[i] for i in range(v))
                    )
                    % q
                    for j in range(v, v + o)
                ]
                for k in rows
            ]
            oils, _ = prime_field.solve(a, [(target[k] - base[k]) % q for k in rows], o, q)
            if oils is None:
                break
            z[v : v + o] = oils
            first += o
        else:
            return tuple(prime_field.mat_vec(s_inverse, z, q))


def oil_vinegar_verify(public: QuadraticMap, message: bytes, signature: Sequence[int]) -> bool:
    """Check ``P(signature) == H(message)``."""
    _validation.byte_string(message, "message")
    if len(signature) != public.n_vars:
        raise ValueError(f"signature must have length {public.n_vars}")
    return list(public.evaluate(signature)) == _digest(message, public.n_polys, public.q)


def _row_space(a: Sequence[Sequence[int]], q: int) -> list[list[int]]:
    reduced, pivots = prime_field.rref(a, q, range(len(a[0])))
    return reduced[: len(pivots)]


def beullens_rainbow_attack(
    public: QuadraticMap, o2: int, *, seed: int, max_guesses: int = 1000
) -> RainbowBreakResult:
    """Recover the last-layer oil space ``O2`` of a toy Rainbow public key.

    Parameters
    ----------
    public : QuadraticMap
        A Rainbow public key over an odd prime field.
    o2 : int
        Size of the last layer.
    seed : int
        Seed for the random points ``x``.
    max_guesses : int, optional
        How many points ``x`` to try.

    Raises
    ------
    RuntimeError
        No kernel ``ker D_x`` met ``O2`` within ``max_guesses`` points.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.rainbow_keygen(7, 3, 2, 2, seed=2026)
    >>> len(pqc.beullens_rainbow_attack(keys.public, 2, seed=1).oil_subspace)
    2
    """
    _validation.integer(o2, "o2", minimum=1)
    _validation.seed(seed)
    _validation.integer(max_guesses, "max_guesses", minimum=1)
    q, n = public.q, public.n_vars
    forms = symmetric_forms(public)
    rng = random.Random(seed)
    evaluations = 0
    for guess in range(1, max_guesses + 1):
        x = [rng.randrange(q) for _ in range(n)]
        kernel = prime_field.nullspace(polar_matrix(forms, x, q), n, q)
        # Skip the all-zero combination, which itertools.product yields first.
        for coeffs in itertools.islice(itertools.product(range(q), repeat=len(kernel)), 1, None):
            y = [sum(c * k[i] for c, k in zip(coeffs, kernel, strict=True)) % q for i in range(n)]
            evaluations += 1
            d_y = polar_matrix(forms, y, q)
            # y^T M_k y = 2 P_h(y): the quadratic part of P vanishes on O2.
            if any(prime_field.mat_vec(d_y, y, q)) or prime_field.rank(d_y, q) > o2:
                continue
            w = _row_space([list(col) for col in zip(*d_y, strict=True)], q)
            # O2 = {z : D(e_i, z) in W for all i}: test D(e_i, z) against a basis of W-perp.
            w_perp = prime_field.nullspace(w, public.n_polys, q)
            equations = [
                [
                    sum(a * form[i][j] for a, form in zip(dual, forms, strict=True)) % q
                    for j in range(n)
                ]
                for dual in w_perp
                for i in range(n)
            ]
            oil = prime_field.nullspace(equations, n, q)
            return RainbowBreakResult(
                tuple(y),
                tuple(tuple(row) for row in oil),
                tuple(tuple(row) for row in w),
                guess,
                evaluations,
            )
    raise RuntimeError(f"no oil vector found in {max_guesses} guesses")
