"""Integer vectors and polynomial rings for the lattice schemes of :mod:`cybersecuritykit.pqc`.

Polynomials are tuples of coefficients, constant term first. The cyclic ring
:math:`\\mathbb{Z}_q[x]/(x^n - 1)` is NTRU's; the negacyclic ring
:math:`\\mathbb{Z}_q[x]/(x^n + 1)` is the one of Ring-LWE, Kyber and the
Fiat-Shamir with aborts signature.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation

Poly = tuple[int, ...]

_SMALLEST = -(2**63)
"""Lower bound for signed entries: far beyond any toy coefficient, small enough to stay an int."""


def int_vector(values: Sequence[int], name: str, length: int | None = None) -> Poly:
    """Validate a sequence of signed integers, optionally of a given length."""
    vector = tuple(values)
    if length is not None and len(vector) != length:
        raise ValueError(f"{name} must have {length} entries")
    for x in vector:
        _validation.integer(x, name, minimum=_SMALLEST)
    return vector


def power_of_two(n: int, name: str, minimum: int) -> None:
    """Validate a power of two at least ``minimum``."""
    _validation.integer(n, name, minimum=minimum)
    if n & (n - 1):
        raise ValueError(f"{name} must be a power of two")


def centered(x: int, q: int) -> int:
    """Representative of ``x mod q`` in ``(-q/2, q/2]``."""
    x %= q
    return x - q if x > q // 2 else x


def multiply(a: Sequence[int], b: Sequence[int], q: int, sign: int) -> Poly:
    """Schoolbook product mod ``x^n - sign`` and ``q``: ``sign`` 1 is cyclic, -1 negacyclic."""
    n = len(a)
    out = [0] * n
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                k = i + j
                if k < n:
                    out[k] += x * y
                else:
                    out[k - n] += sign * x * y
    return tuple(c % q for c in out)


def add(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    """Coefficient-wise sum mod ``q``."""
    return tuple((x + y) % q for x, y in zip(a, b, strict=True))


def subtract(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    """Coefficient-wise difference mod ``q``."""
    return tuple((x - y) % q for x, y in zip(a, b, strict=True))


def uniform(rng: random.Random, n: int, q: int) -> Poly:
    """``n`` coefficients uniform in ``[0, q)``."""
    return tuple(rng.randrange(q) for _ in range(n))


def ternary(rng: random.Random, n: int, ones: int | None = None, minus: int | None = None) -> Poly:
    """``n`` coefficients in ``{-1, 0, 1}``.

    Uniform and independent by default; with ``ones`` and ``minus`` given, exactly
    that many 1s and -1s in a random order, as NTRU's fixed-weight polynomials.
    """
    if ones is None or minus is None:
        return tuple(rng.choice((-1, 0, 1)) for _ in range(n))
    coefficients = [1] * ones + [-1] * minus + [0] * (n - ones - minus)
    rng.shuffle(coefficients)
    return tuple(coefficients)


def dot(u: Sequence[int], v: Sequence[int]) -> int:
    """The integer inner product of two vectors of equal length."""
    return sum(x * y for x, y in zip(u, v, strict=True))


def poly_dot(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], q: int, sign: int) -> Poly:
    """Inner product of two vectors of polynomials, with products as in :func:`multiply`."""
    total: Poly = (0,) * len(a[0])
    for x, y in zip(a, b, strict=True):
        total = add(total, multiply(x, y, q, sign), q)
    return total


def binomial(rng: random.Random, n: int, eta: int) -> Poly:
    """``n`` coefficients from the centered binomial distribution of Kyber, in ``[-eta, eta]``."""
    return tuple(
        sum(rng.getrandbits(1) for _ in range(eta)) - sum(rng.getrandbits(1) for _ in range(eta))
        for _ in range(n)
    )
