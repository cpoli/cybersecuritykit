"""Arithmetic in GF(2^m) and in polynomials over it.

A field element is an ``int`` whose bit ``i`` is the coefficient of ``alpha^i`` in
the polynomial basis, reduced by a fixed primitive polynomial of degree ``m``.
A polynomial is a list of field elements, constant term first, with no trailing zeros
(the zero polynomial is ``[]``).
"""

__all__ = [
    "MODULI",
    "Poly",
    "gf_inv",
    "gf_mul",
    "gf_pow",
    "poly_add",
    "poly_deriv",
    "poly_divmod",
    "poly_eval",
    "poly_gcd",
    "poly_mul",
    "poly_scale",
]

# A primitive polynomial of each degree, bit i the coefficient of x^i (Lidl and Niederreiter,
# *Finite Fields*, table of primitive polynomials); for example 0b10011 is x^4 + x + 1.
MODULI = {
    2: 0b111,
    3: 0b1011,
    4: 0b10011,
    5: 0b100101,
    6: 0b1000011,
    7: 0b10001001,
    8: 0b100011101,
    9: 0b1000010001,
    10: 0b10000001001,
    11: 0b100000000101,
    12: 0b1000001010011,
}

Poly = list[int]


def gf_mul(a: int, b: int, m: int) -> int:
    """Carry-less multiplication of two elements of GF(2^m), reduced mod ``MODULI[m]``."""
    modulus = MODULI[m]
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if (a >> m) & 1:
            a ^= modulus
    return out


def gf_pow(a: int, e: int, m: int) -> int:
    """``a ** e`` in GF(2^m) by square and multiply, for ``e >= 0``."""
    out = 1
    while e:
        if e & 1:
            out = gf_mul(out, a, m)
        a = gf_mul(a, a, m)
        e >>= 1
    return out


def gf_inv(a: int, m: int) -> int:
    """Inverse of a non-zero element: ``a ** (2^m - 2)``."""
    return gf_pow(a, 2**m - 2, m)


def _trim(p: Poly) -> Poly:
    while p and not p[-1]:
        p.pop()
    return p


def poly_add(p: Poly, q: Poly) -> Poly:
    """Sum (and difference) of two polynomials in characteristic 2."""
    out = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        out[i] = c
    for i, c in enumerate(q):
        out[i] ^= c
    return _trim(out)


def poly_scale(p: Poly, c: int, m: int) -> Poly:
    """``c * p`` for a field element ``c``."""
    return _trim([gf_mul(c, x, m) for x in p])


def poly_mul(p: Poly, q: Poly, m: int) -> Poly:
    """Product of two polynomials."""
    out = [0] * max(len(p) + len(q) - 1, 0)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            out[i + j] ^= gf_mul(a, b, m)
    return _trim(out)


def poly_divmod(p: Poly, d: Poly, m: int) -> tuple[Poly, Poly]:
    """Quotient and remainder of ``p`` by a non-zero ``d``."""
    rem = list(p)
    quotient = [0] * max(len(p) - len(d) + 1, 0)
    lead = gf_inv(d[-1], m)
    while len(rem) >= len(d):
        c = gf_mul(rem[-1], lead, m)
        shift = len(rem) - len(d)
        quotient[shift] = c
        for i, x in enumerate(d):
            rem[shift + i] ^= gf_mul(c, x, m)
        _trim(rem)
    return _trim(quotient), rem


def poly_eval(p: Poly, x: int, m: int) -> int:
    """Value of ``p`` at ``x`` by Horner's rule."""
    out = 0
    for c in reversed(p):
        out = gf_mul(out, x, m) ^ c
    return out


def poly_deriv(p: Poly) -> Poly:
    """Formal derivative; in characteristic 2 only odd powers survive."""
    return _trim([c if i % 2 else 0 for i, c in enumerate(p)][1:])


def poly_gcd(p: Poly, q: Poly, m: int) -> Poly:
    """Monic greatest common divisor of ``p`` and a polynomial ``q``."""
    while q:
        p, q = q, poly_divmod(p, q, m)[1]
    return poly_scale(p, gf_inv(p[-1], m), m)
