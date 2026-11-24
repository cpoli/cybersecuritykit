"""Ring learning with errors and LPR encryption (2010).

V. Lyubashevsky, C. Peikert and O. Regev, "On ideal lattices and learning with
errors over rings", *EUROCRYPT 2010*, LNCS 6110, 1-23 (2010). Replace the
random matrix of LWE by multiplication with one random polynomial :math:`a` in
:math:`R_q = \\mathbb{Z}_q[x]/(x^n + 1)`, :math:`n` a power of two: a sample is
:math:`b = a s + e` with small :math:`s` and :math:`e`. The public key shrinks
from :math:`n^2` numbers to :math:`n`, products cost :math:`O(n \\log n)` with
the number-theoretic transform, and the paper proves the search and decision
problems as hard as worst-case problems on ideal lattices.

The encryption is the one of the paper: :math:`u = a r + e_1`,
:math:`v = b r + e_2 + \\lfloor q/2 \\rfloor m`, and
:math:`v - u s = e r - e_1 s + e_2 + \\lfloor q/2 \\rfloor m` reveals the
:math:`n` message bits. Products here are schoolbook, not NTT.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import RingLWECiphertext, RingLWEKeyPair, RingLWEPublicKey
from cybersecuritykit.pqc.utils.rings import (
    Poly,
    add,
    binomial,
    centered,
    int_vector,
    multiply,
    power_of_two,
    subtract,
    uniform,
)

__all__ = ["ring_lwe_decrypt", "ring_lwe_encrypt", "ring_lwe_keygen"]


def ring_lwe_keygen(n: int, q: int, eta: int = 1, seed: int = DEFAULT_SEED) -> RingLWEKeyPair:
    """Draw :math:`a` uniform and :math:`s, e` centered binomial; publish :math:`b = a s + e`.

    Parameters
    ----------
    n : int
        Ring degree, a power of two, at least 2.
    q : int
        Modulus, at least 2.
    eta : int, optional
        Width of the secret and error distribution :math:`[-\\eta, \\eta]`.
    seed : int, optional
        Seed of every random polynomial.

    Returns
    -------
    RingLWEKeyPair

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ring_lwe_keygen(16, 257, seed=1)
    >>> len(keys.public.a), len(keys.public.b)
    (16, 16)
    """
    power_of_two(n, "n", minimum=2)
    _validation.integer(q, "q", minimum=2)
    _validation.integer(eta, "eta")
    _validation.seed(seed)
    rng = random.Random(seed)
    a = uniform(rng, n, q)
    s = binomial(rng, n, eta)
    e = binomial(rng, n, eta)
    return RingLWEKeyPair(RingLWEPublicKey(n, q, a, add(multiply(a, s, q, -1), e, q)), s)


def ring_lwe_encrypt(
    public: RingLWEPublicKey, bits: Sequence[int], seed: int = DEFAULT_SEED
) -> RingLWECiphertext:
    r"""Encrypt :math:`n` bits as :math:`(u, v) = (a r + e_1,\; b r + e_2 + \lfloor q/2 \rfloor m)`.

    :math:`r, e_1, e_2` are ternary (centered binomial with :math:`\eta = 1`).

    Parameters
    ----------
    public : RingLWEPublicKey
        The recipient's key.
    bits : sequence of int
        :math:`n` bits, the coefficients of :math:`m`.
    seed : int, optional
        Seed of :math:`r, e_1, e_2`.

    Returns
    -------
    RingLWECiphertext

    Raises
    ------
    TypeError
        ``public`` is not a :class:`~cybersecuritykit.pqc.core.base.RingLWEPublicKey`.
    ValueError
        A message of the wrong length or with entries other than 0 and 1.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.ring_lwe_keygen(8, 257, seed=1)
    >>> m = (1, 0, 1, 1, 0, 0, 1, 0)
    >>> pqc.ring_lwe_decrypt(keys, pqc.ring_lwe_encrypt(keys.public, m, seed=2)) == m
    True
    """
    if not isinstance(public, RingLWEPublicKey):
        raise TypeError("public must be a RingLWEPublicKey")
    m = int_vector(bits, "bits", public.n)
    if any(x not in (0, 1) for x in m):
        raise ValueError("bits must be 0 or 1")
    _validation.seed(seed)
    rng = random.Random(seed)
    n, q = public.n, public.q
    r, e1, e2 = binomial(rng, n, 1), binomial(rng, n, 1), binomial(rng, n, 1)
    u = add(multiply(public.a, r, q, -1), e1, q)
    v = add(add(multiply(public.b, r, q, -1), e2, q), tuple(q // 2 * x for x in m), q)
    return RingLWECiphertext(u, v)


def ring_lwe_decrypt(keypair: RingLWEKeyPair, ciphertext: RingLWECiphertext) -> Poly:
    """Decrypt: each coefficient of :math:`v - u s` near :math:`q/2` is a 1.

    Parameters
    ----------
    keypair : RingLWEKeyPair
        The private key.
    ciphertext : RingLWECiphertext
        The ciphertext.

    Returns
    -------
    tuple of int
        The :math:`n` bits; wrong where the noise exceeds :math:`q/4`.

    Raises
    ------
    TypeError
        Arguments of the wrong type.
    ValueError
        Polynomials of the wrong length.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.RingLWEKeyPair(pqc.RingLWEPublicKey(2, 17, (0, 0), (0, 0)), (0, 1))
    >>> pqc.ring_lwe_decrypt(keys, pqc.RingLWECiphertext((3, 4), (4, 3)))
    (1, 0)
    """
    if not isinstance(keypair, RingLWEKeyPair):
        raise TypeError("keypair must be a RingLWEKeyPair")
    if not isinstance(ciphertext, RingLWECiphertext):
        raise TypeError("ciphertext must be a RingLWECiphertext")
    n, q = keypair.public.n, keypair.public.q
    if len(ciphertext.u) != n or len(ciphertext.v) != n:
        raise ValueError("ciphertext polynomials must have n coefficients")
    noisy = subtract(ciphertext.v, multiply(ciphertext.u, keypair.secret, q, -1), q)
    return tuple(int(abs(centered(x, q)) > q // 4) for x in noisy)
