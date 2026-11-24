"""Lattice signatures by Fiat-Shamir with aborts (Lyubashevsky, 2009).

V. Lyubashevsky, "Fiat-Shamir with aborts: applications to lattice and
factoring-based signatures", *ASIACRYPT 2009*, LNCS 5912, 598-616 (2009); the
ring form here follows his "Lattice signatures without trapdoors",
*EUROCRYPT 2012*, LNCS 7237, 738-755 (2012), the ancestor of CRYSTALS-Dilithium
(ML-DSA, FIPS 204). The signer commits to :math:`w = a y_1 + y_2` for a fresh
mask :math:`y`, hashes :math:`w` and the message into a sparse challenge
:math:`c`, and answers :math:`z = y + c s`. Since :math:`z` is shifted by the
secret, its distribution would leak :math:`s`; the signer therefore *aborts*
and restarts whenever a coefficient of :math:`z` leaves :math:`[-(B-\\kappa),
B-\\kappa]`, which makes accepted :math:`z` exactly uniform there, whatever the
secret.

The toy uses one ring element instead of Dilithium's module, no rounding or
hints, and derives the challenge by seeding :class:`random.Random` with a
SHAKE-256 digest rather than by FIPS 204's SampleInBall.
"""

import hashlib
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    LyubashevskyKeyPair,
    LyubashevskyPublicKey,
    LyubashevskySignature,
    SignatureLeakage,
)
from cybersecuritykit.pqc.utils.rings import (
    Poly,
    add,
    centered,
    multiply,
    power_of_two,
    subtract,
    uniform,
)

__all__ = [
    "lyubashevsky_keygen",
    "lyubashevsky_leakage",
    "lyubashevsky_sign",
    "lyubashevsky_verify",
]


def _ternary(rng: random.Random, n: int) -> Poly:
    return tuple(rng.choice((-1, 0, 1)) for _ in range(n))


def _challenge(public: LyubashevskyPublicKey, w: Poly, message: bytes) -> Poly:
    """Hash :math:`w` and the message to a polynomial with ``kappa`` coefficients :math:`\\pm 1`."""
    width = (public.q.bit_length() + 7) // 8
    data = b"".join(x.to_bytes(width, "big") for x in w) + message
    rng = random.Random(int.from_bytes(hashlib.shake_256(data).digest(32), "big"))
    c = [0] * public.n
    for i in rng.sample(range(public.n), public.kappa):
        c[i] = rng.choice((-1, 1))
    return tuple(c)


def _commitment(public: LyubashevskyPublicKey, y1: Poly, y2: Poly) -> Poly:
    return add(multiply(public.a, y1, public.q, -1), y2, public.q)


def lyubashevsky_keygen(
    n: int = 16,
    q: int = 8380417,
    kappa: int = 4,
    bound: int | None = None,
    seed: int = DEFAULT_SEED,
) -> LyubashevskyKeyPair:
    r"""Draw ternary :math:`s_1, s_2` and publish :math:`t = a s_1 + s_2` mod :math:`x^n + 1`.

    Parameters
    ----------
    n : int, optional
        Ring degree, a power of two.
    q : int, optional
        Modulus; the default is Dilithium's prime :math:`2^{23} - 2^{13} + 1`.
    kappa : int, optional
        Challenge weight, at most ``n``; :math:`\|c s\|_\infty \le \kappa`.
    bound : int, optional
        Mask bound :math:`B > \kappa`; the default :math:`2 n \kappa` makes an
        attempt pass with probability about :math:`e^{-1}`.
    seed : int, optional
        Seed of :math:`a`, :math:`s_1` and :math:`s_2`.

    Returns
    -------
    LyubashevskyKeyPair

    Raises
    ------
    ValueError
        Parameters out of range, or :math:`q \le 2(B + \kappa)`.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lyubashevsky_keygen(16, seed=1)
    >>> keys.public.bound
    128
    """
    power_of_two(n, "n", minimum=2)
    _validation.integer(q, "q", minimum=2)
    _validation.integer(kappa, "kappa", minimum=1)
    if kappa > n:
        raise ValueError("kappa must be at most n")
    b = 2 * n * kappa if bound is None else bound
    _validation.integer(b, "bound", minimum=kappa + 1)
    if q <= 2 * (b + kappa):
        raise ValueError("q must exceed 2 (bound + kappa)")
    _validation.seed(seed)
    rng = random.Random(seed)
    a = uniform(rng, n, q)
    s1, s2 = _ternary(rng, n), _ternary(rng, n)
    t = add(multiply(a, s1, q, -1), s2, q)
    return LyubashevskyKeyPair(LyubashevskyPublicKey(n, q, kappa, b, a, t), s1, s2)


def lyubashevsky_sign(
    keypair: LyubashevskyKeyPair, message: bytes, seed: int = DEFAULT_SEED, abort: bool = True
) -> LyubashevskySignature:
    r"""Sign: commit to :math:`w = a y_1 + y_2`, hash it to :math:`c`, answer :math:`z = y + c s`.

    Parameters
    ----------
    keypair : LyubashevskyKeyPair
        The signing key.
    message : bytes
        The message :math:`\mu`.
    seed : int, optional
        Seed of the masks :math:`y`.
    abort : bool, optional
        Restart while :math:`\|z\|_\infty > B - \kappa`. ``False`` keeps the
        first :math:`z`, which then leaks the secret (see
        :func:`lyubashevsky_leakage`) and may be rejected by the verifier.

    Returns
    -------
    LyubashevskySignature

    Raises
    ------
    TypeError
        A key or message of the wrong type.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lyubashevsky_keygen(16, seed=1)
    >>> signature = pqc.lyubashevsky_sign(keys, b"hello", seed=2)
    >>> pqc.lyubashevsky_verify(keys.public, b"hello", signature)
    True
    """
    if not isinstance(keypair, LyubashevskyKeyPair):
        raise TypeError("keypair must be a LyubashevskyKeyPair")
    _validation.byte_string(message, "message")
    _validation.seed(seed)
    public = keypair.public
    n, q, b = public.n, public.q, public.bound
    rng = random.Random(seed)
    attempts = 0
    while True:
        attempts += 1
        y1 = tuple(rng.randint(-b, b) for _ in range(n))
        y2 = tuple(rng.randint(-b, b) for _ in range(n))
        c = _challenge(public, _commitment(public, y1, y2), message)
        z1 = tuple(centered(x, q) for x in add(y1, multiply(c, keypair.s1, q, -1), q))
        z2 = tuple(centered(x, q) for x in add(y2, multiply(c, keypair.s2, q, -1), q))
        if not abort or max(map(abs, z1 + z2)) <= b - public.kappa:
            return LyubashevskySignature(z1, z2, c, attempts)


def lyubashevsky_verify(
    public: LyubashevskyPublicKey, message: bytes, signature: LyubashevskySignature
) -> bool:
    r"""Accept when :math:`\|z\|_\infty \le B - \kappa` and :math:`H(a z_1 + z_2 - t c, \mu) = c`.

    Parameters
    ----------
    public : LyubashevskyPublicKey
        The signer's key.
    message : bytes
        The signed message.
    signature : LyubashevskySignature
        The signature.

    Returns
    -------
    bool

    Raises
    ------
    TypeError
        Arguments of the wrong type.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lyubashevsky_keygen(16, seed=1)
    >>> signature = pqc.lyubashevsky_sign(keys, b"hello", seed=2)
    >>> pqc.lyubashevsky_verify(keys.public, b"goodbye", signature)
    False
    """
    if not isinstance(public, LyubashevskyPublicKey):
        raise TypeError("public must be a LyubashevskyPublicKey")
    _validation.byte_string(message, "message")
    if not isinstance(signature, LyubashevskySignature):
        raise TypeError("signature must be a LyubashevskySignature")
    z1, z2, c = signature.z1, signature.z2, signature.c
    if any(len(p) != public.n for p in (z1, z2, c)):
        return False
    if max(map(abs, z1 + z2)) > public.bound - public.kappa:
        return False
    q = public.q
    w = subtract(_commitment(public, z1, z2), multiply(public.t, c, q, -1), q)
    return _challenge(public, w, message) == c


def lyubashevsky_leakage(
    public: LyubashevskyPublicKey, signatures: Sequence[LyubashevskySignature]
) -> SignatureLeakage:
    r"""Estimate :math:`s_1` as the mean of :math:`c^* z_1 / \kappa` over many signatures.

    :math:`c^*(x) = c(x^{-1})` is the adjoint of multiplication by :math:`c`,
    and :math:`c^* c` has constant term :math:`\kappa`. Without aborts,
    :math:`\mathbb{E}[c^* z_1] = \mathbb{E}[c^* c]\, s_1 \approx \kappa s_1`,
    so the average converges to the secret. With aborts, :math:`z_1` is
    uniform whatever :math:`s_1` is, and the average tends to 0.

    Parameters
    ----------
    public : LyubashevskyPublicKey
        The signer's key.
    signatures : sequence of LyubashevskySignature
        Signatures by that key, at least one.

    Returns
    -------
    SignatureLeakage

    Raises
    ------
    TypeError
        A key or signature of the wrong type.
    ValueError
        No signatures.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lyubashevsky_keygen(8, kappa=2, bound=16, seed=4)
    >>> leaky = [pqc.lyubashevsky_sign(keys, b"m", seed=s, abort=False) for s in range(1500)]
    >>> pqc.lyubashevsky_leakage(keys.public, leaky).secret_guess == keys.s1
    True
    """
    if not isinstance(public, LyubashevskyPublicKey):
        raise TypeError("public must be a LyubashevskyPublicKey")
    if not signatures:
        raise ValueError("at least one signature is needed")
    n = public.n
    totals = [0] * n
    for signature in signatures:
        if not isinstance(signature, LyubashevskySignature):
            raise TypeError("signatures must be LyubashevskySignature objects")
        c = signature.c
        adjoint = (c[0],) + tuple(-c[n - i] for i in range(1, n))
        # Exact integer product: no modulus, the coefficients stay small.
        for i, x in enumerate(adjoint):
            for j, y in enumerate(signature.z1):
                k = i + j
                if k < n:
                    totals[k] += x * y
                else:
                    totals[k - n] -= x * y
    scale = public.kappa * len(signatures)
    estimate = tuple(x / scale for x in totals)
    guess = tuple(max(-1, min(1, round(x))) for x in estimate)
    return SignatureLeakage(estimate, guess, len(signatures))
