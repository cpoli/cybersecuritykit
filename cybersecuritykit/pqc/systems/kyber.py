"""A Kyber-like key-encapsulation mechanism (CRYSTALS-Kyber 2018; FIPS 203, 2024).

J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M. Schanck,
P. Schwabe, G. Seiler and D. Stehlé, "CRYSTALS -- Kyber: a CCA-secure
module-lattice-based KEM", *IEEE EuroS&P 2018*, 353-367 (2018); standardized
as ML-KEM in NIST FIPS 203 (2024). Module-LWE sits between LWE and Ring-LWE: a
:math:`k \\times k` matrix of polynomials in :math:`R_q = \\mathbb{Z}_q[x]/(x^n
+ 1)`, :math:`q = 3329`. Keys and ciphertexts are compressed by dropping low
bits, and the Fujisaki-Okamoto transform turns the passively secure
encryption into a KEM secure against chosen ciphertexts: decapsulation
re-encrypts and, on any mismatch, returns a pseudorandom key derived from a
secret :math:`z` (implicit rejection).

This toy follows FIPS 203's structure and hash functions (SHA3-512 for
:math:`G`, SHA3-256 for :math:`H`, SHAKE-128 to expand :math:`A`, SHAKE-256
for the noise and for :math:`J`) but takes any power-of-two degree
:math:`n \\ge 8`, multiplies schoolbook instead of in the NTT domain, and
serializes polynomials as 2-byte integers, so its outputs are not FIPS 203
known answers.
"""

import hashlib
import random

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    KyberCiphertext,
    KyberEncapsulation,
    KyberFailureRate,
    KyberKeyPair,
    KyberPublicKey,
)
from cybersecuritykit.pqc.utils.rings import Poly, add, centered, poly_dot, power_of_two

__all__ = ["kyber_decapsulate", "kyber_encapsulate", "kyber_failure_rate", "kyber_keygen"]

Q = 3329
"""The Kyber prime."""

Vector = tuple[Poly, ...]


def _parameters(k: int) -> tuple[int, int, int, int]:
    """``(eta1, eta2, du, dv)`` of ML-KEM-512, -768 and -1024."""
    return (3 if k == 2 else 2, 2, *((11, 5) if k == 4 else (10, 4)))


def _sample_uniform(seed: bytes, n: int) -> Poly:
    """FIPS 203 SampleNTT: 12-bit rejection sampling from a SHAKE-128 stream."""
    length = 3 * n // 2
    while True:
        data = hashlib.shake_128(seed).digest(length)
        values = []
        for i in range(0, length, 3):
            b0, b1, b2 = data[i : i + 3]
            values += [b0 + 256 * (b1 % 16), b1 // 16 + 16 * b2]
        accepted = [d for d in values if d < Q]
        if len(accepted) >= n:
            return tuple(accepted[:n])
        length *= 2


def _cbd(sigma: bytes, nonce: int, eta: int, n: int) -> Poly:
    """Centered binomial noise from PRF(sigma, nonce) = SHAKE-256(sigma || nonce)."""
    data = hashlib.shake_256(sigma + bytes([nonce])).digest(eta * n // 4)
    bits = [(byte >> j) & 1 for byte in data for j in range(8)]
    return tuple(
        sum(bits[2 * i * eta : (2 * i + 1) * eta])
        - sum(bits[(2 * i + 1) * eta : (2 * i + 2) * eta])
        for i in range(n)
    )


def _matrix(rho: bytes, k: int, n: int) -> tuple[Vector, ...]:
    return tuple(tuple(_sample_uniform(rho + bytes([j, i]), n) for j in range(k)) for i in range(k))


def _compress(p: Poly, d: int) -> Poly:
    return tuple(((x << d) * 2 + Q) // (2 * Q) % (1 << d) for x in p)


def _decompress(p: Poly, d: int) -> Poly:
    return tuple((y * Q * 2 + (1 << d)) >> (d + 1) for y in p)


def _encode(polys: Vector) -> bytes:
    return b"".join(c.to_bytes(2, "big") for p in polys for c in p)


def _public_bytes(public: KyberPublicKey) -> bytes:
    return _encode(public.t) + public.rho


def _ciphertext_bytes(ciphertext: KyberCiphertext) -> bytes:
    return _encode((*ciphertext.u, ciphertext.v))


def _encrypt(
    public: KyberPublicKey, message: bytes, coins: bytes, eta: int | None = None
) -> KyberCiphertext:
    """K-PKE.Encrypt: the passively secure Module-LWE encryption.

    ``eta`` replaces both noise parameters, for :func:`kyber_failure_rate` only.
    """
    k, n = public.k, public.n
    eta1, eta2, du, dv = _parameters(k)
    if eta is not None:
        eta1 = eta2 = eta
    a = _matrix(public.rho, k, n)
    r = tuple(_cbd(coins, i, eta1, n) for i in range(k))
    e1 = tuple(_cbd(coins, k + i, eta2, n) for i in range(k))
    e2 = _cbd(coins, 2 * k, eta2, n)
    columns = tuple(tuple(a[j][i] for j in range(k)) for i in range(k))
    u = tuple(add(poly_dot(col, r, Q, -1), e, Q) for col, e in zip(columns, e1, strict=True))
    bits = [(byte >> j) & 1 for byte in message for j in range(8)]
    m = tuple((Q + 1) // 2 * b for b in bits)
    v = add(add(poly_dot(public.t, r, Q, -1), e2, Q), m, Q)
    return KyberCiphertext(tuple(_compress(p, du) for p in u), _compress(v, dv))


def _noisy_message(keypair: KyberKeyPair, ciphertext: KyberCiphertext) -> Poly:
    r""":math:`w = v - s^T u`: the message times :math:`\lceil q/2 \rfloor`, plus noise."""
    _, _, du, dv = _parameters(keypair.public.k)
    u = tuple(_decompress(p, du) for p in ciphertext.u)
    return tuple(
        (x - y) % Q
        for x, y in zip(_decompress(ciphertext.v, dv), poly_dot(keypair.s, u, Q, -1), strict=True)
    )


def _decrypt(keypair: KyberKeyPair, ciphertext: KyberCiphertext) -> bytes:
    """K-PKE.Decrypt: round :math:`v - s^T u` to the nearest multiple of :math:`q/2`."""
    bits = _compress(_noisy_message(keypair, ciphertext), 1)
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def _keypair(k: int, n: int, d: bytes, z: bytes, eta: int | None = None) -> KyberKeyPair:
    r"""K-PKE.KeyGen from the 32-byte seed ``d``; ``eta`` replaces :math:`\eta_1`."""
    digest = hashlib.sha3_512(d + bytes([k])).digest()
    rho, sigma = digest[:32], digest[32:]
    eta1 = _parameters(k)[0] if eta is None else eta
    a = _matrix(rho, k, n)
    s = tuple(_cbd(sigma, i, eta1, n) for i in range(k))
    e = tuple(_cbd(sigma, k + i, eta1, n) for i in range(k))
    t = tuple(add(poly_dot(row, s, Q, -1), ei, Q) for row, ei in zip(a, e, strict=True))
    return KyberKeyPair(KyberPublicKey(k, n, t, rho), s, z)


def _check_shape(k: int, n: int) -> None:
    _validation.integer(k, "k", minimum=2)
    if k > 4:
        raise ValueError("k must be 2, 3 or 4")
    power_of_two(n, "n", minimum=8)


def kyber_keygen(k: int = 2, n: int = 16, seed: int = DEFAULT_SEED) -> KyberKeyPair:
    r"""Generate a Kyber-like key pair, :math:`t = A s + e` with :math:`A` from :math:`\rho`.

    Parameters
    ----------
    k : int, optional
        Module rank 2, 3 or 4, as in ML-KEM-512, -768 and -1024; it fixes
        :math:`\eta_1` and the compression :math:`(d_u, d_v)`.
    n : int, optional
        Ring degree, a power of two from 8 (FIPS 203 uses 256).
    seed : int, optional
        Seed of the 32-byte randomness :math:`d` and :math:`z`.

    Returns
    -------
    KyberKeyPair

    Raises
    ------
    ValueError
        ``k`` outside 2-4, or ``n`` not a power of two at least 8.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.kyber_keygen(2, 16, seed=1)
    >>> len(keys.public.t), len(keys.public.t[0])
    (2, 16)
    """
    _check_shape(k, n)
    _validation.seed(seed)
    rng = random.Random(seed)
    d, z = rng.randbytes(32), rng.randbytes(32)
    return _keypair(k, n, d, z)


def kyber_encapsulate(public: KyberPublicKey, seed: int = DEFAULT_SEED) -> KyberEncapsulation:
    r"""Encapsulate: :math:`(K, r) = G(m \,\|\, H(\mathrm{ek}))`, encrypt with coins :math:`r`.

    Parameters
    ----------
    public : KyberPublicKey
        The recipient's encapsulation key.
    seed : int, optional
        Seed of the :math:`n`-bit message :math:`m`.

    Returns
    -------
    KyberEncapsulation

    Raises
    ------
    TypeError
        ``public`` is not a :class:`~cybersecuritykit.pqc.core.base.KyberPublicKey`.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.kyber_keygen(seed=1)
    >>> sent = pqc.kyber_encapsulate(keys.public, seed=2)
    >>> pqc.kyber_decapsulate(keys, sent.ciphertext) == sent.shared_key
    True
    """
    if not isinstance(public, KyberPublicKey):
        raise TypeError("public must be a KyberPublicKey")
    _validation.seed(seed)
    message = random.Random(seed).randbytes(public.n // 8)
    digest = hashlib.sha3_512(message + hashlib.sha3_256(_public_bytes(public)).digest()).digest()
    return KyberEncapsulation(_encrypt(public, message, digest[32:]), digest[:32])


def kyber_decapsulate(keypair: KyberKeyPair, ciphertext: KyberCiphertext) -> bytes:
    r"""Decapsulate with the Fujisaki-Okamoto check and implicit rejection.

    Decrypt to :math:`m'`, recompute :math:`(K', r') = G(m' \,\|\, H(\mathrm{ek}))`
    and re-encrypt. A ciphertext that does not match exactly yields
    :math:`J(z \,\|\, c)` instead, a key the attacker cannot predict.

    Parameters
    ----------
    keypair : KyberKeyPair
        The decapsulation key.
    ciphertext : KyberCiphertext
        The received ciphertext.

    Returns
    -------
    bytes
        The 32-byte shared key, or the rejection key.

    Raises
    ------
    TypeError
        Arguments of the wrong type.
    ValueError
        A ciphertext of the wrong shape.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.kyber_keygen(seed=1)
    >>> sent = pqc.kyber_encapsulate(keys.public, seed=2)
    >>> forged = pqc.KyberCiphertext(sent.ciphertext.u, (0,) * 16)
    >>> pqc.kyber_decapsulate(keys, forged) == sent.shared_key
    False
    """
    if not isinstance(keypair, KyberKeyPair):
        raise TypeError("keypair must be a KyberKeyPair")
    if not isinstance(ciphertext, KyberCiphertext):
        raise TypeError("ciphertext must be a KyberCiphertext")
    public = keypair.public
    if len(ciphertext.u) != public.k or any(
        len(p) != public.n for p in (*ciphertext.u, ciphertext.v)
    ):
        raise ValueError("ciphertext must hold k + 1 polynomials of degree n")
    message = _decrypt(keypair, ciphertext)
    digest = hashlib.sha3_512(message + hashlib.sha3_256(_public_bytes(public)).digest()).digest()
    if _encrypt(public, message, digest[32:]) == ciphertext:
        return digest[:32]
    return hashlib.shake_256(keypair.z + _ciphertext_bytes(ciphertext)).digest(32)


def kyber_failure_rate(
    k: int = 2,
    n: int = 16,
    eta: int | None = None,
    trials: int = 100,
    seed: int = DEFAULT_SEED,
) -> KyberFailureRate:
    r"""Measure how often the Kyber-like encryption decrypts to the wrong message.

    Decryption computes :math:`w = v - s^T u = \lceil q/2 \rfloor m + d` with
    the noise :math:`d = e^T r - s^T e_1 + e_2` plus the compression errors, and
    a bit flips when :math:`|d_i| > q/4`. Each trial draws a fresh key pair,
    message and coins and counts the bits that flip. The real parameters make a
    failure so rare (about :math:`2^{-139}` for ML-KEM-512) that no simulation
    sees one; raising ``eta`` widens the noise until failures are measurable,
    which is why the standard fixes :math:`\eta` and the compression together.

    Parameters
    ----------
    k : int, optional
        Module rank 2, 3 or 4; it fixes the compression :math:`(d_u, d_v)`.
    n : int, optional
        Ring degree, a power of two from 8.
    eta : int, optional
        Replaces :math:`\eta_1` and :math:`\eta_2` in every noise draw;
        ``None`` keeps the standard values for ``k``.
    trials : int, optional
        Key pairs and messages to try.
    seed : int, optional
        Seed of every trial's key and message randomness.

    Returns
    -------
    KyberFailureRate

    Raises
    ------
    ValueError
        A bad ``k`` or ``n``, ``eta`` below 1, or no trials.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.kyber_failure_rate(trials=20, seed=1).failures
    0
    >>> pqc.kyber_failure_rate(n=64, eta=32, trials=50, seed=1).failures > 0
    True
    """
    _check_shape(k, n)
    if eta is not None:
        _validation.integer(eta, "eta", minimum=1)
    _validation.integer(trials, "trials", minimum=1)
    _validation.seed(seed)
    eta1, eta2, du, dv = _parameters(k)
    if eta is not None:
        eta1 = eta2 = eta
    rng = random.Random(seed)
    failures = bit_errors = largest = 0
    for _ in range(trials):
        keypair = _keypair(k, n, rng.randbytes(32), b"", eta)
        message = rng.randbytes(n // 8)
        ciphertext = _encrypt(keypair.public, message, rng.randbytes(32), eta)
        bits = [(byte >> j) & 1 for byte in message for j in range(8)]
        noise = [
            centered(w - (Q + 1) // 2 * b, Q)
            for w, b in zip(_noisy_message(keypair, ciphertext), bits, strict=True)
        ]
        largest = max(largest, *(abs(d) for d in noise))
        decrypted = _decrypt(keypair, ciphertext)
        flipped = sum(bin(x ^ y).count("1") for x, y in zip(message, decrypted, strict=True))
        bit_errors += flipped
        failures += flipped > 0
    return KyberFailureRate(
        k,
        n,
        eta1,
        eta2,
        du,
        dv,
        trials,
        failures,
        bit_errors,
        failures / trials,
        bit_errors / (trials * n),
        largest,
    )
