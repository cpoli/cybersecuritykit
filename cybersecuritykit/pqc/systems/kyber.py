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
    KyberKeyPair,
    KyberPublicKey,
)
from cybersecuritykit.pqc.utils.rings import Poly, add, multiply, power_of_two

__all__ = ["kyber_decapsulate", "kyber_encapsulate", "kyber_keygen"]

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
        sum(bits[2 * i * eta : (2 * i + 1) * eta]) - sum(bits[(2 * i + 1) * eta : (2 * i + 2) * eta])
        for i in range(n)
    )


def _matrix(rho: bytes, k: int, n: int) -> tuple[Vector, ...]:
    return tuple(tuple(_sample_uniform(rho + bytes([j, i]), n) for j in range(k)) for i in range(k))


def _dot(a: Vector, b: Vector) -> Poly:
    total = (0,) * len(a[0])
    for x, y in zip(a, b):
        total = add(total, multiply(x, y, Q, -1), Q)
    return total


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


def _encrypt(public: KyberPublicKey, message: bytes, coins: bytes) -> KyberCiphertext:
    """K-PKE.Encrypt: the passively secure Module-LWE encryption."""
    k, n = public.k, public.n
    eta1, eta2, du, dv = _parameters(k)
    a =_matrix(public.rho, k, n)
    r = tuple(_cbd(coins, i, eta1, n) for i in range(k))
    e1 = tuple(_cbd(coins, k + i, eta2, n) for i in range(k))
    e2 = _cbd(coins, 2 * k, eta2, n)
    columns = tuple(tuple(a[j][i] for j in range(k)) for i in range(k))
    u = tuple(add(_dot(col, r), e, Q) for col, e in zip(columns, e1))
    bits = [(byte >> j) & 1 for byte in message for j in range(8)]
    m = tuple((Q + 1) // 2 * b for b in bits)
    v = add(add(_dot(public.t, r), e2, Q), m, Q)
    return KyberCiphertext(tuple(_compress(p, du) for p in u), _compress(v, dv))


def _decrypt(keypair: KyberKeyPair, ciphertext: KyberCiphertext) -> bytes:
    """K-PKE.Decrypt: round :math:`v - s^T u` to the nearest multiple of :math:`q/2`."""
    _, _, du, dv = _parameters(keypair.public.k)
    u = tuple(_decompress(p, du) for p in ciphertext.u)
    w = tuple((x - y) % Q for x, y in zip(_decompress(ciphertext.v, dv), _dot(keypair.s, u)))
    bits = _compress(w, 1)
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def kyber_keygen(k: int = 2, n: int = 16, seed: int = DEFAULT_SEED) -> KyberKeyPair:
    r"""Generate a Kyber-like key pair: :math:`t = A s + e` with :math:`A` expanded from :math:`\rho`.

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
    _validation.integer(k, "k", minimum=2)
    if k > 4:
        raise ValueError("k must be 2, 3 or 4")
    power_of_two(n, "n", minimum=8)
    _validation.seed(seed)
    rng = random.Random(seed)
    d, z = rng.randbytes(32), rng.randbytes(32)
    digest = hashlib.sha3_512(d + bytes([k])).digest()
    rho, sigma = digest[:32], digest[32:]
    eta1 = _parameters(k)[0]
    a = _matrix(rho, k, n)
    s = tuple(_cbd(sigma, i, eta1, n) for i in range(k))
    e = tuple(_cbd(sigma, k + i, eta1, n) for i in range(k))
    t = tuple(add(_dot(row, s), ei, Q) for row, ei in zip(a, e))
    return KyberKeyPair(KyberPublicKey(k, n, t, rho), s, z)


def kyber_encapsulate(public: KyberPublicKey, seed: int = DEFAULT_SEED) -> KyberEncapsulation:
    r"""Encapsulate: :math:`(K, r) = G(m \,\|\, H(\mathrm{ek}))`, then encrypt :math:`m` with coins :math:`r`.

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
        ``public`` is not a :class:`KyberPublicKey`.

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
