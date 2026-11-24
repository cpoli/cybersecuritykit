"""Regev's learning with errors and public-key encryption (2005).

O. Regev, "On lattices, learning with errors, random linear codes, and
cryptography", *Proceedings of the 37th ACM Symposium on Theory of Computing*,
84-93 (2005). Given many samples :math:`(a_i, b_i = \\langle a_i, s \\rangle +
e_i \\bmod q)` with small errors :math:`e_i`, recover :math:`s`. Without the
errors this is linear algebra; with them Regev showed it is as hard, for a
quantum algorithm, as approximating short vectors in every lattice. The
samples form a public key: a bit is encrypted by summing a random subset of
them and adding :math:`\\lfloor q/2 \\rfloor` for a 1.

The errors here come from the centered binomial distribution of Kyber rather
than Regev's discrete Gaussian; both keep each :math:`e_i` small.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import LWEAttackResult, LWECiphertext, LWEKeyPair, LWEPublicKey
from cybersecuritykit.pqc.utils.rings import binomial, centered, int_vector, uniform

__all__ = ["lwe_decrypt", "lwe_encrypt", "lwe_gaussian_attack", "lwe_keygen"]


def lwe_keygen(n: int, m: int, q: int, eta: int = 2, seed: int = DEFAULT_SEED) -> LWEKeyPair:
    r"""Draw a secret :math:`s` and :math:`m` LWE samples as the public key.

    Parameters
    ----------
    n : int
        Dimension of the secret.
    m : int
        Number of samples.
    q : int
        Modulus, at least 2.
    eta : int, optional
        Errors are centered binomial in :math:`[-\eta, \eta]`; 0 removes them.
    seed : int, optional
        Seed of the matrix, the secret and the errors.

    Returns
    -------
    LWEKeyPair
        The secret is uniform mod :math:`q`, as in Regev's scheme.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lwe_keygen(4, 16, 97, seed=1)
    >>> len(keys.public.a), len(keys.secret)
    (16, 4)
    """
    _validation.integer(n, "n", minimum=1)
    _validation.integer(m, "m", minimum=1)
    _validation.integer(q, "q", minimum=2)
    _validation.integer(eta, "eta")
    _validation.seed(seed)
    rng = random.Random(seed)
    a = tuple(uniform(rng, n, q) for _ in range(m))
    secret = uniform(rng, n, q)
    errors = binomial(rng, m, eta)
    b = tuple((sum(x * s for x, s in zip(row, secret)) + e) % q for row, e in zip(a, errors))
    return LWEKeyPair(LWEPublicKey(n, q, a, b), secret)


def _public(public: LWEPublicKey) -> None:
    if not isinstance(public, LWEPublicKey):
        raise TypeError("public must be an LWEPublicKey")


def lwe_encrypt(
    public: LWEPublicKey,
    bit: int,
    seed: int = DEFAULT_SEED,
    subset: Sequence[int] | None = None,
) -> LWECiphertext:
    r"""Encrypt one bit: :math:`u = \sum_{i \in S} a_i`, :math:`v = \sum_{i \in S} b_i + \lfloor q/2 \rfloor \cdot \mathrm{bit}`.

    Parameters
    ----------
    public : LWEPublicKey
        The recipient's samples.
    bit : int
        0 or 1.
    seed : int, optional
        Seed of the random subset :math:`S`.
    subset : sequence of int, optional
        An explicit 0/1 indicator of :math:`S`, one entry per sample, overriding ``seed``.

    Returns
    -------
    LWECiphertext

    Raises
    ------
    TypeError
        ``public`` is not an :class:`LWEPublicKey`.
    ValueError
        A bit or subset entry other than 0 or 1, or a subset of the wrong length.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> public = pqc.LWEPublicKey(2, 17, ((1, 2), (3, 4), (5, 6)), (4, 8, 12))
    >>> pqc.lwe_encrypt(public, 1, subset=(1, 0, 1))
    LWECiphertext(u=(6, 8), v=7)
    """
    _public(public)
    _validation.integer(bit, "bit")
    if bit > 1:
        raise ValueError("bit must be 0 or 1")
    _validation.seed(seed)
    if subset is None:
        chosen = tuple(random.Random(seed).getrandbits(1) for _ in public.b)
    else:
        chosen = int_vector(subset, "subset", len(public.b))
        if any(x not in (0, 1) for x in chosen):
            raise ValueError("subset entries must be 0 or 1")
    q = public.q
    u = tuple(sum(row[j] for row, c in zip(public.a, chosen) if c) % q for j in range(public.n))
    v = (sum(b for b, c in zip(public.b, chosen) if c) + q // 2 * bit) % q
    return LWECiphertext(u, v)


def lwe_decrypt(keypair: LWEKeyPair, ciphertext: LWECiphertext) -> int:
    r"""Decrypt: 1 when :math:`v - \langle u, s \rangle` is nearer :math:`q/2` than 0.

    The difference is :math:`\sum_{i \in S} e_i + \lfloor q/2 \rfloor \cdot
    \mathrm{bit}`, so decryption is right while the summed error stays below
    :math:`q/4`.

    Parameters
    ----------
    keypair : LWEKeyPair
        The private key.
    ciphertext : LWECiphertext
        An encrypted bit.

    Returns
    -------
    int
        The bit.

    Raises
    ------
    TypeError
        Arguments of the wrong type.
    ValueError
        ``u`` of the wrong length.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lwe_keygen(4, 16, 97, seed=1)
    >>> pqc.lwe_decrypt(keys, pqc.lwe_encrypt(keys.public, 1, seed=5))
    1
    """
    if not isinstance(keypair, LWEKeyPair):
        raise TypeError("keypair must be an LWEKeyPair")
    if not isinstance(ciphertext, LWECiphertext):
        raise TypeError("ciphertext must be an LWECiphertext")
    if len(ciphertext.u) != keypair.public.n:
        raise ValueError("ciphertext has the wrong dimension")
    q = keypair.public.q
    d = centered(ciphertext.v - sum(u * s for u, s in zip(ciphertext.u, keypair.secret)), q)
    return int(abs(d) > q // 4)


def lwe_gaussian_attack(public: LWEPublicKey) -> LWEAttackResult:
    """Solve the first :math:`n` independent samples exactly, as if there were no error.

    Gaussian elimination mod a prime :math:`q` recovers :math:`s` at once
    when every :math:`e_i = 0`. With errors, the solution is wrong and fits
    few of the other samples: the noise is the whole of the security.

    Parameters
    ----------
    public : LWEPublicKey
        Samples with a prime modulus.

    Returns
    -------
    LWEAttackResult

    Raises
    ------
    TypeError
        ``public`` is not an :class:`LWEPublicKey`.
    ValueError
        :math:`q` is not prime, or fewer than :math:`n` samples are independent.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lwe_keygen(4, 12, 97, eta=0, seed=2)
    >>> pqc.lwe_gaussian_attack(keys.public).secret == keys.secret
    True
    """
    _public(public)
    n, q = public.n, public.q
    if any(q % d == 0 for d in range(2, int(q**0.5) + 1)):
        raise ValueError("q must be prime")
    rows = [[x % q for x in a] + [b % q] for a, b in zip(public.a, public.b)]
    for col in range(n):
        pivot = next((r for r in range(col, len(rows)) if rows[r][col]), None)
        if pivot is None:
            raise ValueError("fewer than n independent samples")
        rows[col], rows[pivot] = rows[pivot], rows[col]
        scale = pow(rows[col][col], -1, q)
        rows[col] = [x * scale % q for x in rows[col]]
        for r, row in enumerate(rows):
            if r != col and row[col]:
                factor = row[col]
                rows[r] = [(x - factor * y) % q for x, y in zip(row, rows[col])]
    secret = tuple(row[n] for row in rows[:n])
    consistent = sum(
        (sum(x * s for x, s in zip(a, secret)) - b) % q == 0 for a, b in zip(public.a, public.b)
    )
    return LWEAttackResult(secret, consistent)
