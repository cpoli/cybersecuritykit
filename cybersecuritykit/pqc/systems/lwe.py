"""Regev's learning with errors and public-key encryption (2005).

O. Regev, "On lattices, learning with errors, random linear codes, and
cryptography", *Proceedings of the 37th ACM Symposium on Theory of Computing*,
84-93 (2005). Given many samples :math:`(a_i, b_i = \\langle a_i, s \\rangle +
e_i \\bmod q)` with small errors :math:`e_i`, recover :math:`s`. Without the
errors this is linear algebra; with them Regev showed it is as hard, for a
quantum algorithm, as approximating short vectors in every lattice. The
samples form a public key: a bit is encrypted by summing a random subset of
them and adding :math:`\\lfloor q/2 \\rfloor` for a 1.

:func:`lwe_lattice_attack` follows the primal attack: Kannan's embedding
(R. Kannan, "Minkowski's convex body theorem and integer programming",
*Mathematics of Operations Research* 12, 415-440, 1987) turns the error into a
short lattice vector, and LLL finds it while the dimension is small.

The errors here come from the centered binomial distribution of Kyber rather
than Regev's discrete Gaussian; both keep each :math:`e_i` small.
"""

import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import (
    LWEAttackResult,
    LWECiphertext,
    LWEKeyPair,
    LWELatticeAttackResult,
    LWEPublicKey,
)
from cybersecuritykit.pqc.systems.lattice import lll_reduce
from cybersecuritykit.pqc.utils import prime_field
from cybersecuritykit.pqc.utils.rings import binomial, centered, dot, int_vector, uniform

__all__ = ["lwe_decrypt", "lwe_encrypt", "lwe_gaussian_attack", "lwe_keygen", "lwe_lattice_attack"]


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
    b = tuple((dot(row, secret) + e) % q for row, e in zip(a, errors, strict=True))
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
    r"""Encrypt a bit: :math:`(u, v) = (\sum_S a_i, \sum_S b_i + \lfloor q/2 \rfloor \mathrm{bit})`.

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
        ``public`` is not an :class:`~cybersecuritykit.pqc.core.base.LWEPublicKey`.
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
    u = tuple(
        sum(row[j] for row, c in zip(public.a, chosen, strict=True) if c) % q
        for j in range(public.n)
    )
    v = (sum(b for b, c in zip(public.b, chosen, strict=True) if c) + q // 2 * bit) % q
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
    d = centered(ciphertext.v - dot(ciphertext.u, keypair.secret), q)
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
        ``public`` is not an :class:`~cybersecuritykit.pqc.core.base.LWEPublicKey`.
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
    prime_field.check_prime(q, "q")
    rows = [[x % q for x in a] + [b % q] for a, b in zip(public.a, public.b, strict=True)]
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
                rows[r] = [(x - factor * y) % q for x, y in zip(row, rows[col], strict=True)]
    secret = tuple(row[n] for row in rows[:n])
    consistent = sum((dot(a, secret) - b) % q == 0 for a, b in zip(public.a, public.b, strict=True))
    return LWEAttackResult(secret, consistent)


def lwe_lattice_attack(public: LWEPublicKey) -> LWELatticeAttackResult:
    r"""Recover the secret of noisy LWE samples with Kannan's embedding and LLL.

    The vectors :math:`A s \bmod q` form the :math:`q`-ary lattice
    :math:`L(A)`, and :math:`b = A s + e` lies a short step :math:`e` from it.
    Writing :math:`A = (A_1; A_2)` with :math:`A_1` the first :math:`n` rows,
    :math:`L(A)` has the basis :math:`\begin{pmatrix} I & C^T \\ 0 & qI
    \end{pmatrix}` with :math:`C = A_2 A_1^{-1}`. Appending the row
    :math:`(b, 1)` and a zero last column embeds the closest vector problem in
    a shortest vector problem:

    .. math::

        (b, 1) - (A s \bmod q, 0) = (e, 1)

    is unusually short, so LLL tends to put :math:`\pm(e, 1)` in the reduced
    basis. The shortest reduced row with last coordinate :math:`\pm 1` is
    read as :math:`(e, 1)`, and :math:`s = A_1^{-1}(b_1 - e_1)`. This works
    only while the dimension :math:`m + 1` is small: LLL's approximation factor
    grows like :math:`2^{m/2}`, and real parameters put :math:`e` far beyond
    what any reduction finds.

    Parameters
    ----------
    public : LWEPublicKey
        Samples with a prime modulus whose first :math:`n` rows are independent.

    Returns
    -------
    LWELatticeAttackResult
        ``secret`` and ``error`` are ``None`` when no reduced row has last
        coordinate :math:`\pm 1`. With too few samples for the noise, a
        different secret with an even shorter error can come back instead.

    Raises
    ------
    TypeError
        ``public`` is not an :class:`~cybersecuritykit.pqc.core.base.LWEPublicKey`.
    ValueError
        :math:`q` is not prime, or the first :math:`n` samples are dependent.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> keys = pqc.lwe_keygen(4, 16, 97, seed=1)
    >>> pqc.lwe_gaussian_attack(keys.public).secret == keys.secret
    False
    >>> pqc.lwe_lattice_attack(keys.public).secret == keys.secret
    True
    """
    _public(public)
    n, q, a, b = public.n, public.q, public.a, public.b
    prime_field.check_prime(q, "q")
    m = len(b)
    inverse = prime_field.inverse(a[:n], q)
    if inverse is None:
        raise ValueError("the first n samples must be independent")
    columns = list(zip(*inverse, strict=True))
    c = [prime_field.mat_vec(columns, row, q) for row in a[n:]]
    basis = [
        tuple(int(i == j) for j in range(n)) + tuple(row[i] for row in c) + (0,) for i in range(n)
    ]
    basis += [(0,) * j + (q,) + (0,) * (m - j) for j in range(n, m)]
    basis.append(tuple(b) + (1,))
    reduction = lll_reduce(basis)
    rows = [row for row in reduction.basis if abs(row[-1]) == 1]
    if not rows:
        return LWELatticeAttackResult(None, None, m + 1, reduction.swaps)
    row = min(rows, key=lambda v: dot(v, v))
    error = tuple(row[-1] * x for x in row[:m])
    top = [y - e for y, e in zip(b[:n], error[:n], strict=True)]
    secret = tuple(prime_field.mat_vec(inverse, top, q))
    return LWELatticeAttackResult(secret, error, m + 1, reduction.swaps)
