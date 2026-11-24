"""Ajtai's hash function from the short integer solution problem (1996).

M. Ajtai, "Generating hard instances of lattice problems", *Proceedings of the
28th ACM Symposium on Theory of Computing*, 99-108 (1996). A random matrix
:math:`A \\in \\mathbb{Z}_q^{n \\times m}` with :math:`m > n \\log_2 q` hashes a
bit vector :math:`x` to :math:`Ax \\bmod q`. A collision :math:`Ax = Ay` gives a
short nonzero :math:`z = x - y` with :math:`Az = 0`, a solution of SIS, and
Ajtai proved that solving random SIS instances is as hard as approximating
short vectors in *every* lattice of dimension :math:`n`.
"""

import math
import random
from collections.abc import Sequence

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import AjtaiKey, SISCollision

__all__ = ["ajtai_collision", "ajtai_hash", "ajtai_keygen"]


def ajtai_keygen(n: int, m: int, q: int, seed: int = DEFAULT_SEED) -> AjtaiKey:
    r"""Draw a uniformly random SIS matrix.

    Parameters
    ----------
    n : int
        Rows: the lattice dimension, and the length of a hash value.
    m : int
        Columns: the number of input bits, with :math:`2^m > q^n` so the hash compresses.
    q : int
        Modulus, at least 2.
    seed : int, optional
        Seed of the random matrix.

    Returns
    -------
    AjtaiKey

    Raises
    ------
    ValueError
        :math:`2^m \le q^n`, so the function need not have collisions.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.ajtai_keygen(2, 8, 11, seed=1)
    >>> len(key.matrix), len(key.matrix[0])
    (2, 8)
    """
    _validation.integer(n, "n", minimum=1)
    _validation.integer(m, "m", minimum=1)
    _validation.integer(q, "q", minimum=2)
    _validation.seed(seed)
    if m <= n * math.log2(q):
        raise ValueError("m must exceed n log2 q, or the hash does not compress")
    rng = random.Random(seed)
    return AjtaiKey(tuple(tuple(rng.randrange(q) for _ in range(m)) for _ in range(n)), q)


def _key(key: AjtaiKey) -> None:
    if not isinstance(key, AjtaiKey):
        raise TypeError("key must be an AjtaiKey")


def _hash(key: AjtaiKey, bits: Sequence[int]) -> tuple[int, ...]:
    return tuple(sum(a for a, x in zip(row, bits, strict=True) if x) % key.q for row in key.matrix)


def ajtai_hash(key: AjtaiKey, bits: Sequence[int]) -> tuple[int, ...]:
    r"""Hash a bit vector :math:`x \in \{0, 1\}^m` to :math:`Ax \bmod q`.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> pqc.ajtai_hash(pqc.AjtaiKey(((1, 2, 3), (4, 5, 6)), 7), (1, 0, 1))
    (4, 3)
    """
    _key(key)
    vector = tuple(bits)
    if len(vector) != len(key.matrix[0]):
        raise ValueError("bits must have one entry per column of the key")
    for x in vector:
        _validation.integer(x, "bit")
        if x > 1:
            raise ValueError("bits must be 0 or 1")
    return _hash(key, vector)


def ajtai_collision(key: AjtaiKey, limit: int = 1 << 16) -> SISCollision:
    """Find two inputs with the same hash by hashing bit vectors in counting order.

    There are only :math:`q^n` hash values, so by the pigeonhole principle a
    collision appears within the first :math:`q^n + 1` inputs. That bound is
    why the toy is easy: real parameters make :math:`q^n` astronomically large,
    and Ajtai's reduction shows that no shortcut exists unless short lattice
    vectors are easy to find.

    Parameters
    ----------
    key : AjtaiKey
        The hash key.
    limit : int, optional
        Inputs to hash before giving up, at least 2.

    Returns
    -------
    SISCollision

    Raises
    ------
    ValueError
        No collision among the first ``limit`` inputs.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> key = pqc.ajtai_keygen(2, 8, 11, seed=1)
    >>> z = pqc.ajtai_collision(key).difference
    >>> [sum(a * x for a, x in zip(row, z)) % 11 for row in key.matrix]
    [0, 0]
    """
    _key(key)
    _validation.integer(limit, "limit", minimum=2)
    m = len(key.matrix[0])
    seen: dict[tuple[int, ...], tuple[int, ...]] = {}
    for tested in range(1, min(limit, 1 << m) + 1):
        bits = tuple((tested - 1) >> i & 1 for i in range(m))
        value = _hash(key, bits)
        if value in seen:
            x = seen[value]
            return SISCollision(x, bits, tuple(a - b for a, b in zip(x, bits)), tested)
        seen[value] = bits
    raise ValueError("no collision among the inputs tried; raise limit")
