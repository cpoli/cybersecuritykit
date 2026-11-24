"""Shor's period finding and factoring on a simulated state vector (1994).

P. W. Shor, "Algorithms for quantum computation: discrete logarithms and
factoring", *Proceedings of the 35th Annual Symposium on Foundations of
Computer Science*, 124-134 (1994); journal version *SIAM J. Comput.* 26(5),
1484-1509 (1997). Factoring :math:`n` reduces to finding the order :math:`r`
of a random :math:`a` mod :math:`n`: if :math:`r` is even and
:math:`a^{r/2} \\not\\equiv -1`, then :math:`\\gcd(a^{r/2} \\pm 1, n)` are
factors. A quantum computer prepares :math:`\\sum_x |x\\rangle |a^x \\bmod
n\\rangle` over :math:`Q = 2^m \\ge n^2` values of :math:`x`; the quantum
Fourier transform of the first register then peaks near multiples of
:math:`Q/r`, and continued fractions turn one measured :math:`y` into a
divisor of :math:`r`.

This module computes the exact outcome distribution classically, one
fast Fourier transform per value of :math:`a^x`, which costs time
exponential in the number of qubits: :math:`n` is limited to below 64 and
the register to 14 qubits.
"""

import cmath
import math
import random
from fractions import Fraction

from cybersecuritykit import _validation
from cybersecuritykit.constants import DEFAULT_SEED
from cybersecuritykit.pqc.core.base import ShorResult
from cybersecuritykit.pqc.utils import prime_field

__all__ = ["shor_distribution", "shor_factor"]

MAX_QUBITS = 14
"""Largest simulated register: :math:`2^{14}` amplitudes."""

MAX_N = 63
"""Largest number :func:`shor_factor` accepts."""


def _fft(values: list[complex]) -> list[complex]:
    """Radix-2 Cooley-Tukey transform :math:`\\sum_x v_x e^{2 \\pi i x y / Q}`."""
    size = len(values)
    if size == 1:
        return values
    even, odd = _fft(values[0::2]), _fft(values[1::2])
    out = [0j] * size
    for k in range(size // 2):
        twiddle = cmath.exp(2j * math.pi * k / size) * odd[k]
        out[k] = even[k] + twiddle
        out[k + size // 2] = even[k] - twiddle
    return out


def _check_base(n: int, base: int) -> None:
    _validation.integer(n, "n", minimum=3)
    _validation.integer(base, "base", minimum=2)
    if base >= n or math.gcd(base, n) != 1:
        raise ValueError("base must lie in [2, n - 1] and be coprime to n")


def shor_distribution(n: int, base: int, qubits: int) -> tuple[float, ...]:
    r"""Probabilities of each outcome :math:`y` after the quantum Fourier transform.

    Measuring the second register leaves :math:`\sum_{x : a^x = f} |x\rangle`;
    averaged over the values :math:`f`,

    .. math::

        P(y) = \sum_f \Bigl| \frac{1}{Q} \sum_{x : a^x \equiv f} e^{2 \pi i x y / Q} \Bigr|^2 .

    Parameters
    ----------
    n : int
        The modulus.
    base : int
        :math:`a`, coprime to :math:`n`, in :math:`[2, n - 1]`.
    qubits : int
        Size :math:`m` of the first register, 1 to 14; :math:`Q = 2^m`.

    Returns
    -------
    tuple of float
        :math:`Q` probabilities summing to 1.

    Raises
    ------
    ValueError
        A base that shares a factor with :math:`n`, or a register out of range.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> p = pqc.shor_distribution(15, 7, 4)
    >>> [round(x, 3) for x in p]
    [0.25, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0]
    """
    _check_base(n, base)
    _validation.integer(qubits, "qubits", minimum=1)
    if qubits > MAX_QUBITS:
        raise ValueError(f"qubits must be at most {MAX_QUBITS}")
    size = 1 << qubits
    classes: dict[int, list[complex]] = {}
    value = 1
    for x in range(size):
        classes.setdefault(value, [0j] * size)[x] = 1
        value = value * base % n
    probabilities = [0.0] * size
    for indicator in classes.values():
        for y, amplitude in enumerate(_fft(indicator)):
            probabilities[y] += abs(amplitude / size) ** 2
    return tuple(probabilities)


def shor_factor(
    n: int,
    seed: int = DEFAULT_SEED,
    base: int | None = None,
    qubits: int | None = None,
    shots: int = 10,
) -> ShorResult:
    r"""Factor :math:`n` by quantum period finding and classical post-processing.

    Each shot measures :math:`y`; the convergent of :math:`y / Q` with
    denominator at most :math:`n` gives a divisor of :math:`r`, and the
    least common multiple of the divisors grows until :math:`a^L \equiv 1`.
    The order is then the least divisor :math:`r` of :math:`L` with
    :math:`a^r \equiv 1`.

    Parameters
    ----------
    n : int
        An odd composite below 64 that is not a prime power (the cases the
        quantum step is needed for).
    seed : int, optional
        Seed of the base (when not given) and of the measurements.
    base : int, optional
        :math:`a`, coprime to :math:`n`; drawn at random when omitted.
    qubits : int, optional
        Register size; defaults to :math:`2 \lceil \log_2 n \rceil`, so :math:`Q \ge n^2`.
    shots : int, optional
        Most measurements to take.

    Returns
    -------
    ShorResult

    Raises
    ------
    ValueError
        ``n`` even, prime, a prime power or too large; a bad base; no shots.

    Examples
    --------
    >>> from cybersecuritykit import pqc
    >>> result = pqc.shor_factor(15, base=7, seed=1)
    >>> result.period, result.factors
    (4, (3, 5))
    """
    _validation.integer(n, "n", minimum=3)
    if n % 2 == 0 or n > MAX_N or prime_field.prime_power_base(n) is not None:
        raise ValueError(f"n must be an odd composite below {MAX_N + 1} that is not a prime power")
    _validation.integer(shots, "shots", minimum=1)
    _validation.seed(seed)
    rng = random.Random(seed)
    if base is None:
        base = rng.choice([a for a in range(2, n) if math.gcd(a, n) == 1])
    if qubits is None:
        qubits = 2 * math.ceil(math.log2(n))
    distribution = shor_distribution(n, base, qubits)
    size = 1 << qubits
    measurements: list[int] = []
    period = None
    multiple = 1
    for _ in range(shots):
        y = rng.choices(range(size), weights=distribution)[0]
        measurements.append(y)
        multiple = math.lcm(multiple, Fraction(y, size).limit_denominator(n).denominator)
        if pow(base, multiple, n) == 1:
            period = min(
                d for d in range(1, multiple + 1) if multiple % d == 0 and pow(base, d, n) == 1
            )
            break
    factors = None
    if period is not None and period % 2 == 0 and pow(base, period // 2, n) != n - 1:
        p = math.gcd(pow(base, period // 2, n) - 1, n)
        factors = (p, n // p) if p < n // p else (n // p, p)
    return ShorResult(n, base, qubits, period, factors, tuple(measurements), distribution)
