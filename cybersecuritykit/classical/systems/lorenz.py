"""The Lorenz SZ40 teleprinter cipher and Tutte's break (1942).

W. T. Tutte, "Fish and I" (lecture, University of Waterloo, 1998), and the
*General Report on Tunny* (1945, National Archives HW 25/4). The machine adds
two wheel streams, chi and psi, to each 5-bit teleprinter character. Only the
chi wheels move regularly, so in the delta (each bit plus the next) the key
repeats with each chi wheel's period, and Tutte found the 41 of chi 1 by
writing the stream out at trial widths.
"""

import random
from collections.abc import Iterable, Sequence

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import LorenzWheels, PeriodTest
from cybersecuritykit.constants import DEFAULT_SEED

__all__ = ["lorenz_keystream", "lorenz_wheels", "tutte_period_test"]

CHI_LENGTHS = (41, 31, 29, 26, 23)
PSI_LENGTHS = (43, 47, 51, 53, 59)
MOTOR_LENGTH = 61


def lorenz_wheels(seed: int = DEFAULT_SEED) -> LorenzWheels:
    """Draw random cam patterns for the chi, psi and motor wheels.

    The real machine had two motor wheels (37 and 61 cams); one stands in for
    both here. Cams are drawn independently, so roughly half are raised.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> [len(w) for w in classical.lorenz_wheels(seed=1).chi]
    [41, 31, 29, 26, 23]
    """
    _validation.seed(seed)
    rng = random.Random(seed)

    def wheel(n: int) -> tuple[int, ...]:
        return tuple(rng.randrange(2) for _ in range(n))

    return LorenzWheels(
        tuple(wheel(n) for n in CHI_LENGTHS),
        tuple(wheel(n) for n in PSI_LENGTHS),
        wheel(MOTOR_LENGTH),
    )


def lorenz_keystream(wheels: LorenzWheels, length: int) -> tuple[int, ...]:
    """Return ``length`` 5-bit key characters, impulse 1 as the high bit.

    Each character is chi plus psi on every impulse. The chi and motor wheels
    step every character; the psi wheels step together when the motor shows 1.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> stream = classical.lorenz_keystream(classical.lorenz_wheels(seed=1), 5)
    >>> len(stream), max(stream) < 32
    (5, True)
    """
    if not isinstance(wheels, LorenzWheels):
        raise TypeError("wheels must be a LorenzWheels")
    _validation.integer(length, "length")
    out = []
    psi_at = 0
    for t in range(length):
        x = 0
        for chi, psi in zip(wheels.chi, wheels.psi, strict=True):
            x = x << 1 | (chi[t % len(chi)] ^ psi[psi_at % len(psi)])
        out.append(x)
        if wheels.motor[t % len(wheels.motor)]:
            psi_at += 1
    return tuple(out)


def tutte_period_test(bits: Sequence[int], periods: Iterable[int]) -> PeriodTest:
    """Measure, for each trial period, how often the delta stream repeats.

    Parameters
    ----------
    bits : sequence of int
        One impulse of a key stream, as 0s and 1s.
    periods : iterable of int
        Trial periods, each at least 1 and shorter than the delta stream.

    Returns
    -------
    PeriodTest
        Agreement for each period; random bits give about 0.5.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.tutte_period_test([0, 1, 1] * 20, [2, 3]).best_period
    3
    """
    if any(b not in (0, 1) or isinstance(b, bool) for b in bits):
        raise ValueError("bits must be 0s and 1s")
    delta = [a ^ b for a, b in zip(bits, bits[1:], strict=False)]
    tried = tuple(periods)
    if not tried:
        raise ValueError("periods must not be empty")
    for p in tried:
        _validation.integer(p, "period", minimum=1)
        if p >= len(delta):
            raise ValueError("every period must be shorter than the delta stream")
    agreement = tuple(
        sum(a == b for a, b in zip(delta, delta[p:], strict=False)) / (len(delta) - p)
        for p in tried
    )
    return PeriodTest(tried, agreement, tried[agreement.index(max(agreement))])
