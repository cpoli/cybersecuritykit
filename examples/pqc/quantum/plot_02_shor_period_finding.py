r"""
Shor's period finding (Shor, 1994)
==================================

Factoring :math:`N` reduces to finding the order :math:`r` of a random base
:math:`a` modulo :math:`N`: if :math:`r` is even and
:math:`a^{r/2} \not\equiv -1`, then :math:`\gcd(a^{r/2} \pm 1, N)` are factors.
Peter Shor's quantum step puts a register of :math:`Q = 2^q` values in
superposition, computes :math:`a^x \bmod N`, and applies the quantum Fourier
transform. Measurement then lands near a multiple of :math:`Q / r`:

.. math::

   \Pr[y] = \frac{1}{Q^2} \sum_{c} \Bigl| \sum_{x : a^x \equiv c}
   e^{2 \pi i x y / Q} \Bigr|^2, \qquad \frac{y}{Q} \approx \frac{k}{r}.

Continued fractions turn :math:`y / Q` into :math:`k / r`. The same idea
solves discrete logarithms, which breaks RSA, Diffie-Hellman and elliptic
curves alike. Here the state vector is simulated exactly on a classical
computer.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_shor_distribution

pqc = csk.pqc

# %%
# Factoring 15
# ------------
# The base :math:`a = 7` has order 4 modulo 15, and :math:`7^2 \pm 1` are 48
# and 50, which share the factors 3 and 5 with 15.

result = pqc.shor_factor(15, base=7, seed=1)
print(result.period, result.factors, "from", result.measurements)
assert result.period == 4 and result.factors == (3, 5)
assert pow(7, 4, 15) == 1

# %%
# The distribution has :math:`r` peaks
# ------------------------------------
# With 8 qubits, :math:`Q / r = 64` exactly, so the four peaks are sharp.

peaks = [y for y, p in enumerate(result.distribution) if p > 1e-10]
print(peaks)
assert peaks == [0, 64, 128, 192]
assert abs(sum(result.distribution) - 1) < 1e-10

# %%
# Factoring 21
# ------------
# Here :math:`r = 6` does not divide :math:`Q = 1024`, so the peaks spread and
# continued fractions do the rounding.

other = pqc.shor_factor(21, base=2, seed=1)
print(other.period, other.factors)
assert other.period == 6 and other.factors == (3, 7)

ax = plot_shor_distribution(result)
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Run ``shor_factor(15, base=14)``: it finds period 2 but returns no
# factors. Explain why from :math:`14 \equiv -1 \pmod{15}`, and count the
# bases modulo 15 for which the classical post-processing succeeds.
#
# A worked solution is in :doc:`/exercises/pqc`.
