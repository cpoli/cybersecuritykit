r"""
Grover's search (Grover, 1996)
==============================

Lov Grover found a quantum search over :math:`N` items that needs only about
:math:`\sqrt{N}` oracle calls. Each iteration flips the sign of the marked
items and then reflects every amplitude about the mean, which rotates the
state by :math:`2\theta` towards the marked items:

.. math::

   \Pr[\text{success after } k] = \sin^2\bigl((2k + 1)\theta\bigr),
   \qquad \sin \theta = \sqrt{M / N}.

The best :math:`k` is about :math:`\tfrac{\pi}{4}\sqrt{N/M}`, and Bennett,
Bernstein, Brassard and Vazirani proved no quantum algorithm does better. A
:math:`b`-bit key search falls to :math:`2^{b/2}` steps, which is why
AES-256 is the post-quantum choice.
"""

# %%
import math

import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_grover_success

pqc = csk.pqc

# %%
# Searching 256 items
# -------------------
# Twelve iterations find item 42 among :math:`2^8` with probability above
# 0.999, against 1/256 for a single guess.

result = pqc.grover_search(8, [42], seed=1)
print(result.iterations, "iterations, measured", result.measured)
assert result.iterations == 12 and result.found and result.measured == 42

# %%
# The simulation follows the rotation
# -----------------------------------
# Every point of the state-vector run matches :math:`\sin^2((2k+1)\theta)`.

theta = math.asin(1 / 16)
for k, p in enumerate(result.success):
    assert abs(p - math.sin((2 * k + 1) * theta) ** 2) < 1e-10

# %%
# The square-root speed-up
# ------------------------
# The iteration count grows as :math:`\sqrt{N}`: a 20-bit search takes 804
# iterations instead of about a million guesses.

for bits in (8, 16, 20):
    print(bits, "bits:", pqc.grover_iterations(2**bits), "iterations")
assert pqc.grover_iterations(2**20) == 804

ax = plot_grover_success(result)
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Run ``grover_search(8, [42], iterations=24)``. Explain from the rotation
# picture why running too long lowers the success probability again.
#
# A worked solution is in :doc:`/exercises/pqc`.
