r"""
Recovering a Lorenz wheel from statistics (Tutte, 1942)
=======================================================

The Lorenz SZ40 added a keystream built from twelve pinwheels of coprime
lengths to teleprinter traffic. Bill Tutte, given a keystream recovered from a
depth, wrote out one impulse in rows and noticed repeats at a period of 41:
the first chi wheel. Taking differences, :math:`\Delta x_i = x_i \oplus
x_{i+1}`, makes the irregular psi wheels mostly vanish, so the chi period
shows through.

Generate a keystream from seeded wheels, then score every candidate period.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# Seeded wheels with the real lengths
# -----------------------------------

wheels = csk.classical.lorenz_wheels(seed=2026)
print("chi:", [len(w) for w in wheels.chi], "psi:", [len(w) for w in wheels.psi])
stream = csk.classical.lorenz_keystream(wheels, 4000)

# %%
# The first impulse agrees with itself 41 places on
# -------------------------------------------------

bits = [x >> 4 & 1 for x in stream]
test = csk.classical.tutte_period_test(bits, range(20, 70))
assert test.best_period == 41
print("best period:", test.best_period)

ax = visualizers.plot_period_test(test)

plt.show()

# %%
# Exercise
# --------
# Repeat for the second impulse, ``x >> 3 & 1``. Which period should win, and
# how many characters of keystream does the test need to find it reliably?
