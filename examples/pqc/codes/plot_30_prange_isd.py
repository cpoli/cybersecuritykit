r"""
Prange's information-set decoding (Prange, 1962)
================================================

Decoding a random linear code is hard: given a parity-check matrix :math:`H`
(:math:`r \times n`) and a syndrome :math:`s`, find an error :math:`e` of
weight at most :math:`t` with :math:`He = s`. Eugene Prange's method guesses
:math:`r` columns that hold the whole error. If those columns are invertible,
one linear solve gives a candidate, and the guess is right with probability

.. math::

   p = \binom{n - t}{r - t} \Big/ \binom{n}{r}.

The number of guesses is geometric with mean :math:`1/p`; every attack on
code-based cryptography since refines this one. Solve a small example, then
watch the iteration counts follow the geometric law.
"""

# %%
import random

import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_isd_iterations

pqc = csk.pqc

# %%
# The Hamming code
# ----------------
# The :math:`[7, 4]` Hamming code corrects one error: column :math:`i` of
# :math:`H` is :math:`i` in binary, so the syndrome names the flipped bit.

h = ((1, 0, 1, 0, 1, 0, 1), (0, 1, 1, 0, 0, 1, 1), (0, 0, 0, 1, 1, 1, 1))
error = (0, 0, 0, 0, 1, 0, 0)
result = pqc.prange_isd(h, pqc.syndrome(h, error), 1, seed=2026)
print(result)
assert result.error == error

# %%
# A random-looking parity check
# -----------------------------
# A Goppa code of length 32 has 15 parity checks and corrects 3 errors. Prange
# ignores its structure and treats :math:`H` as a random matrix.

code = pqc.goppa_code(5, 3, seed=7)
n, k, t = code.n, code.k, 3
probability = pqc.prange_success_probability(n, k, t)
print(f"[{n}, {k}] code, t = {t}: p = {probability:.4f}, mean {1 / probability:.1f} guesses")

rng = random.Random(1)
iterations = []
for run in range(300):
    positions = rng.sample(range(n), t)
    e = tuple(int(i in positions) for i in range(n))
    found = pqc.prange_isd(code.parity_check, pqc.syndrome(code.parity_check, e), t, seed=run)
    assert pqc.syndrome(code.parity_check, found.error) == pqc.syndrome(code.parity_check, e)
    iterations.append(found.iterations)
mean = sum(iterations) / len(iterations)
print(f"observed mean {mean:.1f} guesses")

# %%
# Singular guesses cost extra
# ---------------------------
# A guess also fails when its :math:`r` columns are singular. For a random
# binary matrix that happens with probability about
# :math:`1 - \prod_{i \ge 1} (1 - 2^{-i}) \approx 0.71`, so the observed mean
# lies between :math:`1/p` and about :math:`1/(0.29\,p)`. The counts are still
# geometric: the histogram follows the law with the observed rate.

invertible = 0.2888
assert 1 / probability < mean < 1.3 / (invertible * probability)

ax = plot_isd_iterations(iterations, 1 / mean)
ax.set_title(f"Prange on a [{n}, {k}] code with t = {t}")
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Show that the expected work grows like :math:`(n / (n - k))^t` for small
# :math:`t`, and estimate how many guesses a code with :math:`n = 1024`,
# :math:`k = 524` and :math:`t = 50` (McEliece's 1978 parameters) needs.
#
# A worked solution is in :doc:`/exercises/pqc`.
