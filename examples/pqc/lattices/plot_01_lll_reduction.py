r"""
LLL lattice reduction (Lenstra, Lenstra and Lovász, 1982)
==========================================================

A lattice has many bases, and most of them are long and nearly parallel.
The LLL algorithm turns any basis into a reduced one in polynomial time by
size-reducing each vector against the earlier ones and swapping neighbours
whenever the Lovász condition fails:

.. math::

   \|b_k^*\|^2 \ge \left(\delta - \mu_{k,k-1}^2\right) \|b_{k-1}^*\|^2,
   \qquad \delta = \tfrac{3}{4}.

The first reduced vector is within a factor :math:`2^{(n-1)/2}` of the
shortest. That is weak in high dimension and decisive in low dimension, and
it is the main tool for attacking lattice cryptosystems.
"""

# %%
import random

import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_gram_schmidt_profile

pqc = csk.pqc

# %%
# A textbook example
# ------------------
# The three-dimensional basis from the Wikipedia article, reduced with
# :math:`\delta = 3/4`.

small = pqc.lll_reduce([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
print(small.basis, "after", small.swaps, "swaps")
assert small.basis == ((0, 1, 0), (1, 0, 1), (-1, 0, 2))

# %%
# A scrambled copy of the integer lattice
# ---------------------------------------
# Adding integer multiples of one row to another never changes the lattice.
# Twelve such steps hide :math:`\mathbb{Z}^4` behind long vectors; LLL finds
# the unit vectors again.

rng = random.Random(3)
basis = [[int(i == j) for j in range(4)] for i in range(4)]
for _ in range(12):
    i, j = rng.sample(range(4), 2)
    factor = rng.choice([-3, -2, 2, 3])
    basis[i] = [x + factor * y for x, y in zip(basis[i], basis[j], strict=True)]
print(basis)

result = pqc.lll_reduce(basis)
print(result.basis, "after", result.swaps, "swaps")
assert sorted(sum(x * x for x in row) for row in result.basis) == [1, 1, 1, 1]

# %%
# The Gram-Schmidt profile
# ------------------------
# The product of the Gram-Schmidt lengths is the lattice volume, 1 here, and
# does not change. Reduction evens the lengths out, which is what makes the
# first vector short.

volume_before = 1.0
for norm in result.norms_before:
    volume_before *= norm
assert abs(volume_before - 1) < 1e-10
assert all(abs(norm - 1) < 1e-10 for norm in result.norms_after)

ax = plot_gram_schmidt_profile(result)
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Reduce the same scrambled basis with ``delta=0.5`` and ``delta=0.99``.
# Compare the swap counts and explain why a larger :math:`\delta` costs more
# swaps.
#
# A worked solution is in :doc:`/exercises/pqc`.
