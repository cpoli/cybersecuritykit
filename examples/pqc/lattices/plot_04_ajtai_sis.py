r"""
Ajtai's short-integer-solution hash (Ajtai, 1996)
=================================================

Miklós Ajtai showed that a random instance of a lattice problem can be as
hard as the worst case. His hash multiplies a bit vector by a public random
matrix modulo :math:`q`:

.. math::

   f_A(x) = A x \bmod q, \qquad A \in \mathbb{Z}_q^{n \times m},
   \quad x \in \{0, 1\}^m.

When :math:`m > n \log_2 q` the hash compresses, so collisions exist. A
collision :math:`f_A(x) = f_A(y)` gives :math:`A (x - y) \equiv 0`, a short
vector with entries in :math:`\{-1, 0, 1\}` in the lattice
:math:`\Lambda^\perp(A)`. Finding collisions is therefore as hard as the
short-integer-solution (SIS) problem.
"""

# %%
from collections import Counter
from itertools import product

import matplotlib.pyplot as plt

import cybersecuritykit as csk

pqc = csk.pqc

# %%
# The hash compresses
# -------------------
# With :math:`n = 2`, :math:`m = 8` and :math:`q = 11` there are 256 inputs
# and only :math:`11^2 = 121` possible outputs.

key = pqc.ajtai_keygen(2, 8, 11, seed=1)
digest = pqc.ajtai_hash(key, (1, 0, 1, 1, 0, 0, 1, 0))
print(digest)
assert 2**8 > 11**2

# %%
# A collision is a short lattice vector
# -------------------------------------
# A brute-force search stops at the first repeated hash value.

collision = pqc.ajtai_collision(key)
print(collision.x, collision.y, "after", collision.tested, "inputs")
assert pqc.ajtai_hash(key, collision.x) == pqc.ajtai_hash(key, collision.y)
z = collision.difference
assert any(z) and set(z) <= {-1, 0, 1}
assert all(sum(a * x for a, x in zip(row, z, strict=True)) % 11 == 0 for row in key.matrix)

# %%
# How the inputs fill the outputs
# -------------------------------
# Every hash value with two or more inputs is a collision.

buckets = Counter(pqc.ajtai_hash(key, bits) for bits in product((0, 1), repeat=8))
sizes = Counter(buckets.values())
print(f"{len(buckets)} of {11**2} values used")

fig, ax = plt.subplots()
ax.bar(sorted(sizes), [sizes[s] for s in sorted(sizes)], color="#2563eb")
ax.set_xlabel("inputs sharing one hash value")
ax.set_ylabel("hash values")
ax.set_title(f"256 inputs land on {len(buckets)} of 121 hash values")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# ``ajtai_keygen(2, 8, 31)`` raises an error. Compute :math:`n \log_2 q`,
# explain why the key generator insists on compression, and find the
# smallest :math:`m` it accepts for :math:`q = 31`.
#
# A worked solution is in :doc:`/exercises/pqc`.
