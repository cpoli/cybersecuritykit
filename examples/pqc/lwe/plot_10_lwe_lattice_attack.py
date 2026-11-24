r"""
The primal lattice attack on learning with errors (Regev, 2005)
===============================================================

Regev's samples :math:`b = A s + e \bmod q` hide :math:`s` behind a small
error, but :math:`b` still lies close to the lattice
:math:`L(A) = \{A x \bmod q\}`. Kannan's embedding appends :math:`b` to a
basis of :math:`L(A)` with an extra coordinate 1, so that

.. math::

   (b, 1) - (A s \bmod q, 0) = (e, 1)

is an unusually short vector of the embedded lattice. LLL finds it while the
dimension :math:`m + 1` is small, and then :math:`s = A_1^{-1}(b_1 - e_1)`
from the first :math:`n` samples. This is the attack every LWE parameter set
is sized against: the noise must be wide enough, and the dimension large
enough, that no reduction reaches :math:`(e, 1)`.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

pqc = csk.pqc

# %%
# Noise defeats elimination, not reduction
# ----------------------------------------
# :math:`n = 8`, :math:`m = 24` samples, :math:`q = 97`, errors in
# :math:`[-4, 4]`. Gaussian elimination on the first eight samples returns a
# wrong secret; the embedded 25-dimensional lattice gives the right one.

keys = pqc.lwe_keygen(8, 24, 97, eta=4, seed=1)
guess = pqc.lwe_gaussian_attack(keys.public)
attack = pqc.lwe_lattice_attack(keys.public)
print("elimination:", guess.secret)
print("lattice:    ", attack.secret, "after", attack.swaps, "LLL swaps")
print("secret:     ", keys.secret)
print("error:      ", attack.error)
assert guess.secret != keys.secret
assert attack.secret == keys.secret
assert attack.dimension == 25

# %%
# Wider noise hides the short vector
# ----------------------------------
# As :math:`\eta` grows, :math:`(e, 1)` stops being much shorter than the
# other lattice vectors, and LLL's exponential approximation factor no longer
# singles it out. Each width runs ten keys.

widths = [2, 8, 16, 24, 32]
recovered = []
for eta in widths:
    hits = 0
    for seed in range(10):
        noisy = pqc.lwe_keygen(8, 24, 97, eta=eta, seed=seed)
        hits += pqc.lwe_lattice_attack(noisy.public).secret == noisy.secret
    recovered.append(hits)
print(dict(zip(widths, recovered, strict=True)))
assert recovered[0] == recovered[1] == 10 and recovered[-1] < 10

fig, ax = plt.subplots()
ax.plot(widths, recovered, "o-", color="#dc2626")
ax.set_xlabel(r"error width $\eta$")
ax.set_ylabel("secrets recovered, of 10")
ax.set_ylim(0, 10.5)
ax.set_title("Kannan embedding + LLL, $n = 8$, $m = 24$, $q = 97$")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Compute the length :math:`\|(e, 1)\|` of the vector the attack looks for at
# :math:`\eta = 4`, and compare it with the Gaussian heuristic
# :math:`\sqrt{d / (2 \pi e)} \, \det(L)^{1/d}` for the shortest vector of a
# random lattice of the same dimension :math:`d = m + 1` and determinant
# :math:`q^{m - n}`.
#
# A worked solution is in :doc:`/exercises/pqc`.
