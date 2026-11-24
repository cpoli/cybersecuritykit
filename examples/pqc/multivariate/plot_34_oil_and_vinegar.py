r"""
Unbalanced Oil and Vinegar signatures (Kipnis-Patarin-Goubin, 1999)
===================================================================

In an oil-and-vinegar central map no term multiplies two oil variables:

.. math::

   f_k(x) = \sum_{i \in V,\, j \in V \cup O} \alpha^{(k)}_{ij} x_i x_j
   + \sum_i \beta^{(k)}_i x_i + \gamma_k .

Fix the vinegar variables at random and every :math:`f_k` is linear in the
oils, so the signer solves a linear system. The public key hides the map behind
a secret change of variables :math:`S`. Patarin's balanced scheme (1997), with
as many vinegars as oils, fell to Kipnis and Shamir in 1998. Kipnis, Patarin
and Goubin's fix takes more vinegars than oils. Sign and verify on toy
parameters, then compare the secret map with the public one.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_quadratic_form

pqc = csk.pqc

# %%
# Signing and verifying
# ---------------------
# Six vinegars and three oils over :math:`\mathrm{GF}(7)`: three equations
# in nine variables.

keys = pqc.uov_keygen(7, vinegar=6, oil=3, seed=2026)
signature = pqc.oil_vinegar_sign(keys.private, b"hello", seed=1)
print(f"signature {signature}")
assert pqc.oil_vinegar_verify(keys.public, b"hello", signature)
assert not pqc.oil_vinegar_verify(keys.public, b"hellO", signature)

# Different signing seeds give different signatures of the same message.
signatures = {pqc.oil_vinegar_sign(keys.private, b"hello", seed=s) for s in range(5)}
assert len(signatures) > 1
assert all(pqc.oil_vinegar_verify(keys.public, b"hello", s) for s in signatures)

# %%
# The hidden zero block
# ---------------------
# The central map has an all-zero oil-by-oil block, the trapdoor. The secret
# change of variables spreads the coefficients over the whole public matrix.

central = keys.private.central
oil = range(6, 9)
assert all(central.quadratic[k][i][j] == 0 for k in range(3) for i in oil for j in oil)
assert any(keys.public.quadratic[0][i][j] for i in oil for j in oil)

fig, (left, right) = plt.subplots(1, 2, figsize=(9, 4))
plot_quadratic_form(central, 0, ax=left)
left.set_title("secret central map: zero oil block")
plot_quadratic_form(keys.public, 0, ax=right)
right.set_title("public map P = F o S")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Count the equations and unknowns the signer solves once the vinegars are
# fixed, and estimate how often that system is singular over
# :math:`\mathrm{GF}(q)` for :math:`o = 3`.
#
# A worked solution is in :doc:`/exercises/pqc`.
