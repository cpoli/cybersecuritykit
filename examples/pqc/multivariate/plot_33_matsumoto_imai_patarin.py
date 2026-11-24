r"""
Matsumoto-Imai and Patarin's linearization (Matsumoto-Imai, 1988)
=================================================================

Tsutomu Matsumoto and Hideki Imai hid the power map
:math:`X \mapsto X^{2^\theta + 1}` on :math:`\mathrm{GF}(2^n)` between two secret
affine maps. Written over :math:`\mathrm{GF}(2)` it becomes :math:`n` quadratic
polynomials in :math:`n` variables, the public key. Jacques Patarin (1995) saw
that :math:`Y = X^{2^\theta + 1}` implies
:math:`X^{2^{2\theta}} Y = X Y^{2^\theta}`, a relation that is *bilinear* in
the plaintext :math:`u` and the ciphertext :math:`v`:

.. math::

   \sum_{i,j} \gamma_{ij}\, u_i v_j + \sum_i \alpha_i u_i
   + \sum_j \beta_j v_j + \delta = 0.

Known pairs give the coefficients by linear algebra. Substituting a target
ciphertext then leaves a linear system in its plaintext. Encrypt, decrypt with
the secret key, then decrypt with Patarin's relations and the public key alone.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_quadratic_form

pqc = csk.pqc

# %%
# A toy key on 5 bits
# -------------------
# :math:`\theta = 2` gives the exponent 5, coprime to :math:`2^5 - 1 = 31`,
# so the power map is a bijection.

keys = pqc.matsumoto_imai_keygen(5, 2, seed=2026)
print(f"{keys.public.n_polys} quadratic polynomials in {keys.public.n_vars} variables")
plaintext = (1, 0, 1, 1, 0)
ciphertext = pqc.matsumoto_imai_encrypt(keys.public, plaintext)
assert pqc.matsumoto_imai_decrypt(keys.private, ciphertext) == plaintext

# Encryption is a bijection on all 32 plaintexts.
images = {keys.public.evaluate(tuple((x >> i) & 1 for i in range(5))) for x in range(32)}
assert len(images) == 32

# %%
# Patarin's attack
# ----------------
# The relations come from public-key evaluations only; the secret maps are
# never used.

result = pqc.patarin_linearization(keys.public, ciphertext, seed=1)
print(result)
assert result.plaintext == plaintext
assert result.relations >= 5

# Other ciphertexts fall to the same method.
for x in (0, 7, 19, 31):
    u = tuple((x >> i) & 1 for i in range(5))
    found = pqc.patarin_linearization(keys.public, keys.public.evaluate(u), seed=1)
    assert found.plaintext == u

ax = plot_quadratic_form(keys.public, 0)
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Derive :math:`X^{2^{2\theta}} Y = X Y^{2^\theta}` from
# :math:`Y = X^{2^\theta + 1}`, and explain why the Frobenius powers make it
# bilinear over :math:`\mathrm{GF}(2)`. How many unknown coefficients does it
# have for :math:`n = 5`?
#
# A worked solution is in :doc:`/exercises/pqc`.
