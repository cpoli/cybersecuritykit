r"""
Learning with errors (Regev, 2005)
==================================

Oded Regev's problem hides a secret :math:`s \in \mathbb{Z}_q^n` behind
noisy inner products. Without the noise, Gaussian elimination recovers
:math:`s` at once; with it, the problem is as hard as worst-case lattice
problems for a quantum computer. To encrypt a bit, sum a random subset
:math:`S` of the public samples:

.. math::

   b_i = \langle a_i, s \rangle + e_i, \qquad
   u = \sum_{i \in S} a_i, \qquad
   v = \sum_{i \in S} b_i + \Bigl\lfloor \frac{q}{2} \Bigr\rfloor \cdot \mathrm{bit}.

Decryption computes :math:`v - \langle u, s \rangle`, which is the bit times
:math:`\lfloor q/2 \rfloor` plus the summed errors. It is right while the
errors stay below :math:`q/4`.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

pqc = csk.pqc

# %%
# Encrypt and decrypt bits
# ------------------------
# :math:`n = 8`, :math:`m = 32` samples, :math:`q = 97`, errors in
# :math:`[-2, 2]`.

keys = pqc.lwe_keygen(8, 32, 97, seed=1)
bits = [1, 0, 1, 1, 0]
decrypted = [
    pqc.lwe_decrypt(keys, pqc.lwe_encrypt(keys.public, b, seed=s)) for s, b in enumerate(bits)
]
print(decrypted)
assert decrypted == bits

# %%
# The error budget
# ----------------
# Wider errors make the summed error cross :math:`q/4` more often. The errors
# are drawn once per key, so each width averages ten keys with forty
# encryptions each.

widths = list(range(0, 25, 4))
rates = []
for eta in widths:
    wrong = 0
    for k in range(10):
        noisy = pqc.lwe_keygen(8, 32, 97, eta=eta, seed=k)
        wrong += sum(
            pqc.lwe_decrypt(noisy, pqc.lwe_encrypt(noisy.public, s % 2, seed=s)) != s % 2
            for s in range(40)
        )
    rates.append(wrong / 400)
print(dict(zip(widths, rates, strict=True)))
assert rates[0] == rates[1] == 0 and rates[-1] > 0.1

# %%
# Without noise there is no problem
# ---------------------------------
# With :math:`\eta = 0` the samples are linear equations, and elimination
# finds the secret. With noise the same attack returns a wrong answer.

clean = pqc.lwe_keygen(4, 12, 97, eta=0, seed=2)
assert pqc.lwe_gaussian_attack(clean.public).secret == clean.secret
noisy = pqc.lwe_keygen(4, 12, 97, eta=2, seed=2)
guess = pqc.lwe_gaussian_attack(noisy.public)
print(guess.secret, "against", noisy.secret, ";", guess.consistent, "of 12 samples fit")
assert guess.secret != noisy.secret

fig, ax = plt.subplots()
ax.plot(widths, rates, "o-", color="#dc2626")
ax.set_xlabel(r"error width $\eta$")
ax.set_ylabel("decryption failure rate")
ax.set_title("Regev LWE, $n = 8$, $m = 32$, $q = 97$: 400 bits per width")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# A ciphertext sums about :math:`m/2` errors. Estimate the largest
# :math:`\eta` for which that sum stays below :math:`q/4` with high
# probability, and compare with the failure curve.
#
# A worked solution is in :doc:`/exercises/pqc`.
