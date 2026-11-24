r"""
Fiat-Shamir with aborts (Lyubashevsky, 2009)
============================================

The `Fiat-Shamir heuristic
<https://cpoli.github.io/blockchainkit/history/crypto_breakthroughs.html#the-fiat-shamir-heuristic-from-interaction-to-signatures>`__
turns an identification protocol into a signature by hashing the commitment.
Over lattices the response :math:`z = y + c s` is a problem: its
distribution is shifted by the secret, so averaging signatures reveals
:math:`s`. Vadim Lyubashevsky's fix is to abort and retry unless :math:`z`
lies in a box that every secret can reach:

.. math::

   w = a y_1 + y_2, \quad c = H(w, \mu), \quad z = y + c s, \quad
   \text{output } z \text{ only if } \|z\|_\infty \le B - \kappa.

Accepted responses are then uniform on the box, whatever :math:`s` is. This
is the design behind Dilithium (ML-DSA, FIPS 204).
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_signature_leakage

pqc = csk.pqc

# %%
# Sign and verify
# ---------------
# :math:`n = 16` over :math:`q = 8380417`, Dilithium's modulus.

keys = pqc.lyubashevsky_keygen(16, seed=1)
signature = pqc.lyubashevsky_sign(keys, b"pay alice 10", seed=2)
assert pqc.lyubashevsky_verify(keys.public, b"pay alice 10", signature)
assert not pqc.lyubashevsky_verify(keys.public, b"pay alice 99", signature)
attempts = [pqc.lyubashevsky_sign(keys, b"m", seed=s).attempts for s in range(200)]
print(f"{sum(attempts) / 200:.2f} attempts per signature on average")
assert min(attempts) >= 1

# %%
# Averaging signatures
# --------------------
# A small box (:math:`B = 16`) makes the effect visible. The attacker
# averages :math:`c^* z_1 / \kappa` over many signatures; without aborts that
# average converges to :math:`s_1`.

small = pqc.lyubashevsky_keygen(8, kappa=2, bound=16, seed=4)
leaky = [pqc.lyubashevsky_sign(small, b"m", seed=s, abort=False) for s in range(1500)]
safe = [pqc.lyubashevsky_sign(small, b"m", seed=s) for s in range(1500)]
leaks = {
    "without aborts": pqc.lyubashevsky_leakage(small.public, leaky),
    "with aborts": pqc.lyubashevsky_leakage(small.public, safe),
}
print("secret      ", small.s1)
print("no aborts   ", leaks["without aborts"].secret_guess)
print("with aborts ", leaks["with aborts"].secret_guess)
assert leaks["without aborts"].secret_guess == small.s1
assert all(abs(x) < 0.5 for x in leaks["with aborts"].estimate)

ax = plot_signature_leakage(leaks, small.s1)
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# The expected number of attempts depends on how much of the box
# :math:`[-B, B]` survives the cut at :math:`B - \kappa`. Derive it for one
# coefficient, raise it to the number of coefficients, and compare with the
# measured average.
#
# A worked solution is in :doc:`/exercises/pqc`.
