r"""
Niederreiter encryption with syndromes (Niederreiter, 1986)
===========================================================

Harald Niederreiter turned McEliece around: the message *is* the error. It is
encoded as a vector :math:`e` of weight :math:`t`, and the ciphertext is its
syndrome under a hidden parity-check matrix,

.. math::

   H' = S\,H\,P, \qquad c = H' e^{\mathsf T}.

The ciphertext is only :math:`n - k` bits, and the owner decodes the syndrome
with the Goppa structure. (Niederreiter proposed generalized Reed-Solomon
codes, which Sidelnikov and Shestakov broke in 1992; with Goppa codes the
scheme is as secure as McEliece.) Encrypt a weight-:math:`t` error, decrypt it,
and recover it with Prange's decoder from the public key alone.
"""

# %%
import random

import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_binary_matrix

pqc = csk.pqc

# %%
# Encrypting an error vector
# --------------------------
# The ciphertext of a length-32 error of weight 3 is a 15-bit syndrome.

keys = pqc.niederreiter_keygen(5, 3, seed=2026)
n = len(keys.public.parity_check[0])
positions = random.Random(4).sample(range(n), 3)
error = tuple(int(i in positions) for i in range(n))
ciphertext = pqc.niederreiter_encrypt(keys.public, error)
print(f"{n}-bit message of weight 3 -> {len(ciphertext)}-bit ciphertext")
assert len(ciphertext) == len(keys.public.parity_check) == 15
assert pqc.niederreiter_decrypt(keys.private, ciphertext) == error

# %%
# Every weight-3 error has its own syndrome
# -----------------------------------------
# A code correcting 3 errors has distinct syndromes for all
# :math:`\binom{32}{3} = 4960` errors of weight 3, so encryption is injective.

seen = set()
weights = [(a, b, c) for a in range(n) for b in range(a + 1, n) for c in range(b + 1, n)]
for triple in weights:
    e = tuple(int(i in triple) for i in range(n))
    seen.add(pqc.niederreiter_encrypt(keys.public, e))
assert len(seen) == len(weights) == 4960

# %%
# The syndrome-decoding attack
# ----------------------------
# Recovering :math:`e` from :math:`c` is exactly Prange's problem on :math:`H'`.

result = pqc.break_niederreiter(keys.public, ciphertext, seed=1)
print(f"recovered the error after {result.iterations} guesses")
assert result.error == error

ax = plot_binary_matrix(keys.public.parity_check)
ax.set_title("public parity check H' = S H P")
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Count the messages a Niederreiter ciphertext can carry,
# :math:`\log_2 \binom{n}{t}` bits, for :math:`n = 32, t = 3` and for
# :math:`n = 3488, t = 64`, and compare with the ciphertext length.
#
# A worked solution is in :doc:`/exercises/pqc`.
