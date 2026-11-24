r"""
McEliece encryption with Goppa codes (McEliece, 1978)
=====================================================

Robert McEliece hid a binary Goppa code, which its owner can decode quickly,
behind a random-looking generator matrix

.. math::

   G' = S\,G\,P, \qquad c = m\,G' + e, \quad \operatorname{wt}(e) = t,

with :math:`S` invertible and :math:`P` a permutation. The owner undoes
:math:`P`, corrects the :math:`t` errors with the Goppa decoder and undoes
:math:`S`. Everyone else faces a random-looking decoding problem,
the one Prange's information-set decoding attacks. Generate a toy key, round
trip a message, compare the hidden and public generators, then break it.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_binary_matrix

pqc = csk.pqc

# %%
# A toy key
# ---------
# With :math:`m = 5` and :math:`t = 3` the Goppa code has length
# :math:`n = 2^5 = 32` and dimension :math:`k \ge n - mt = 17`.

keys = pqc.mceliece_keygen(5, 3, seed=2026)
code = keys.private.code
print(f"[{code.n}, {code.k}] Goppa code correcting {code.t} errors")
assert (code.n, code.k) == (32, 17)

message = (1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1)
ciphertext = pqc.mceliece_encrypt(keys.public, message, seed=1)
assert pqc.mceliece_decrypt(keys.private, ciphertext) == message

# %%
# The owner's decoder corrects any 3 errors
# -----------------------------------------
# Flip three bits of a codeword and the Goppa decoder names exactly those bits.

received = list(code.generator[0])
for i in (2, 9, 30):
    received[i] ^= 1
found = pqc.goppa_decode(code, received)
assert [i for i, bit in enumerate(found) if bit] == [2, 9, 30]

# %%
# Breaking the toy key
# --------------------
# Without the code, an attacker runs information-set decoding on :math:`G'`.
# At toy size that takes a few dozen guesses; at McEliece's
# :math:`n = 1024, t = 50` it took decades of improvements to get anywhere.

result = pqc.break_mceliece(keys.public, ciphertext, seed=3)
print(f"recovered the message after {result.iterations} guesses")
assert result.message == message
assert sum(result.error) == 3

fig, (left, right) = plt.subplots(1, 2, figsize=(9, 3.5))
plot_binary_matrix(code.generator, ax=left)
left.set_title("secret Goppa generator G")
plot_binary_matrix(keys.public.generator, ax=right)
right.set_title("public generator G' = S G P")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# The public key has :math:`k \times n` bits. Compute its size for the
# Classic McEliece parameters :math:`n = 3488, k = 2720`, and explain why the
# systematic form :math:`(I_k \mid A)` lets you store only :math:`A`.
#
# A worked solution is in :doc:`/exercises/pqc`.
