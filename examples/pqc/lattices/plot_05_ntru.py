r"""
NTRU (Hoffstein, Pipher and Silverman, 1998)
============================================

NTRU works in the ring :math:`\mathbb{Z}[x]/(x^N - 1)`. The private key is a
small polynomial :math:`f`, invertible modulo :math:`p` and :math:`q`; the
public key hides a second small polynomial :math:`g`:

.. math::

   h = f_q\, g \bmod q, \qquad e = p\, r h + m \bmod q, \qquad
   f e \equiv p\, r g + f m \pmod q.

Every term on the right is small, so when its coefficients stay inside
:math:`(-q/2, q/2)` the decryptor reads off :math:`f m` and multiplies by
:math:`f_p`. When a coefficient wraps, decryption fails. The pair
:math:`(f, g)` is also a short vector of a :math:`2N`-dimensional lattice
built from :math:`h`, which is what lattice reduction attacks.
"""

# %%
import random

import matplotlib.pyplot as plt

import cybersecuritykit as csk

pqc = csk.pqc

# %%
# Encrypt and decrypt
# -------------------
# :math:`N = 11`, :math:`p = 3`, :math:`q = 64`, with three coefficients of
# each sign in :math:`f` and :math:`g`.

keys = pqc.ntru_keygen(11, 3, 64, 3, seed=1)
message = (1, 0, -1, 1, 1, 0, 0, -1, 0, 1, 0)
ciphertext = pqc.ntru_encrypt(keys.public, message, seed=2)
print("ciphertext", ciphertext)
assert pqc.ntru_decrypt(keys, ciphertext) == message

# %%
# Wrapping makes decryption fail
# ------------------------------
# A smaller :math:`q` gives less room for :math:`p r g + f m`.

moduli = (16, 32, 64)
failures = []
for q in moduli:
    small = pqc.ntru_keygen(11, 3, q, 3, seed=1)
    rng = random.Random(5)
    wrong = 0
    for s in range(200):
        m = tuple(rng.choice((-1, 0, 1)) for _ in range(11))
        wrong += pqc.ntru_decrypt(small, pqc.ntru_encrypt(small.public, m, seed=s)) != m
    failures.append(wrong / 200)
print(dict(zip(moduli, failures, strict=True)))
assert failures[0] > failures[1] > failures[2] == 0

# %%
# Recovering the key with LLL
# ---------------------------
# At :math:`N = 7` the 14-dimensional NTRU lattice is small enough for exact
# LLL, and a rotation of :math:`(f, g)` appears among the reduced rows.

toy = pqc.ntru_keygen(7, 3, 41, 2, seed=3)
attack = pqc.ntru_lattice_attack(toy.public)
print(attack.dimension, "dimensions,", attack.swaps, "swaps")
assert attack.keypair.public == toy.public
secret = (1, -1, 0, 1, 0, 0, -1)
assert pqc.ntru_decrypt(attack.keypair, pqc.ntru_encrypt(toy.public, secret, seed=4)) == secret

fig, ax = plt.subplots()
ax.bar([str(q) for q in moduli], failures, color="#dc2626")
ax.set_xlabel("modulus $q$")
ax.set_ylabel("decryption failure rate")
ax.set_title("NTRU, $N = 11$, $p = 3$: 200 messages per modulus")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Bound the largest coefficient of :math:`p r g + f m` for the parameters
# above, and find the smallest :math:`q` for which failure is impossible.
#
# A worked solution is in :doc:`/exercises/pqc`.
