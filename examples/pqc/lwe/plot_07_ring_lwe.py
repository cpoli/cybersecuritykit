r"""
Ring learning with errors (Lyubashevsky, Peikert and Regev, 2010)
=================================================================

Plain LWE needs a whole matrix in the public key. Vadim Lyubashevsky, Chris
Peikert and Oded Regev replaced the matrix by one polynomial in
:math:`R_q = \mathbb{Z}_q[x]/(x^n + 1)`, whose multiplication acts like a
structured matrix, and proved the ring version is still hard. Their
encryption scheme (LPR) carries :math:`n` bits at once:

.. math::

   b = a s + e, \qquad u = a r + e_1, \qquad
   v = b r + e_2 + \Bigl\lfloor \frac{q}{2} \Bigr\rceil m,

and :math:`v - u s = e r - e_1 s + e_2 + \lfloor q/2 \rceil m` rounds back
to :math:`m`. ML-KEM (Kyber) and ML-DSA (Dilithium) are built on this ring.
"""

# %%
import random

import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.utils.rings import multiply

pqc = csk.pqc

# %%
# Sixteen bits in one ciphertext
# ------------------------------
# :math:`n = 16`, :math:`q = 257`.

keys = pqc.ring_lwe_keygen(16, 257, seed=1)
rng = random.Random(2)
message = tuple(rng.randrange(2) for _ in range(16))
ciphertext = pqc.ring_lwe_encrypt(keys.public, message, seed=3)
assert pqc.ring_lwe_decrypt(keys, ciphertext) == message
print(message)
assert 0 < sum(message) < 16

# %%
# Negacyclic wrap-around
# ----------------------
# Multiplying by :math:`x` shifts the coefficients, and the top one comes
# back negated because :math:`x^n = -1`. That sign is what separates
# :math:`x^n + 1` from NTRU's cyclic :math:`x^n - 1`.

x = (0, 1) + (0,) * 14
shifted = multiply(keys.public.a, x, 257, -1)
assert shifted[0] == (-keys.public.a[-1]) % 257
assert shifted[1:] == keys.public.a[:-1]

# %%
# Many messages, no errors
# ------------------------
# With errors in :math:`[-1, 1]` the noise term never reaches :math:`q/4`.

errors = 0
for s in range(50):
    m = tuple(rng.randrange(2) for _ in range(16))
    d = pqc.ring_lwe_decrypt(keys, pqc.ring_lwe_encrypt(keys.public, m, seed=s))
    errors += sum(x != y for x, y in zip(d, m, strict=True))
print(errors, "bit errors in 800 bits")
assert errors == 0

# %%
# Key sizes
# ---------
# An LWE public key with :math:`m = 2n` samples holds :math:`2n(n + 1)`
# numbers; a ring key holds :math:`2n`.

dims = [8, 16, 32, 64, 128, 256]
plain = [2 * n * (n + 1) for n in dims]
ring = [2 * n for n in dims]
lwe_keys = pqc.lwe_keygen(16, 32, 257, seed=1)
assert len(lwe_keys.public.a) * 16 + len(lwe_keys.public.b) == plain[1]

fig, ax = plt.subplots()
ax.plot(dims, plain, "o-", color="#94a3b8", label="LWE, $m = 2n$")
ax.plot(dims, ring, "o-", color="#2563eb", label="ring LWE")
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xlabel("dimension $n$")
ax.set_ylabel("numbers in the public key")
ax.set_title("A ring turns a quadratic key into a linear one")
ax.legend()
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Write :math:`a` as an :math:`n \times n` matrix whose product with the
# coefficient vector of :math:`s` equals :math:`a s` in :math:`R_q`. Which
# entries carry a minus sign, and why?
#
# A worked solution is in :doc:`/exercises/pqc`.
