r"""
CRYSTALS-Kyber key encapsulation (Bos et al., 2018)
===================================================

Kyber, standardized as ML-KEM in FIPS 203 (2024), is ring LWE over a small
module: vectors of :math:`k` polynomials in
:math:`\mathbb{Z}_{3329}[x]/(x^n + 1)`. Ciphertexts are compressed by
dropping low bits, and the Fujisaki-Okamoto transform turns the passively
secure encryption into a chosen-ciphertext-secure KEM:

.. math::

   (K, r) = G\bigl(m \,\|\, H(\mathrm{ek})\bigr), \qquad
   c = \mathrm{Enc}(\mathrm{ek}, m; r).

The decapsulator decrypts :math:`m'`, re-encrypts it, and returns :math:`K`
only if the result equals :math:`c`; otherwise it returns a pseudorandom key
derived from a secret :math:`z` (implicit rejection), so a tampered
ciphertext teaches the attacker nothing. This toy uses :math:`n = 16`
instead of 256, with SHA-3 from :mod:`hashlib`.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

pqc = csk.pqc

# %%
# Agreeing on a key
# -----------------
# Rank :math:`k = 2`, :math:`n = 16`: a 32-byte shared key.

keys = pqc.kyber_keygen(2, 16, seed=1)
sent = pqc.kyber_encapsulate(keys.public, seed=2)
assert pqc.kyber_decapsulate(keys, sent.ciphertext) == sent.shared_key
print(sent.shared_key.hex())

agreed = sum(
    pqc.kyber_decapsulate(keys, e.ciphertext) == e.shared_key
    for e in (pqc.kyber_encapsulate(keys.public, seed=s) for s in range(100))
)
print(agreed, "of 100 encapsulations agree")
assert agreed == 100

# %%
# Implicit rejection
# ------------------
# Change one coefficient of the ciphertext. The re-encryption check fails,
# and the decapsulator answers with an unrelated key instead of an error.


def bit_distance(x: bytes, y: bytes) -> int:
    return sum(bin(a ^ b).count("1") for a, b in zip(x, y, strict=True))


distances = []
for i in range(16):
    v = list(sent.ciphertext.v)
    v[i] = (v[i] + 1) % 16
    forged = pqc.KyberCiphertext(sent.ciphertext.u, tuple(v))
    distances.append(bit_distance(pqc.kyber_decapsulate(keys, forged), sent.shared_key))
print(distances)
assert all(d > 64 for d in distances)

fig, ax = plt.subplots()
ax.bar(range(16), distances, color="#dc2626", label="tampered ciphertext")
ax.axhline(128, color="#94a3b8", linestyle="--", label="unrelated keys (128 of 256 bits)")
ax.set_xlabel("coefficient of $v$ changed")
ax.set_ylabel("bits differing from the real key")
ax.set_title("Implicit rejection: a forged ciphertext yields a random key")
ax.legend(loc="lower right")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Suppose decapsulation raised an error on a failed re-encryption check
# instead of returning a pseudorandom key. Explain how an attacker who can
# submit ciphertexts could use that signal.
#
# A worked solution is in :doc:`/exercises/pqc`.
