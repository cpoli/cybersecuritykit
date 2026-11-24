r"""
How much ciphertext fixes the key (Shannon's unicity distance, 1949)
====================================================================

English is redundant: it carries about 1.5 bits per letter out of a possible
:math:`\log_2 26 \approx 4.7`. Shannon showed that once the ciphertext is
long enough for that redundancy to exceed the key's entropy, only one key
gives sensible plaintext. That length is the *unicity distance*,

.. math::

   U = \frac{\log_2 |K|}{\log_2 26 - H}.

Compute it for the ciphers in this package, then count the spurious keys of a
real shift ciphertext to see how close the estimate is.
"""

# %%
import math

import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# Key spaces of the classical ciphers
# -----------------------------------

ciphers = {
    "shift": 26,
    "Vigenere, 6 letters": 26**6,
    "Hill 3x3": 26**9,  # An upper bound: not every matrix is invertible.
    "substitution": math.factorial(26),
}
results = {name: csk.classical.unicity_distance(keys) for name, keys in ciphers.items()}
for name, result in results.items():
    print(f"{name:>20}: {result.key_entropy:6.1f} bits -> {result.distance:5.1f} letters")
assert abs(results["substitution"].distance - 27.6) < 0.05

fig, ax = plt.subplots(figsize=(8, 3.5))
ax.barh(list(results), [r.distance for r in results.values()], color="#2563eb")
ax.set(xlabel="unicity distance (letters)", title="ciphertext needed before the key is unique")
fig.tight_layout()

plt.show()

# %%
# Spurious keys on a real ciphertext
# ----------------------------------
# A key is still alive while its decryption uses only letter pairs seen in
# English. The count falls from 26 to one within a few letters: more than the
# 1.5 Shannon's formula gives, because this test is cruder than a reader.

text = " ".join(csk.classical.utils.english.CORPUS.split()[:12])
spurious = csk.classical.spurious_shift_keys(csk.classical.shift_encrypt(text, 7))
print("keys alive:", spurious.counts[:10], "unique from", spurious.unique_from, "letters")
assert spurious.unique_from is not None and spurious.unique_from <= 10

fig, ax = plt.subplots(figsize=(8, 3.5))
ax.step(spurious.lengths[:15], spurious.counts[:15], where="post", color="#2563eb")
ax.axvline(results["shift"].distance, color="#dc2626", linestyle="--", label="Shannon's estimate")
ax.set(xlabel="ciphertext letters", ylabel="shift keys still plausible", yscale="log")
ax.legend()
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Compress English before encrypting it, so that its entropy rises towards
# 4.7 bits per letter. What happens to the unicity distance, and why did
# Shannon say redundancy is what an attacker exploits?
#
# A worked solution is in :doc:`/exercises/classical`.
