r"""
Encrypting letter pairs (Playfair, 1854)
========================================

Charles Wheatstone's cipher, promoted by Lord Playfair, encrypts two letters
at a time with a 5 by 5 keyed square. Single-letter counts no longer map one
to one onto cipher letters; an attacker has to count the 600 or so digraphs
instead of 26 letters, which needs far more ciphertext.

Build the square, check the published example, break a long message by
simulated annealing, and compare how many distinct units the attacker has to
count.
"""

# %%
from collections import Counter

import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# The keyed square and the published example
# ------------------------------------------
# J is merged into I; a doubled letter in a pair is split with an X.

square = csk.classical.playfair_square("playfair example")
print("\n".join(" ".join(row) for row in square))
ciphertext = csk.classical.playfair_encrypt("hide the gold in the tree stump", "playfair example")
assert ciphertext == "BMODZBXDNABEKUDMUIXMMOUVIF"
assert csk.classical.playfair_decrypt(ciphertext, "playfair example").startswith("HIDETHEGOLD")

# %%
# Breaking it without the key
# ---------------------------
# Simulated annealing (Cowan, 2008) starts from a random square and keeps
# swapping cells, rows and columns, scoring each decryption against English
# letter pairs. About 800 letters and 20,000 moves are enough here.

text = " ".join(csk.classical.utils.english.CORPUS.split()[:200])
secret = csk.classical.playfair_encrypt(text, "harbour master")
broken = csk.classical.break_playfair(secret, seed=1, restarts=1, steps=20_000)
print(broken.plaintext[:60], f"({broken.tested} squares scored)")
assert broken.plaintext == csk.classical.playfair_decrypt(secret, "harbour master")

# %%
# Digraph counts are flatter than letter counts
# ---------------------------------------------

passage = (
    "The garrison had no news for three weeks and the officers began to fear that the "
    "bridge had fallen, so a rider was sent along the valley road to look for the convoy"
)
encrypted = csk.classical.playfair_encrypt(passage, "playfair example")
pairs = Counter(encrypted[i : i + 2] for i in range(0, len(encrypted), 2))
letters = Counter(encrypted)
assert max(pairs.values()) / sum(pairs.values()) < max(letters.values()) / sum(letters.values())

fig, ax = plt.subplots(figsize=(8, 3.5))
ax.plot(sorted(letters.values(), reverse=True), "o-", color="#94a3b8", label="single letters")
ax.plot(sorted(pairs.values(), reverse=True), "o-", color="#2563eb", label="letter pairs")
ax.set(xlabel="rank", ylabel="count", title="Playfair ciphertext: what an attacker counts")
ax.legend()
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Encrypt ``"AB"`` and ``"BA"`` under the example key. Show that reversing a
# pair reverses its ciphertext, and explain how an attacker can use that.
#
# A worked solution is in :doc:`/exercises/classical`.
