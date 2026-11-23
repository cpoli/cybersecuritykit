r"""
Matrix encryption and its known-plaintext break (Hill, 1929)
============================================================

Lester Hill encrypted blocks of :math:`n` letters as vectors,
:math:`c = K p \bmod 26`, the first cipher built from linear algebra. The
linearity is also its weakness: :math:`n` blocks of known plaintext with an
invertible matrix give the key as :math:`K = C P^{-1} \bmod 26`.

Check the textbook vector, then recover the key from a guessed opening.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# The textbook vector
# -------------------

key = ((6, 24, 1), (13, 16, 10), (20, 17, 15))  # GYBNQKURP
assert csk.classical.hill_encrypt("ACTCAT", key) == "POHFIN"
assert csk.classical.hill_decrypt("POHFIN", key) == "ACTCAT"
print("inverse key:", csk.classical.hill_inverse(key))

# %%
# Known plaintext gives the key
# -----------------------------
# The attacker guesses how the message starts and solves a linear system.

message = "THEARMYMARCHESATDAWNTOWARDSTHERIVER"
ciphertext = csk.classical.hill_encrypt(message, key)
result = csk.classical.hill_known_plaintext(message[:18], ciphertext[:18], 3)
assert result.key == key
print("blocks used:", result.blocks)

fig, axes = plt.subplots(1, 2, figsize=(8, 3.5))
for ax, matrix, title in ((axes[0], key, "secret key"), (axes[1], result.key, "recovered")):
    ax.imshow(matrix, cmap="Blues", vmin=0, vmax=25)
    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            ax.text(j, i, value, ha="center", va="center")
    ax.set(title=title, xticks=[], yticks=[])
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Which pairs of 2-letter plaintext blocks cannot be used to recover a
# :math:`2 \times 2` key? Find one with determinant divisible by 13.
#
# A worked solution is in :doc:`/exercises/classical`.
