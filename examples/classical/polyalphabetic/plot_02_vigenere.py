r"""
A keyword picks the alphabets (Bellaso, 1553)
=============================================

Giovan Battista Bellaso replaced Alberti's disk with a short keyword that
anyone could remember: each keyword letter selects a shifted alphabet, and
the keyword repeats along the message. The cipher was later credited to
Blaise de Vigenere and called *le chiffre indechiffrable*.

Encrypt the textbook vector, then watch how the keyword spreads each
plaintext letter over several cipher letters.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# The textbook vector
# -------------------

ciphertext = csk.classical.vigenere_encrypt("attack at dawn", "lemon")
assert ciphertext == "LXFOPVEFRNHR"
assert csk.classical.vigenere_decrypt(ciphertext, "lemon") == "ATTACKATDAWN"

# %%
# Each keyword letter is its own shift cipher
# -------------------------------------------
# Letter :math:`i` is shifted by keyword letter :math:`i \bmod 5`. Reading
# every fifth letter gives a shift cipher with one key.

passage = (
    "The courier rode through the night with the letter sewn into his coat, and at dawn he "
    "reached the river where the boatmen waited to carry the news across to the city"
)
key = "LEMON"
encrypted = csk.classical.vigenere_encrypt(passage, key)
column = encrypted[0::5]
assert csk.classical.shift_decrypt(column, 11) == csk.classical.shift_encrypt(passage, 0)[0::5]

fig, axes = plt.subplots(1, 2, figsize=(11, 3.5), sharey=True)
visualizers.plot_letter_frequencies(passage, ax=axes[0])
axes[0].set_title("plaintext")
visualizers.plot_letter_frequencies(encrypted, ax=axes[1])
axes[1].set_title("Vigenere ciphertext, key LEMON")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Encrypt the passage with the key ``"LEMONLEMON"`` and with ``"L"``. Which
# of the two is really a longer key, and which is a shift cipher?
#
# A worked solution is in :doc:`/exercises/classical`.
