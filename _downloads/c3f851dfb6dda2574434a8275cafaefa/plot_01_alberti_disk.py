r"""
The cipher disk turns the alphabet (Alberti, c. 1467)
=====================================================

Leon Battista Alberti mounted a mixed alphabet on a disk inside a fixed plain
alphabet. Turning the disk every few letters changes the substitution, so the
same plaintext letter is written in different ways. It is the first
polyalphabetic cipher.

Encrypt a run of identical letters, then compare the letter counts of a
passage encrypted with the disk held still and with the disk turning.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# One letter, many cipher letters
# -------------------------------

disk = "QWERTYUIOPASDFGHJKLZXCVBNM"  # A mixed inner alphabet, fixed for the lesson.
turning = csk.classical.alberti_encrypt("EEEEEEEEEEEE", disk, start=3, period=3)
print(turning)
assert len(set(turning)) == 4  # Four turns of the disk, four different cipher letters.

# %%
# Turning flattens the counts
# ---------------------------
# With ``period`` very large the disk never turns and the cipher is a single
# substitution; with ``period=1`` it turns after every letter.

passage = (
    "Every evening the keeper climbed the stairs of the tower and wrote the hour in the "
    "book, and every evening the sea was the same grey colour under the same grey sky"
)
still = csk.classical.alberti_encrypt(passage, disk, start=0, period=10_000)
moving = csk.classical.alberti_encrypt(passage, disk, start=0, period=1)
assert csk.classical.alberti_decrypt(moving, disk, start=0, period=1).startswith("EVERY")
assert csk.classical.index_of_coincidence(moving) < csk.classical.index_of_coincidence(still)

fig, axes = plt.subplots(1, 2, figsize=(11, 3.5), sharey=True)
visualizers.plot_letter_frequencies(still, ax=axes[0])
axes[0].set_title("disk held still")
visualizers.plot_letter_frequencies(moving, ax=axes[1])
axes[1].set_title("disk turned after every letter")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# With ``period=1`` the disk returns to its start after 26 letters. Show that
# letters 26 places apart are encrypted the same way, and explain how that
# regularity would help an attacker.
#
# A worked solution is in :doc:`/exercises/classical`.
