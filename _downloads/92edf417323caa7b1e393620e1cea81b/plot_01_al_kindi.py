r"""
Frequency analysis breaks the shift cipher (al-Kindi, c. 850)
=============================================================

al-Kindi observed that in any long text of a language some letters are
common and others rare, and that a substitution cipher moves those counts to
other letters without changing them. Counting the ciphertext and matching
the counts against the language reveals the key.

Encrypt a passage with a shift cipher, score all 26 shifts by Pearson's
:math:`\chi^2` distance from English letter frequencies, and keep the best.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# Encrypt with a secret shift
# ---------------------------

passage = (
    "The harbour master kept the lamp burning through the night, and every ship that "
    "passed the cliffs saw the light and turned away from the rocks below the town"
)
ciphertext = csk.classical.shift_encrypt(passage, 17)
print(ciphertext[:40], "...")

# %%
# Count, compare, and read off the key
# ------------------------------------
# The ciphertext letter counts are English counts moved 17 places on.

result = csk.classical.break_shift_cipher(ciphertext)
assert result.shift == 17
assert result.plaintext.startswith("THEHARBOURMASTER")
print("recovered shift:", result.shift)

fig, axes = plt.subplots(1, 2, figsize=(11, 3.5))
visualizers.plot_letter_frequencies(ciphertext, ax=axes[0])
visualizers.plot_shift_scores(result, ax=axes[1])
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Shorten the passage to its first 20 letters, then its first 10. At what
# length does the minimum of the :math:`\chi^2` scores stop landing on 17?
#
# A worked solution is in :doc:`/exercises/classical`.
