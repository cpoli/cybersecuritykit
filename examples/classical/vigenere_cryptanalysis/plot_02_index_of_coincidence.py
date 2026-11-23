r"""
The index of coincidence (Friedman, 1922)
=========================================

William Friedman measured how often two letters drawn from a text are equal.
English gives about 0.066, random letters :math:`1/26 \approx 0.038`. Split a
Vigenere ciphertext into :math:`m` columns: when :math:`m` is the key length
each column is a shift cipher and its index jumps back to English. Each
column then falls to frequency analysis.

Scan the candidate periods, then break each column and read the key.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# English versus random letters
# -----------------------------

passage = (
    "The scribe sat down at the long table with a candle and a sheet of clean paper and "
    "began to count the letters one by one. He noticed that some groups of three letters "
    "appeared again and again at regular distances, and he wrote those distances in a "
    "column at the side of the page. By morning he had found that every distance could be "
    "divided by the same small number, and from that number he guessed the length of the "
    "secret word. Then the rest was only patience"
)
ciphertext = csk.classical.vigenere_encrypt(passage, "CIPHER")
print("plaintext IC:", round(csk.classical.index_of_coincidence(passage), 3))
print("ciphertext IC:", round(csk.classical.index_of_coincidence(ciphertext), 3))

# %%
# Scan the periods, then solve each column
# ----------------------------------------

profile = csk.classical.coincidence_profile(ciphertext, max_period=12)
assert profile.best_period == 6
broken = csk.classical.break_vigenere(ciphertext, profile.best_period)
assert broken.key == "CIPHER"
print("key:", broken.key)

ax = visualizers.plot_coincidence_profile(profile)

plt.show()

# %%
# Exercise
# --------
# Periods 12 also score high. Why do multiples of the key length look English
# too, and why does the profile prefer the smallest one?
