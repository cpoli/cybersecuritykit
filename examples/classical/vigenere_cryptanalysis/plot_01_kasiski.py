r"""
Repeated fragments give the key length (Kasiski, 1863)
======================================================

Friedrich Kasiski noticed that when the same plaintext fragment meets the
same part of a repeating keyword, it produces the same ciphertext fragment.
The distances between repeats are therefore multiples of the keyword length,
and their most common factor is the length itself.

Encrypt a long passage with a keyword, collect the repeated trigrams, and
count the factors of their distances.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# Collect repeats and factor their distances
# ------------------------------------------

passage = (
    "When the messenger reached the northern fort he found the gates closed and the walls "
    "lined with archers who would not let him pass until the captain had read the letter. "
    "The captain was a careful man who trusted nobody, and he held the sealed paper up to "
    "the light before he broke the wax. Inside there were only rows of letters that made "
    "no sense at all, and he called for the old scribe who kept the books of the garrison"
)
ciphertext = csk.classical.vigenere_encrypt(passage, "LEMON")
result = csk.classical.kasiski_examination(ciphertext)
for trigram, positions in list(result.repeats.items())[:5]:
    print(trigram, positions)
assert result.likely_period == 5

ax = visualizers.plot_kasiski_factors(result)

plt.show()

# %%
# Exercise
# --------
# Factors 2 and 3 are counted for nearly every distance. Explain why the
# examination still prefers 5, and what happens with the keyword ``"LEMONS"``.
