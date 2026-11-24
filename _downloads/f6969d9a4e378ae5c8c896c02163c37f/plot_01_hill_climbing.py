r"""
Hill climbing a substitution key (Jakobsen, 1995)
=================================================

A simple substitution has :math:`26! \approx 4 \times 10^{26}` keys, too many
to try. Thomas Jakobsen's fast method starts from the frequency-matched key
and keeps swapping pairs of key letters whenever the swap makes the decryption
score better on English bigrams. Computers made this local search, far too
slow by hand, routine.

Encrypt a passage, climb, and watch the score rise.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# Encrypt with a random-looking key
# ---------------------------------

passage = (
    "When the messenger reached the northern fort he found the gates closed and the walls "
    "lined with archers who would not let him pass until the captain had read the letter. "
    "The captain was a careful man who trusted nobody, and he held the sealed paper up to "
    "the light before he broke the wax. Inside there were only rows of letters that made "
    "no sense at all, and he called for the old scribe who kept the books of the garrison. "
    "The scribe sat down at the long table with a candle and a sheet of clean paper and "
    "began to count the letters one by one. He noticed that some groups of three letters "
    "appeared again and again at regular distances, and he wrote those distances in a "
    "column at the side of the page. By morning he had found that every distance could be "
    "divided by the same small number, and from that number he guessed the length of the "
    "secret word. Then the rest was only patience, because each column of letters had been "
    "shifted by a single amount and could be solved like the simple ciphers of the market. "
    "When the captain read the message at last he ordered the gates to be opened, and the "
    "soldiers rode out before noon to meet the enemy at the river crossing"
)
key = "QWERTYUIOPASDFGHJKLZXCVBNM"
ciphertext = csk.classical.substitution_encrypt(passage, key)

# %%
# Climb
# -----

result = csk.classical.hill_climb_substitution(ciphertext, seed=2026, restarts=3)
truth = csk.classical.substitution_decrypt(ciphertext, key)
correct = sum(a == b for a, b in zip(result.plaintext, truth, strict=True)) / len(truth)
print(f"{correct:.0%} of letters right:", result.plaintext[:60])
assert correct > 0.9

ax = visualizers.plot_climb_history(result)

plt.show()

# %%
# Exercise
# --------
# Run the climb on the first 100 letters only. Does it still read the text?
# Relate the answer to the unicity distance of simple substitution.
