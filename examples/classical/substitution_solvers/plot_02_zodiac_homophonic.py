r"""
Annealing a homophonic cipher (the Zodiac 340, 2020)
====================================================

A homophonic cipher gives common letters several symbols, so every symbol
appears about equally often and letter counting fails. The Zodiac killer's
340-symbol cipher of 1969 resisted for 51 years until David Oranchak, Sam Blake
and Jarl Van Eycke solved it in December 2020 with AZdecrypt, a simulated
annealing solver scoring candidate plaintexts against language statistics.

Build a homophonic key, see the flattened counts, and anneal.
"""

# %%
from collections import Counter

import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# A homophonic key and its flat counts
# ------------------------------------

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
key = csk.classical.homophonic_key(seed=1, symbols=30)
print("symbols for E:", key["E"], " for Z:", key["Z"])
symbols = csk.classical.homophonic_encrypt(passage, key)
plain = csk.classical.homophonic_decrypt(symbols, key)

# %%
# Anneal
# ------

result = csk.classical.solve_homophonic(symbols, seed=2026)
correct = sum(a == b for a, b in zip(result.plaintext, plain, strict=True)) / len(plain)
print(f"{correct:.0%} of letters right:", result.plaintext[:60])
assert correct > 0.8

letters = Counter(plain)
cipher = Counter(symbols)
fig, ax = plt.subplots(figsize=(8, 3.5))
ax.plot(sorted(letters.values(), reverse=True), "o-", color="#94a3b8", label="plaintext letters")
ax.plot(sorted(cipher.values(), reverse=True), "o-", color="#2563eb", label="cipher symbols")
ax.set(xlabel="rank", ylabel="count", title="homophones flatten the counts")
ax.legend()
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Raise ``symbols`` to 60. Does the solver still read the text from the same
# passage? Explain why more homophones need more ciphertext.
