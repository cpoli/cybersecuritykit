r"""
Characteristics that ignore the plugboard (Rejewski, 1932)
==========================================================

Enigma operators sent their three-letter message key twice at the start of
each message. Marian Rejewski saw that the first and fourth letters, second
and fifth, third and sixth, define permutations :math:`AD`, :math:`BE` and
:math:`CF`, and that the lengths of their cycles do not depend on the
plugboard at all: conjugating by a permutation preserves cycle structure.
A catalogue of cycle lengths for each rotor start then narrows the key.

Compute the characteristic, confirm the plugboard leaves it unchanged, and
build a small catalogue.
"""

# %%
from collections import Counter

import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# The plugboard does not change the characteristic
# ------------------------------------------------

settings = csk.classical.EnigmaSettings(("III", "I", "II"), "B")
wired = csk.classical.EnigmaSettings(("III", "I", "II"), "B", "AQ BW CE DR FT GY")
bare = csk.classical.rejewski_characteristic(settings, "KDO")
plugged = csk.classical.rejewski_characteristic(wired, "KDO")
assert bare == plugged
print("AD:", bare.ad, "BE:", bare.be, "CF:", bare.cf)
# Products of two involutions: cycle lengths come in equal pairs.
assert all(bare.ad.count(n) % 2 == 0 for n in bare.ad)

# %%
# A small catalogue
# -----------------
# Fix the rotor order and the first letter, try all 676 settings of the other
# two, and count how many share each characteristic.

catalogue = Counter(
    csk.classical.rejewski_characteristic(settings, "K" + a + b)
    for a in csk.constants.ALPHABET
    for b in csk.constants.ALPHABET
)
sizes = Counter(catalogue.values())
assert sizes[1] > len(catalogue) / 2  # Most characteristics point to one start.

fig, ax = plt.subplots(figsize=(7, 3.5))
ax.bar([str(k) for k in sorted(sizes)], [sizes[k] for k in sorted(sizes)], color="#2563eb")
ax.set(
    xlabel="rotor starts sharing a characteristic",
    ylabel="characteristics",
    title=f"{len(catalogue)} characteristics for 676 starts",
)
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Count how many cycles of each permutation the plugboard ``"AB"`` can
# change. Then prove that conjugation, :math:`S P S^{-1}`, never changes
# cycle lengths.
#
# A worked solution is in :doc:`/exercises/classical`.
