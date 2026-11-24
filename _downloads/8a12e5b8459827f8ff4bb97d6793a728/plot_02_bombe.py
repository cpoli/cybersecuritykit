r"""
Searching rotor starts from a crib (Turing's bombe, 1940)
=========================================================

Bletchley Park often guessed a word of plaintext, a *crib*, such as
WETTERVORHERSAGE (weather forecast). Because Enigma never encrypts a letter
to itself, a crib can only sit where no letter meets its own image. Alan
Turing's bombe then tested every rotor start against the crib, using loops
in the crib's *menu* to reject wrong settings quickly.

Slide the crib to find the allowed places, draw the menu, and search all
:math:`26^3` starts.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# Where can the crib sit?
# -----------------------

settings = csk.classical.EnigmaSettings(("I", "II", "III"), "B")
ciphertext = csk.classical.enigma_encrypt("WETTERVORHERSAGEBISKAYA", settings, "JXM")
allowed = csk.classical.crib_positions(ciphertext, "WETTERVORHERSAGE")
print("allowed offsets:", allowed)
assert 0 in allowed

# %%
# The menu and its loops
# ----------------------

menu = csk.classical.crib_menu(ciphertext, "WETTERVORHERSAGE", 0)
print(len(menu.edges), "edges,", menu.loops, "loops")
assert menu.loops >= 1

# %%
# Test every rotor start
# ----------------------

result = csk.classical.bombe_search(ciphertext, "WETTERVORHERSAGE", 0, settings)
assert result.tested == 26**3
assert result.positions == ("JXM",)
print("stop:", result.positions)

fig, ax = plt.subplots(figsize=(8, 3))
span = len(ciphertext) - len("WETTERVORHERSAGE") + 1
ax.bar(range(span), [1 if i in allowed else 0 for i in range(span)], color="#2563eb")
ax.set(
    xlabel="crib offset",
    yticks=[0, 1],
    yticklabels=["ruled out", "allowed"],
    title="no letter of the crib may meet itself",
)
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Shorten the crib to ``"WETTER"`` and search again. How many stops does the
# bombe report, and why do longer cribs with more loops give fewer?
#
# A worked solution is in :doc:`/exercises/classical`.
