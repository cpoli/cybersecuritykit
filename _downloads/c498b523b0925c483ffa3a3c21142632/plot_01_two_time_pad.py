r"""
Vernam's cipher and the two-time pad (Vernam, 1917)
===================================================

Gilbert Vernam's teleprinter combined each character of a message with a
character of a key tape, :math:`c_i = m_i \oplus k_i`. With a random tape
used once this is the one-time pad, taught in
`blockchainkit <https://cpoli.github.io/blockchainkit/>`__. Here the tape is
used twice: XORing the two ciphertexts cancels the key and leaves
:math:`m_1 \oplus m_2`, which a guessed word (a *crib*) unpicks.

Encrypt two messages under one tape, cancel the key, and drag a crib along.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk

# %%
# Two messages, one tape
# ----------------------

tape = bytes((37 * i + 11) % 256 for i in range(40))  # A fixed, non-random tape.
first = b"MEET AT THE NORTH GATE AT DAWN"
second = b"RETREAT TO THE OLD MILL TONIGH"
c1, c2 = csk.classical.vernam_encrypt(first, tape), csk.classical.vernam_encrypt(second, tape)
assert csk.classical.vernam_encrypt(c1, tape) == first

# %%
# The key cancels
# ---------------

combined = csk.classical.two_time_pad(c1, c2)
assert combined == bytes(a ^ b for a, b in zip(first, second, strict=True))

# %%
# Drag a crib along the combined stream
# -------------------------------------
# Wherever the first message really contains the crib, the other message
# appears in clear. Printable fragments are the candidates.

hits = csk.classical.crib_drag(c1, c2, b" THE ")
for hit in hits:
    print(hit.offset, hit.fragment)
assert any(hit.offset == 7 and hit.fragment == b" TO T" for hit in hits)

fig, ax = plt.subplots(figsize=(9, 3))
ax.bar(range(len(combined)), list(combined), color="#2563eb")
ax.set(
    xlabel="position",
    ylabel="byte",
    title="ciphertext XOR ciphertext = plaintext XOR plaintext",
)
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Many bytes of the combined stream are small. Explain why two upper-case
# ASCII texts XOR to values below 32, and why a space XORs a letter into its
# lower-case form.
#
# A worked solution is in :doc:`/exercises/classical`.
