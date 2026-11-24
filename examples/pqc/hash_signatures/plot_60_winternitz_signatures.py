r"""
Winternitz one-time signatures (Winternitz, 1979)
=================================================

Lamport's one-time signature reveals one of two secrets per message bit, as
taught in `blockchainkit's Lamport example
<https://cpoli.github.io/blockchainkit/api/gallery/crypto/hash_signatures/plot_01_lamport_signatures.html>`__.
Robert Winternitz's idea, published by Merkle, signs :math:`\log_2 w` bits at
once: each base-:math:`w` digit :math:`d_i` of the digest is signed by hashing a
secret :math:`d_i` times along a chain whose end is public,

.. math::

   \sigma_i = H^{d_i}(s_i), \qquad H^{w-1-d_i}(\sigma_i) = p_i.

Anyone can hash a signature chain further, so a checksum of the digits is
signed too: raising one digit must lower another. Sign with one key, weigh
size against work, then reuse the key and forge.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_winternitz_tradeoff

pqc = csk.pqc

# %%
# One key, one signature
# ----------------------
# With 16-byte hashes and :math:`w = 16` there are 32 message digits and 3
# checksum digits, so 35 chains.

key = pqc.winternitz_keygen(11, n=16, w=16)
signature = pqc.winternitz_sign(key, b"pay alice 10")
assert len(signature.chains) == 35
assert pqc.winternitz_verify(key.public, b"pay alice 10", signature)
assert not pqc.winternitz_verify(key.public, b"pay alice 99", signature)

# %%
# The width trades size for hashing
# ---------------------------------
# A larger :math:`w` gives fewer, longer chains: smaller signatures, more work.

small, large = pqc.winternitz_cost(16, 2), pqc.winternitz_cost(16, 256)
print(small)
print(large)
assert small.signature_bytes > large.signature_bytes
assert small.keygen_hashes < large.keygen_hashes

# %%
# Reusing the key
# ---------------
# Each extra signature reveals chain values lower down. A forger holding the
# lowest value seen on every chain can sign any message whose digits are all
# at least those minima, and searches for one.

messages = [b"pay alice %d" % i for i in range(4)]
small_key = pqc.winternitz_keygen(11, n=8, w=16)
observed = [(m, pqc.winternitz_sign(small_key, m)) for m in messages]
forgery = pqc.winternitz_forge(small_key.public, observed)
print(forgery.message, "after", forgery.tested, "candidates")
assert forgery.message is not None and forgery.signature is not None
assert forgery.message not in messages
assert pqc.winternitz_verify(small_key.public, forgery.message, forgery.signature)

ax = plot_winternitz_tradeoff()
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# With one observed signature the forger fails. Explain how the checksum
# stops it, and why two signatures with different digits can be enough.
#
# A worked solution is in :doc:`/exercises/pqc`.
