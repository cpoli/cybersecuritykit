r"""
XMSS Merkle signatures and state rollback (Buchmann, Dahmen and Hülsing, 2011)
==============================================================================

A one-time key signs one message. Merkle's answer, taught in `blockchainkit's
Merkle tree entry
<https://cpoli.github.io/blockchainkit/history/structures_breakthroughs.html#merkle-trees-and-compact-authentication>`__,
is to hash :math:`2^h` one-time public keys into a tree and publish only the
root. XMSS uses Winternitz keys as leaves; a signature carries the leaf index
:math:`i`, the one-time signature and the :math:`h` sibling hashes that lead
from leaf to root,

.. math::

   \text{node}_{\ell+1} = H(\text{node}_\ell \,\|\, \text{sibling}_\ell).

The scheme is *stateful*: the signer must never use a leaf twice. Sign a few
messages, draw one authentication path, then restore an old key state and
watch the forger use the reused leaf.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_auth_path

pqc = csk.pqc

# %%
# Signing advances the state
# --------------------------
# Each call returns the signature and the next key, whose ``next_index`` has
# moved on. A height-3 tree holds eight one-time keys.

key = pqc.xmss_keygen(5, height=3, n=8)
signed = []
for i in range(3):
    result = pqc.xmss_sign(key, b"block %d" % i)
    signed.append((b"block %d" % i, result.signature))
    key = result.key
assert [s.index for _, s in signed] == [0, 1, 2]
assert key.next_index == 3
assert all(len(s.auth_path) == 3 for _, s in signed)
assert all(pqc.xmss_verify(key.public, m, s) for m, s in signed)

# %%
# A rolled-back state reuses a leaf
# ---------------------------------
# A virtual machine restored from a snapshot, or a key copied to a second
# server, signs again from an old ``next_index``. Leaf 0 now carries several
# messages, and its Winternitz key leaks like any reused one-time key.

snapshot = pqc.xmss_keygen(9, height=2, n=8)
reused = [(m, pqc.xmss_sign(snapshot, m).signature) for m in (b"a", b"b", b"c", b"d")]
assert {s.index for _, s in reused} == {0}
forgery = pqc.xmss_forge(snapshot.public, reused)
print(forgery.message, "after", forgery.tested, "candidates")
assert forgery.message is not None and forgery.signature is not None
assert pqc.xmss_verify(snapshot.public, forgery.message, forgery.signature)

ax = plot_auth_path(signed[2][1])
ax.figure.tight_layout()

plt.show()

# %%
# Exercise
# --------
# How many hashes does a verifier compute for the authentication path of a
# height-:math:`h` tree, and how many one-time keys does the key hold? Why
# does the forger need several signatures on the *same* leaf rather than one
# signature on each of several leaves?
#
# A worked solution is in :doc:`/exercises/pqc`.
