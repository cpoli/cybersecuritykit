r"""
SPHINCS stateless hash-based signatures (Bernstein et al., 2015)
================================================================

XMSS breaks if its state is lost. SPHINCS removes the state: the message
itself, hashed with a secret randomizer, picks one of :math:`2^{dh}` leaves of
a hypertree of :math:`d` layers of height :math:`h`. That leaf holds a HORST
*few-time* key, which reveals :math:`k` of its :math:`t = 2^a` secrets per
message. Leaves are picked at random, so a few-time key will sometimes sign
twice; HORST is built so that this costs only a little security. After
:math:`r` signatures on one key, a forger needs every index of a new message to
be already revealed,

.. math::

   \Pr[\text{forgery}] = \bigl(1 - (1 - 1/t)^{rk}\bigr)^{k}.

Sign many messages statelessly, count how often a few-time key is reused, and
forge against a HORST key that signed too often.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.visualizers import plot_few_time_security, plot_key_reuse

pqc = csk.pqc

# %%
# Stateless signing
# -----------------
# No key comes back from signing: the same message always gives the same
# signature, and the verifier climbs from the HORST root through every layer.

key = pqc.sphincs_keygen(5, layers=2, height=2, k=6, a=4, n=16)
signature = pqc.sphincs_sign(key, b"release 1.0")
assert pqc.sphincs_sign(key, b"release 1.0") == signature
assert pqc.sphincs_verify(key.public, b"release 1.0", signature)
assert len(signature.layers) == 2

# %%
# Few-time keys get reused
# ------------------------
# With :math:`2^{2 \cdot 2} = 16` leaves, 40 messages must share keys.

indices = [pqc.sphincs_sign(key, b"message %d" % i).index for i in range(40)]
assert len(set(indices)) <= 16

# %%
# Too many signatures on one HORST key
# ------------------------------------
# Twelve signatures on a small HORST key reveal most of its 64 secrets, and a
# short search finds a new message whose indices are all known.

horst = pqc.horst_keygen(3, k=8, a=6, n=8)
seen = [(m, pqc.horst_sign(horst, m)) for m in (b"m%d" % i for i in range(12))]
forgery = pqc.horst_forge(horst.public, seen, max_tries=50_000)
print(forgery.message, "after", forgery.tested, "candidates")
assert forgery.message is not None and forgery.signature is not None
assert pqc.horst_verify(horst.public, forgery.message, forgery.signature)
print(f"{pqc.few_time_security(8, 6, 12):.1f} bits left after 12 signatures")

fig, (left, right) = plt.subplots(1, 2, figsize=(10, 4))
plot_key_reuse(indices, ax=left)
plot_few_time_security(8, 6, [1, 2, 4, 8, 16, 32], ax=right)
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Real SPHINCS uses :math:`k = 32`, :math:`a = 16` and a hypertree of
# 12 layers and total height 60, so :math:`2^{60}` leaves. Use ``few_time_security`` to explain why
# a few-time key there can sign several times without harm.
#
# A worked solution is in :doc:`/exercises/pqc`.
