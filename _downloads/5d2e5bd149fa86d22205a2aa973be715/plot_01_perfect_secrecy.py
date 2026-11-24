r"""
Perfect secrecy (Shannon, 1949)
===============================

Claude Shannon defined a cipher as *perfectly secret* when seeing the
ciphertext leaves the attacker's beliefs unchanged:
:math:`P(m \mid c) = P(m)` for every message :math:`m`. He proved this needs
at least as many keys as messages. The one-time pad
(`blockchainkit <https://cpoli.github.io/blockchainkit/>`__) meets the bound;
a shift cipher meets it for one letter but not for two.

Compute the attacker's posterior by Bayes' rule over every key.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.classical import visualizers

# %%
# One letter under a shift: perfectly secret
# ------------------------------------------

single = csk.classical.shift_cipher_posterior({"A": 0.7, "B": 0.3}, "Q")
assert single.perfect

# %%
# Two letters under a shift: the ciphertext leaks
# -----------------------------------------------
# AB shifts to BC with key 1, but no single shift turns AC into BC.

prior = {"AB": 0.5, "AC": 0.25, "ZZ": 0.25}
shift = csk.classical.shift_cipher_posterior(prior, "BC")
assert not shift.perfect and abs(shift.posterior["AB"] - 1) < 1e-10

# %%
# Two letters under a one-time pad: perfectly secret again
# --------------------------------------------------------

pad = csk.classical.one_time_pad_posterior(prior, "BC")
assert pad.perfect

fig, axes = plt.subplots(1, 2, figsize=(10, 3.5), sharey=True)
visualizers.plot_posterior(shift, ax=axes[0])
visualizers.plot_posterior(pad, ax=axes[1])
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# With a prior over all 676 two-letter messages, how many shift keys would
# perfect secrecy need? Compare with the 26 the shift cipher has.
#
# A worked solution is in :doc:`/exercises/classical`.
