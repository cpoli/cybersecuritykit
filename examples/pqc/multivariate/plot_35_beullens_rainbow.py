r"""
Breaking Rainbow in a weekend (Beullens, 2022)
==============================================

Rainbow (Ding-Schmidt, 2005) stacks oil-and-vinegar layers. The quadratic part
of every public polynomial vanishes on the second layer's oil space
:math:`O_2`. Ward Beullens used the polar form

.. math::

   D(x, y) = P(x + y) - P(x) - P(y) + P(0)

and observed that, for a random :math:`x`, the kernel of
:math:`D_x = D(x, \cdot)` meets :math:`O_2` with useful probability. A vector
:math:`y` there satisfies :math:`P_h(y) = 0` and makes :math:`D_y` low-rank,
and from one such vector the whole of :math:`O_2` follows by linear algebra.
That broke the NIST round-3 SL1 parameters on a laptop in about 53 hours. Run
it on a toy key and check the recovered space against the secret one.
"""

# %%
import matplotlib.pyplot as plt

import cybersecuritykit as csk
from cybersecuritykit.pqc.utils import prime_field
from cybersecuritykit.pqc.visualizers import plot_quadratic_form

pqc = csk.pqc

# %%
# A toy Rainbow key
# -----------------
# Over :math:`\mathrm{GF}(7)`: 3 vinegars, a first layer of 2 oils and a
# second layer of 2 oils, so 4 equations in 7 variables.

q = 7
keys = pqc.rainbow_keygen(q, 3, 2, 2, seed=2026)
signature = pqc.oil_vinegar_sign(keys.private, b"rainbow", seed=1)
assert pqc.oil_vinegar_verify(keys.public, b"rainbow", signature)

# %%
# The attack
# ----------
# It reads only the public key.

result = pqc.beullens_rainbow_attack(keys.public, 2, seed=1)
print(f"{result.guesses} points x, {result.evaluations} kernel vectors tested")
assert len(result.oil_subspace) == 2

# %%
# Checking against the secret key
# -------------------------------
# A vector lies in :math:`O_2` exactly when :math:`S y` has zero vinegar and
# first-layer coordinates.

s = keys.private.s_matrix
for y in (result.oil_vector, *result.oil_subspace):
    assert prime_field.mat_vec(s, y, q)[:5] == [0] * 5

# The quadratic part of the public map vanishes on O2.
n, m = keys.public.n_vars, keys.public.n_polys
homogeneous = pqc.QuadraticMap(q, keys.public.quadratic, ((0,) * n,) * m, (0,) * m)
assert homogeneous.evaluate(result.oil_vector) == (0,) * m

# %%
# The public form in a basis ending with O2
# -----------------------------------------
# Rewritten in a basis whose last two vectors span :math:`O_2`, every public
# polynomial shows the zero corner that the secret change of variables hid.

complement: list[tuple[int, ...]] = []
for i in range(n):
    e = tuple(int(i == j) for j in range(n))
    if prime_field.rank([*complement, e, *result.oil_subspace], q) > len(complement) + 2:
        complement.append(e)
basis = [*complement, *result.oil_subspace]
assert len(basis) == prime_field.rank(basis, q) == n


def change_basis(quad: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
    """Upper-triangular matrix of the quadratic form in the new coordinates."""
    full = [
        [sum(u[i] * quad[i][j] * w[j] for i in range(n) for j in range(n)) for w in basis]
        for u in basis
    ]
    return tuple(
        tuple(
            0 if b < a else full[a][a] % q if a == b else (full[a][b] + full[b][a]) % q
            for b in range(n)
        )
        for a in range(n)
    )


rotated = pqc.QuadraticMap(
    q,
    tuple(change_basis(quad) for quad in keys.public.quadratic),
    keys.public.linear,
    keys.public.constant,
)
for quad in rotated.quadratic:
    assert quad[n - 2][n - 2] == quad[n - 2][n - 1] == quad[n - 1][n - 1] == 0

fig, (left, right) = plt.subplots(1, 2, figsize=(9, 4))
plot_quadratic_form(keys.public, 0, ax=left)
left.set_title("public polynomial 0")
plot_quadratic_form(rotated, 0, ax=right)
right.set_title("last two basis vectors in O2")
fig.tight_layout()

plt.show()

# %%
# Exercise
# --------
# Show that :math:`D(x, y)` is bilinear and that :math:`D(y, y) = 2 P_h(y)`.
# Then argue why a random :math:`x` gives a kernel :math:`\ker D_x` that meets
# :math:`O_2` with probability about :math:`1/q` in this toy.
#
# A worked solution is in :doc:`/exercises/pqc`.
