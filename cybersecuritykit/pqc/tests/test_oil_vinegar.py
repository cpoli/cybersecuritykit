"""UOV, Rainbow and Beullens's attack on Rainbow, through the public API of pqc."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc

UOV = pqc.uov_keygen(7, vinegar=6, oil=3, seed=1)
RAINBOW = pqc.rainbow_keygen(7, 3, 2, 2, seed=2)


def quadratic_part(p, x):
    return tuple(
        sum(quad[i][j] * x[i] * x[j] for i in range(p.n_vars) for j in range(p.n_vars)) % p.q
        for quad in p.quadratic
    )


def test_uov_central_map_has_no_oil_times_oil_terms():
    central = UOV.private.central
    assert UOV.private.layers == ((6, 3),)
    assert (central.n_vars, central.n_polys) == (9, 3)
    for quad in central.quadratic:
        assert all(quad[i][j] == 0 for i in range(6, 9) for j in range(6, 9))
    # The public map mixes the variables: oil-times-oil terms appear.
    assert any(
        quad[i][j] for quad in UOV.public.quadratic for i in range(6, 9) for j in range(6, 9)
    )


def test_rainbow_central_map_is_layered():
    central = RAINBOW.private.central
    assert RAINBOW.private.layers == ((3, 2), (5, 2))
    assert (central.n_vars, central.n_polys) == (7, 4)
    for quad, lin in zip(central.quadratic[:2], central.linear[:2], strict=True):
        # Layer 1 uses only the first 5 variables and has no product of its oils 3, 4.
        assert all(quad[i][j] == 0 for i in range(7) for j in range(7) if max(i, j) >= 5)
        assert all(lin[i] == 0 for i in range(5, 7))
        assert quad[3][3] == quad[3][4] == quad[4][4] == 0
    for quad in central.quadratic[2:]:
        assert quad[5][5] == quad[5][6] == quad[6][6] == 0


@pytest.mark.parametrize("keys", [UOV, RAINBOW], ids=["uov", "rainbow"])
def test_signatures_verify_and_bind_the_message(keys):
    signature = pqc.oil_vinegar_sign(keys.private, b"toy message", seed=4)
    assert len(signature) == keys.public.n_vars
    assert pqc.oil_vinegar_verify(keys.public, b"toy message", signature)
    assert not pqc.oil_vinegar_verify(keys.public, b"toy messagE", signature)
    assert signature != pqc.oil_vinegar_sign(keys.private, b"toy message", seed=5)


@settings(max_examples=25, deadline=None)
@given(st.binary(max_size=40), st.integers(0, 2**32))
def test_uov_sign_verify_property(message, seed):
    signature = pqc.oil_vinegar_sign(UOV.private, message, seed=seed)
    assert pqc.oil_vinegar_verify(UOV.public, message, signature)


def test_signing_over_a_tiny_field_retries_singular_vinegar_choices():
    keys = pqc.rainbow_keygen(3, 2, 2, 2, seed=9)
    for i in range(40):
        message = bytes([i])
        assert pqc.oil_vinegar_verify(
            keys.public, message, pqc.oil_vinegar_sign(keys.private, message, seed=i)
        )


def test_beullens_recovers_the_secret_oil_subspace_of_rainbow():
    result = pqc.beullens_rainbow_attack(RAINBOW.public, 2, seed=3)
    assert len(result.oil_subspace) == 2 and len(result.w_subspace) == 2
    assert result.guesses >= 1 and result.evaluations >= 1
    s = RAINBOW.private.s_matrix
    for y in (result.oil_vector, *result.oil_subspace):
        assert any(y)
        # In the secret coordinates z = S y only the last-layer oil variables are non-zero.
        z = [sum(a * b for a, b in zip(row, y, strict=True)) % 7 for row in s]
        assert z[:5] == [0] * 5
        assert quadratic_part(RAINBOW.public, y) == (0,) * 4


def test_beullens_on_larger_toy_rainbow():
    keys = pqc.rainbow_keygen(5, 4, 3, 3, seed=6)
    result = pqc.beullens_rainbow_attack(keys.public, 3, seed=1)
    assert len(result.oil_subspace) == 3
    for y in result.oil_subspace:
        z = [sum(a * b for a, b in zip(row, y, strict=True)) % 5 for row in keys.private.s_matrix]
        assert z[:7] == [0] * 7


def test_beullens_gives_up_after_max_guesses():
    failures = 0
    for seed in range(10):
        try:
            pqc.beullens_rainbow_attack(RAINBOW.public, 2, seed=seed, max_guesses=1)
        except RuntimeError:
            failures += 1
    assert failures > 0


def test_oil_vinegar_rejects_bad_parameters():
    with pytest.raises(ValueError, match="odd prime"):
        pqc.uov_keygen(9, vinegar=4, oil=2, seed=0)
    with pytest.raises(ValueError, match="odd prime"):
        pqc.rainbow_keygen(2, 2, 2, 2, seed=0)
    with pytest.raises(ValueError, match="oil"):
        pqc.uov_keygen(7, vinegar=4, oil=0, seed=0)
    with pytest.raises(ValueError, match="vinegar"):
        pqc.uov_keygen(7, vinegar=0, oil=2, seed=0)
    with pytest.raises(ValueError, match="o2"):
        pqc.rainbow_keygen(7, 2, 2, 0, seed=0)
    with pytest.raises(TypeError):
        pqc.oil_vinegar_sign(UOV.private, "text", seed=0)
    with pytest.raises(ValueError, match="length 9"):
        pqc.oil_vinegar_verify(UOV.public, b"", (0,))
    with pytest.raises(ValueError, match="o2"):
        pqc.beullens_rainbow_attack(RAINBOW.public, 0, seed=0)
    with pytest.raises(ValueError, match="max_guesses"):
        pqc.beullens_rainbow_attack(RAINBOW.public, 2, seed=0, max_guesses=0)
