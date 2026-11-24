"""Ajtai's SIS hash (1996) and its collisions through the public API."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def test_ajtai_hash_is_a_matrix_vector_product_mod_q():
    key = pqc.AjtaiKey(((1, 2, 3), (4, 5, 6)), 7)
    # Column 0 plus column 2: (1 + 3, 4 + 6) = (4, 10) = (4, 3) mod 7.
    assert pqc.ajtai_hash(key, (1, 0, 1)) == (4, 3)
    assert pqc.ajtai_hash(key, (0, 0, 0)) == (0, 0)


def test_keygen_is_seeded_and_compresses():
    key = pqc.ajtai_keygen(2, 8, 11, seed=5)
    assert key == pqc.ajtai_keygen(2, 8, 11, seed=5)
    assert key != pqc.ajtai_keygen(2, 8, 11, seed=6)
    assert len(key.matrix) == 2 and all(len(row) == 8 for row in key.matrix)
    assert all(0 <= x < 11 for row in key.matrix for x in row)


def test_a_collision_is_a_short_solution_of_the_sis_problem():
    key = pqc.ajtai_keygen(2, 8, 11, seed=1)
    collision = pqc.ajtai_collision(key)
    assert collision.x != collision.y
    assert pqc.ajtai_hash(key, collision.x) == pqc.ajtai_hash(key, collision.y)
    assert collision.difference == tuple(
        a - b for a, b in zip(collision.x, collision.y, strict=True)
    )
    assert set(collision.difference) <= {-1, 0, 1}
    for row in key.matrix:
        assert sum(a * z for a, z in zip(row, collision.difference, strict=True)) % 11 == 0
    # Pigeonhole: 11^2 + 1 inputs always contain a collision.
    assert collision.tested <= 11**2 + 1


@settings(max_examples=25, deadline=None)
@given(st.integers(0, 10_000), st.lists(st.integers(0, 1), min_size=8, max_size=8),
       st.lists(st.integers(0, 1), min_size=8, max_size=8))  # fmt: skip
def test_the_hash_is_linear(seed, x, y):
    key = pqc.ajtai_keygen(2, 8, 11, seed)
    hx, hy = pqc.ajtai_hash(key, x), pqc.ajtai_hash(key, y)
    s = [a + b for a, b in zip(x, y, strict=True)]
    # A(x + y) = Ax + Ay mod q, checked through the matrix itself for 0/1/2 entries.
    expected = tuple(sum(a * v for a, v in zip(row, s, strict=True)) % 11 for row in key.matrix)
    assert tuple((a + b) % 11 for a, b in zip(hx, hy, strict=True)) == expected


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pqc.ajtai_keygen(0, 8, 11), ValueError),
        (lambda: pqc.ajtai_keygen(2, 6, 11), ValueError),  # 2^6 < 11^2: no compression
        (lambda: pqc.ajtai_keygen(2, 8, 1), ValueError),
        (lambda: pqc.ajtai_keygen(2, 8, 11, seed="a"), TypeError),
        (lambda: pqc.ajtai_hash("key", (0, 1)), TypeError),
        (lambda: pqc.ajtai_hash(pqc.AjtaiKey(((1, 2),), 5), (0, 1, 1)), ValueError),
        (lambda: pqc.ajtai_hash(pqc.AjtaiKey(((1, 2),), 5), (0, 2)), ValueError),
        (lambda: pqc.ajtai_collision("key"), TypeError),
        (lambda: pqc.ajtai_collision(pqc.ajtai_keygen(2, 8, 11), limit=1), ValueError),
        (lambda: pqc.ajtai_collision(pqc.ajtai_keygen(2, 8, 11), limit=2), ValueError),
        (lambda: pqc.ajtai_collision(pqc.ajtai_keygen(2, 8, 11), limit=True), TypeError),
    ],
)
def test_ajtai_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
