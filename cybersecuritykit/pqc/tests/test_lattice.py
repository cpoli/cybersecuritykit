"""LLL lattice reduction (Lenstra, Lenstra and Lovász, 1982) through the public API."""

from fractions import Fraction

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def _gram_schmidt(basis):
    out = []
    for b in basis:
        v = [Fraction(x) for x in b]
        for u in out:
            if not any(u):
                continue
            mu = sum(Fraction(x) * y for x, y in zip(b, u, strict=True)) / sum(y * y for y in u)
            v = [x - mu * y for x, y in zip(v, u, strict=True)]
        out.append(v)
    return out


def _determinant_squared(basis):
    result = Fraction(1)
    for v in _gram_schmidt(basis):
        result *= sum(x * x for x in v)
    return result


def _coordinates(basis, vector):
    """Solve ``x B = vector`` over the rationals by Gauss-Jordan elimination."""
    n = len(basis)
    rows = [[Fraction(basis[j][i]) for j in range(n)] + [Fraction(vector[i])] for i in range(n)]
    for col in range(n):
        pivot = next(r for r in range(col, n) if rows[r][col])
        rows[col], rows[pivot] = rows[pivot], rows[col]
        rows[col] = [x / rows[col][col] for x in rows[col]]
        for r in range(n):
            if r != col and rows[r][col]:
                f = rows[r][col]
                rows[r] = [x - f * y for x, y in zip(rows[r], rows[col], strict=True)]
    return [row[n] for row in rows]


def test_lll_reduces_the_wikipedia_example():
    # Wikipedia, "Lenstra-Lenstra-Lovász lattice basis reduction algorithm", delta = 3/4.
    result = pqc.lll_reduce([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
    assert result.basis == ((0, 1, 0), (1, 0, 1), (-1, 0, 2))
    assert result.swaps >= 1


def test_lll_finds_a_short_basis_of_a_skewed_lattice():
    # 21*55 - 34*34 = -1, so the lattice is Z^2 and LLL must find two unit-length vectors.
    result = pqc.lll_reduce([[21, 34], [34, 55]])
    assert sorted(sum(x * x for x in row) for row in result.basis) == [1, 1]


def test_lll_records_gram_schmidt_norms_before_and_after():
    basis = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
    result = pqc.lll_reduce(basis)
    before = [float(sum(x * x for x in v)) ** 0.5 for v in _gram_schmidt(basis)]
    after = [float(sum(x * x for x in v)) ** 0.5 for v in _gram_schmidt(result.basis)]
    assert result.norms_before == pytest.approx(before)
    assert result.norms_after == pytest.approx(after)


def test_an_already_reduced_basis_is_left_alone():
    result = pqc.lll_reduce([[1, 0], [0, 1]])
    assert result.basis == ((1, 0), (0, 1)) and result.swaps == 0


small_bases = st.integers(2, 4).flatmap(
    lambda n: st.lists(
        st.lists(st.integers(-20, 20), min_size=n, max_size=n), min_size=n, max_size=n
    )
)


@settings(max_examples=40, deadline=None)
@given(small_bases, st.sampled_from([0.5, 0.75, 0.99]))
def test_lll_output_is_size_reduced_lovasz_and_spans_the_same_lattice(basis, delta):
    if _determinant_squared(basis) == 0:
        with pytest.raises(ValueError):
            pqc.lll_reduce(basis, delta)
        return
    result = pqc.lll_reduce(basis, delta)
    assert _determinant_squared(result.basis) == _determinant_squared(basis)
    star = _gram_schmidt(result.basis)
    norms = [sum(x * x for x in v) for v in star]
    for i, b in enumerate(result.basis):
        for j in range(i):
            mu = sum(Fraction(x) * y for x, y in zip(b, star[j], strict=True)) / norms[j]
            assert abs(mu) <= Fraction(1, 2)
            if j == i - 1:
                assert norms[i] >= (Fraction(delta) - mu * mu) * norms[j]
    for row in result.basis:
        assert all(x.denominator == 1 for x in _coordinates(basis, row))


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pqc.lll_reduce([]), ValueError),
        (lambda: pqc.lll_reduce([[1, 2], [3]]), ValueError),
        (lambda: pqc.lll_reduce([[1, 2], [2, 4]]), ValueError),
        (lambda: pqc.lll_reduce([[1, 2, 3], [4, 5, 6], [5, 7, 9]]), ValueError),
        (lambda: pqc.lll_reduce([[1, 0], [0, 1], [1, 1]]), ValueError),
        (lambda: pqc.lll_reduce([[1.5, 2], [3, 4]]), TypeError),
        (lambda: pqc.lll_reduce([[1, 0], [0, 1]], delta=0.2), ValueError),
        (lambda: pqc.lll_reduce([[1, 0], [0, 1]], delta=1.0), ValueError),
        (lambda: pqc.lll_reduce([[1, 0], [0, 1]], delta="x"), TypeError),
    ],
)
def test_lll_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
