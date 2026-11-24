"""Prange's information-set decoding, through the public API of cybersecuritykit.pqc."""

import math

import pytest

import cybersecuritykit as csk

pqc = csk.pqc

# The [7, 4] Hamming code: column j of H is j + 1 written in binary, low bit first.
HAMMING_H = (
    (1, 0, 1, 0, 1, 0, 1),
    (0, 1, 1, 0, 0, 1, 1),
    (0, 0, 0, 1, 1, 1, 1),
)


def test_syndrome_of_a_single_error_names_its_position():
    # Hamming's design: the syndrome of an error in position j is j + 1 in binary.
    error = (0, 0, 0, 0, 1, 0, 0)
    assert pqc.syndrome(HAMMING_H, error) == (1, 0, 1)


@pytest.mark.parametrize("position", range(7))
def test_prange_finds_every_single_error_of_the_hamming_code(position):
    error = tuple(int(i == position) for i in range(7))
    result = pqc.prange_isd(HAMMING_H, pqc.syndrome(HAMMING_H, error), 1, seed=position)
    assert result.error == error
    assert result.iterations >= 1
    assert len(result.columns) == 3
    assert pqc.syndrome(HAMMING_H, result.error) == pqc.syndrome(HAMMING_H, error)


def test_prange_of_a_zero_syndrome_is_the_zero_word():
    result = pqc.prange_isd(HAMMING_H, (0, 0, 0), 1, seed=1)
    assert result.error == (0,) * 7 and result.iterations >= 1


def test_prange_success_probability_is_the_binomial_ratio():
    # Pr[the t errors all avoid a random information set of k positions].
    assert pqc.prange_success_probability(7, 4, 1) == pytest.approx(3 / 7)
    assert pqc.prange_success_probability(32, 17, 3) == pytest.approx(2730 / 29760)
    assert pqc.prange_success_probability(10, 5, 6) == 0.0
    assert math.isclose(pqc.prange_success_probability(5, 0, 5), 1.0)


def test_prange_gives_up_after_max_iterations():
    # A weight-0 search for a non-zero syndrome never succeeds.
    with pytest.raises(RuntimeError, match="no error of weight"):
        pqc.prange_isd(HAMMING_H, (1, 1, 1), 0, seed=0, max_iterations=20)


def test_prange_rejects_bad_inputs():
    with pytest.raises(ValueError, match="rectangular"):
        pqc.prange_isd(((1, 0), (1,)), (0, 0), 1, seed=0)
    with pytest.raises(ValueError, match="0 or 1"):
        pqc.prange_isd(((2, 0),), (0,), 1, seed=0)
    with pytest.raises(ValueError, match="length"):
        pqc.prange_isd(HAMMING_H, (0, 1), 1, seed=0)
    with pytest.raises(ValueError, match="full row rank"):
        pqc.prange_isd(((1, 1), (1, 1)), (0, 0), 1, seed=0)
    with pytest.raises(ValueError, match="non-empty"):
        pqc.prange_isd((), (), 1, seed=0)
    with pytest.raises(TypeError):
        pqc.prange_isd(HAMMING_H, (0, 0, 0), True, seed=0)
    with pytest.raises(TypeError):
        pqc.prange_isd(HAMMING_H, (0, 0, 0), 1, seed="x")
    with pytest.raises(ValueError):
        pqc.prange_isd(HAMMING_H, (0, 0, 0), 1, seed=0, max_iterations=0)
    with pytest.raises(ValueError, match="k"):
        pqc.prange_success_probability(4, 5, 1)
    with pytest.raises(ValueError, match="t"):
        pqc.prange_success_probability(4, 2, 5)
