"""Tests for the shared argument validators."""

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cybersecuritykit import _validation


@given(st.integers(min_value=0))
def test_integer_accepts_values_at_or_above_minimum(value):
    _validation.integer(value, "n")


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_integer_rejects_non_integers(value):
    with pytest.raises(TypeError, match="n must be an integer"):
        _validation.integer(value, "n")


def test_integer_rejects_values_below_minimum():
    with pytest.raises(ValueError, match=">= 2"):
        _validation.integer(1, "n", minimum=2)


def test_seed_accepts_any_integer_and_rejects_the_rest():
    _validation.seed(-5)
    for bad in (True, 1.5, "7", b"7"):
        with pytest.raises(TypeError):
            _validation.seed(bad)


@given(st.floats(min_value=0, max_value=1))
def test_probability_accepts_the_unit_interval(value):
    _validation.probability(value, "p")


@pytest.mark.parametrize("value", [True, "0.5", None])
def test_probability_rejects_non_numbers(value):
    with pytest.raises(TypeError):
        _validation.probability(value, "p")


@pytest.mark.parametrize("value", [-0.1, 1.1, math.nan])
def test_probability_rejects_values_outside_the_unit_interval(value):
    with pytest.raises(ValueError):
        _validation.probability(value, "p")


def test_positive():
    _validation.positive(0.5, "t")
    _validation.positive(3, "t")
    with pytest.raises(TypeError):
        _validation.positive(False, "t")
    for bad in (0, -1, math.inf, math.nan):
        with pytest.raises(ValueError):
            _validation.positive(bad, "t")


def test_byte_string():
    _validation.byte_string(b"", "key")
    _validation.byte_string(b"k", "key", allow_empty=False)
    for bad in (bytearray(b"k"), memoryview(b"k"), "k"):
        with pytest.raises(TypeError, match="key must be bytes"):
            _validation.byte_string(bad, "key")
    with pytest.raises(ValueError, match="must not be empty"):
        _validation.byte_string(b"", "key", allow_empty=False)
