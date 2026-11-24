"""State-vector simulations of Shor's period finding (1994) and Grover's search (1996)."""

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def test_period_finding_for_15_peaks_at_multiples_of_q_over_r():
    # 7 has order 4 mod 15: the 256 outcomes concentrate on 0, 64, 128, 192.
    distribution = pqc.shor_distribution(15, 7, 8)
    assert len(distribution) == 256
    for y, p in enumerate(distribution):
        assert abs(p - (0.25 if y % 64 == 0 else 0.0)) < 1e-10


def test_period_finding_for_21_when_r_does_not_divide_q():
    # 2 has order 6 mod 21; 2^10 / 6 is not an integer, so the peaks spread.
    distribution = pqc.shor_distribution(21, 2, 10)
    assert abs(sum(distribution) - 1) < 1e-10
    peaks = sorted(range(1024), key=distribution.__getitem__)[-6:]
    assert sorted(peaks) == [0, 171, 341, 512, 683, 853]  # round(1024 k / 6)


@pytest.mark.parametrize(
    ("n", "base", "period", "factors"), [(15, 7, 4, (3, 5)), (21, 2, 6, (3, 7))]
)
def test_shor_factors_the_textbook_cases(n, base, period, factors):
    result = pqc.shor_factor(n, base=base, seed=1)
    assert (result.n, result.base, result.period, result.factors) == (n, base, period, factors)
    assert result.qubits == 2 * math.ceil(math.log2(n))
    assert len(result.distribution) == 2**result.qubits
    assert 1 <= len(result.measurements) <= 10


def test_a_small_register_is_enough_when_r_divides_q():
    result = pqc.shor_factor(15, base=7, qubits=4, seed=2)
    assert (result.qubits, len(result.distribution), result.factors) == (4, 16, (3, 5))
    assert set(result.measurements) <= {0, 4, 8, 12}


@pytest.mark.parametrize(("n", "base", "period"), [(15, 14, 2), (21, 4, 3)])
def test_bad_bases_find_the_period_but_no_factor(n, base, period):
    # 14 = -1 mod 15 makes a^(r/2) + 1 = 0; 4 has odd order 3 mod 21.
    result = pqc.shor_factor(n, base=base, seed=1)
    assert result.period == period
    assert result.factors is None


@settings(max_examples=15, deadline=None)
@given(st.sampled_from([15, 21, 33, 35, 39]), st.integers(0, 1000))
def test_a_random_base_factors_or_reports_failure(n, seed):
    result = pqc.shor_factor(n, seed=seed)
    assert math.gcd(result.base, n) == 1
    assert pow(result.base, result.period, n) == 1
    if result.factors is not None:
        p, q = result.factors
        assert 1 < p <= q < n and p * q == n


def test_one_unlucky_shot_misses_the_period():
    # Measuring y = 0 says nothing about r.
    misses = [s for s in range(20) if pqc.shor_factor(15, base=7, shots=1, seed=s).period is None]
    assert misses
    result = pqc.shor_factor(15, base=7, shots=1, seed=misses[0])
    assert result.measurements == (0,)
    assert result.factors is None


@settings(max_examples=20, deadline=None)
@given(st.integers(2, 10), st.data())
def test_grover_success_follows_sin_squared(qubits, data):
    space = 2**qubits
    marked = data.draw(st.sets(st.integers(0, space - 1), min_size=1, max_size=3))
    result = pqc.grover_search(qubits, sorted(marked), iterations=12)
    theta = math.asin(math.sqrt(len(marked) / space))
    for k, p in enumerate(result.success):
        assert abs(p - math.sin((2 * k + 1) * theta) ** 2) < 1e-10


def test_grover_finds_one_of_1024_in_25_steps():
    assert pqc.grover_iterations(1024) == 25
    assert pqc.grover_iterations(1024, 4) == 12
    assert pqc.grover_iterations(4, 4) == 0
    result = pqc.grover_search(10, [700], seed=3)
    assert result.iterations == 25
    assert result.success[-1] > 0.999
    assert (result.measured, result.found) == (700, True)
    assert result == pqc.grover_search(10, [700], seed=3)


def test_too_many_iterations_overshoot():
    result = pqc.grover_search(4, [5], iterations=6, seed=0)
    assert result.success[3] > 0.96 > result.success[6]
    assert not pqc.grover_search(4, [5], iterations=6, seed=1).found


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pqc.shor_distribution(15, 5, 8), ValueError),
        (lambda: pqc.shor_distribution(15, 7, 0), ValueError),
        (lambda: pqc.shor_distribution(15, 7, 15), ValueError),
        (lambda: pqc.shor_distribution(1, 1, 4), ValueError),
        (lambda: pqc.shor_factor(16), ValueError),
        (lambda: pqc.shor_factor(13), ValueError),
        (lambda: pqc.shor_factor(25), ValueError),
        (lambda: pqc.shor_factor(65), ValueError),
        (lambda: pqc.shor_factor(15, base=6), ValueError),
        (lambda: pqc.shor_factor(15, base=1), ValueError),
        (lambda: pqc.shor_factor(15, shots=0), ValueError),
        (lambda: pqc.shor_factor(15, seed="1"), TypeError),
        (lambda: pqc.grover_iterations(0), ValueError),
        (lambda: pqc.grover_iterations(4, 5), ValueError),
        (lambda: pqc.grover_search(0, [0]), ValueError),
        (lambda: pqc.grover_search(17, [0]), ValueError),
        (lambda: pqc.grover_search(3, []), ValueError),
        (lambda: pqc.grover_search(3, [8]), ValueError),
        (lambda: pqc.grover_search(3, [1, 1]), ValueError),
        (lambda: pqc.grover_search(3, [1], iterations=-1), ValueError),
        (lambda: pqc.grover_search(3, [1.0]), TypeError),
    ],
)
def test_quantum_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
