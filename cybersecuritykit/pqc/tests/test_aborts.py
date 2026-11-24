"""Lyubashevsky's Fiat-Shamir with aborts (2009), through the public API."""

import dataclasses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pq = csk.pqc


def test_the_key_is_a_ring_sis_instance():
    keys = pq.lyubashevsky_keygen(16, seed=3)
    assert keys == pq.lyubashevsky_keygen(16, seed=3)
    public = keys.public
    assert (public.n, public.q, public.kappa, public.bound) == (16, 8380417, 4, 128)
    assert set(keys.s1) | set(keys.s2) <= {-1, 0, 1}
    # t = a s1 + s2 in Z_q[x]/(x^16 + 1), written out by hand.
    expected = list(keys.s2)
    for i in range(16):
        for j in range(16):
            sign = 1 if i + j < 16 else -1
            expected[(i + j) % 16] += sign * public.a[i] * keys.s1[j]
    assert public.t == tuple(x % public.q for x in expected)


@settings(max_examples=20, deadline=None)
@given(st.integers(0, 10_000), st.binary(max_size=40))
def test_signatures_verify_and_respect_the_bound(seed, message):
    keys = pq.lyubashevsky_keygen(16, seed=seed)
    signature = pq.lyubashevsky_sign(keys, message, seed=seed)
    assert pq.lyubashevsky_verify(keys.public, message, signature)
    assert not pq.lyubashevsky_verify(keys.public, message + b"!", signature)
    limit = keys.public.bound - keys.public.kappa
    assert max(abs(x) for x in signature.z1 + signature.z2) <= limit
    assert sum(map(abs, signature.c)) == keys.public.kappa
    assert signature.attempts >= 1


def test_rejection_takes_several_attempts():
    # Each attempt survives with probability about (1 - kappa/B)^(2n) = e^-1.
    keys = pq.lyubashevsky_keygen(16, seed=1)
    attempts = [pq.lyubashevsky_sign(keys, b"m", seed=s).attempts for s in range(200)]
    assert 2.0 < sum(attempts) / len(attempts) < 4.0
    unchecked = pq.lyubashevsky_sign(keys, b"m", seed=0, abort=False)
    assert unchecked.attempts == 1


def test_oversized_or_altered_signatures_fail():
    keys = pq.lyubashevsky_keygen(16, seed=2)
    signature = pq.lyubashevsky_sign(keys, b"msg", seed=2)
    big = dataclasses.replace(signature, z1=(keys.public.bound,) + signature.z1[1:])
    assert not pq.lyubashevsky_verify(keys.public, b"msg", big)
    other = dataclasses.replace(signature, z2=((signature.z2[0] + 1),) + signature.z2[1:])
    assert not pq.lyubashevsky_verify(keys.public, b"msg", other)
    assert not pq.lyubashevsky_verify(keys.public, b"msg", dataclasses.replace(signature, z1=(0,)))


def test_without_aborts_signatures_leak_the_secret():
    keys = pq.lyubashevsky_keygen(8, kappa=2, bound=16, seed=4)
    leaky = [pq.lyubashevsky_sign(keys, b"m", seed=s, abort=False) for s in range(1500)]
    leak = pq.lyubashevsky_leakage(keys.public, leaky)
    assert leak.signatures == 1500
    assert leak.secret_guess == keys.s1
    safe = [pq.lyubashevsky_sign(keys, b"m", seed=s) for s in range(1500)]
    guess = pq.lyubashevsky_leakage(keys.public, safe).secret_guess
    assert guess != keys.s1
    assert max(map(abs, pq.lyubashevsky_leakage(keys.public, safe).estimate)) < 0.5


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda: pq.lyubashevsky_keygen(12), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, q=1), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, kappa=0), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, kappa=17), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, kappa=4, bound=4), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, kappa=4, bound=200, q=401), ValueError),
        (lambda: pq.lyubashevsky_keygen(16, seed=1.5), TypeError),
        (lambda: pq.lyubashevsky_sign("keys", b"m"), TypeError),
        (lambda: pq.lyubashevsky_sign(pq.lyubashevsky_keygen(8), "m"), TypeError),
        (lambda: pq.lyubashevsky_verify("key", b"m", None), TypeError),
        (lambda: pq.lyubashevsky_verify(pq.lyubashevsky_keygen(8).public, b"m", "sig"), TypeError),
        (lambda: pq.lyubashevsky_verify(pq.lyubashevsky_keygen(8).public, "m", None), TypeError),
        (lambda: pq.lyubashevsky_leakage("key", []), TypeError),
        (lambda: pq.lyubashevsky_leakage(pq.lyubashevsky_keygen(8).public, []), ValueError),
        (lambda: pq.lyubashevsky_leakage(pq.lyubashevsky_keygen(8).public, ["sig"]), TypeError),
    ],
)
def test_aborts_rejects_bad_input(call, error):
    with pytest.raises(error):
        call()
