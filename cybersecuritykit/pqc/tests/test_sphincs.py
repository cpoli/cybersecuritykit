"""HORST few-time and SPHINCS-style stateless signatures through cybersecuritykit.pqc."""

import dataclasses
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def test_horst_indices_split_the_digest_into_a_bit_numbers():
    key = pqc.horst_keygen(3, k=8, a=6, n=16)
    indices = pqc.horst_indices(key.public, b"hello")
    assert len(indices) == 8
    assert all(0 <= i < 64 for i in indices)
    assert indices == pqc.horst_indices(key.public, b"hello")
    assert indices != pqc.horst_indices(key.public, b"hellp")


def test_a_horst_signature_reveals_the_selected_secrets_and_verifies():
    key = pqc.horst_keygen(3, k=8, a=6, n=16)
    signature = pqc.horst_sign(key, b"hello")
    assert len(signature.secrets) == len(signature.auth_paths) == 8
    assert all(len(path) == 6 for path in signature.auth_paths)
    assert pqc.horst_verify(key.public, b"hello", signature)
    assert not pqc.horst_verify(key.public, b"hellp", signature)
    other = pqc.horst_keygen(4, k=8, a=6, n=16)
    assert not pqc.horst_verify(other.public, b"hello", signature)


def test_a_malformed_horst_signature_does_not_verify():
    key = pqc.horst_keygen(3, k=8, a=6, n=16)
    signature = pqc.horst_sign(key, b"hello")
    short = dataclasses.replace(signature, secrets=signature.secrets[:-1])
    assert not pqc.horst_verify(key.public, b"hello", short)
    paths = (signature.auth_paths[0][:-1],) + signature.auth_paths[1:]
    assert not pqc.horst_verify(
        key.public, b"hello", dataclasses.replace(signature, auth_paths=paths)
    )


def test_one_horst_signature_gives_a_forger_nothing_but_many_do():
    key = pqc.horst_keygen(3, k=8, a=6, n=8)
    once = [(b"m0", pqc.horst_sign(key, b"m0"))]
    failed = pqc.horst_forge(key.public, once, max_tries=500)
    assert failed.message is None and failed.signature is None and failed.tested == 500
    many = [(m, pqc.horst_sign(key, m)) for m in (b"m%d" % i for i in range(12))]
    forgery = pqc.horst_forge(key.public, many, max_tries=50_000)
    assert forgery.message is not None and forgery.signature is not None
    assert forgery.message not in {m for m, _ in many}
    assert pqc.horst_verify(key.public, forgery.message, forgery.signature)


def test_the_horst_forger_rejects_bad_observations():
    key = pqc.horst_keygen(3, k=4, a=4, n=8)
    signature = pqc.horst_sign(key, b"a")
    with pytest.raises(ValueError, match="verify"):
        pqc.horst_forge(key.public, [(b"b", signature)])
    with pytest.raises(ValueError, match="at least one"):
        pqc.horst_forge(key.public, [])


def test_few_time_security_falls_as_signatures_accumulate():
    # One signature, k = 1, a = 1: half the leaves are revealed, so a forger succeeds
    # with probability 1/2, one bit of security.
    assert abs(pqc.few_time_security(1, 1, 1) - 1.0) < 1e-10
    # k = 2, a = 2, one signature: each index is revealed with probability 1 - (3/4)^2.
    expected = -2 * math.log2(1 - (3 / 4) ** 2)
    assert abs(pqc.few_time_security(2, 2, 1) - expected) < 1e-10
    bits = [pqc.few_time_security(32, 16, r) for r in (1, 10, 100, 1000, 10_000)]
    assert all(b > c for b, c in zip(bits, bits[1:], strict=False))


def test_a_sphincs_signature_verifies_without_any_state():
    key = pqc.sphincs_keygen(5, layers=2, height=2, k=6, a=4, n=16)
    first = pqc.sphincs_sign(key, b"release 1.0")
    # Stateless: no key comes back, and signing again gives the same signature.
    assert pqc.sphincs_sign(key, b"release 1.0") == first
    assert pqc.sphincs_verify(key.public, b"release 1.0", first)
    assert len(first.layers) == 2
    assert 0 <= first.index < 2 ** (2 * 2)
    assert not pqc.sphincs_verify(key.public, b"release 1.1", first)
    other = pqc.sphincs_keygen(6, layers=2, height=2, k=6, a=4, n=16)
    assert not pqc.sphincs_verify(other.public, b"release 1.0", first)


def test_different_messages_pick_different_few_time_keys():
    key = pqc.sphincs_keygen(5, layers=2, height=2, k=6, a=4, n=16)
    indices = {pqc.sphincs_sign(key, b"m%d" % i).index for i in range(20)}
    assert len(indices) > 5


def test_an_altered_sphincs_signature_does_not_verify():
    key = pqc.sphincs_keygen(5, layers=2, height=2, k=6, a=4, n=16)
    signature = pqc.sphincs_sign(key, b"release 1.0")
    public = key.public
    moved = dataclasses.replace(signature, index=(signature.index + 1) % 16)
    assert not pqc.sphincs_verify(public, b"release 1.0", moved)
    assert not pqc.sphincs_verify(
        public, b"release 1.0", dataclasses.replace(signature, randomizer=bytes(16))
    )
    assert not pqc.sphincs_verify(
        public, b"release 1.0", dataclasses.replace(signature, layers=signature.layers[:1])
    )
    bad_leaf = dataclasses.replace(signature.layers[0], index=signature.layers[0].index ^ 1)
    layers = (bad_leaf,) + signature.layers[1:]
    assert not pqc.sphincs_verify(
        public, b"release 1.0", dataclasses.replace(signature, layers=layers)
    )
    horst = dataclasses.replace(signature.horst, secrets=signature.horst.secrets[:-1])
    assert not pqc.sphincs_verify(
        public, b"release 1.0", dataclasses.replace(signature, horst=horst)
    )
    wots = dataclasses.replace(
        signature.layers[1], wots=pqc.WinternitzSignature(signature.layers[1].wots.chains[:-1])
    )
    layers = signature.layers[:1] + (wots,)
    assert not pqc.sphincs_verify(
        public, b"release 1.0", dataclasses.replace(signature, layers=layers)
    )


def test_sphincs_keys_are_reproducible_from_the_seed():
    a = pqc.sphincs_keygen(5, layers=1, height=2, k=4, a=4, n=8)
    assert a == pqc.sphincs_keygen(5, layers=1, height=2, k=4, a=4, n=8)
    assert a.public.root != pqc.sphincs_keygen(6, layers=1, height=2, k=4, a=4, n=8).public.root


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"layers": 0}, ValueError),
        ({"layers": 5}, ValueError),
        ({"height": 0}, ValueError),
        ({"k": 0}, ValueError),
        ({"a": 13}, ValueError),
        ({"a": 0}, ValueError),
        ({"n": 40}, ValueError),
        ({"w": 5}, ValueError),
        ({"k": 2.0}, TypeError),
    ],
)
def test_sphincs_keygen_rejects_bad_parameters(kwargs, error):
    with pytest.raises(error):
        pqc.sphincs_keygen(1, **kwargs)


def test_bad_inputs_are_rejected():
    key = pqc.horst_keygen(1, k=2, a=2, n=8)
    with pytest.raises(ValueError):
        pqc.horst_keygen(1, a=13)
    with pytest.raises(TypeError):
        pqc.horst_sign(key, "a")
    with pytest.raises(ValueError, match="max_tries"):
        pqc.horst_forge(key.public, [(b"a", pqc.horst_sign(key, b"a"))], max_tries=0)
    with pytest.raises(ValueError, match="signatures"):
        pqc.few_time_security(8, 6, 0)
    sphincs = pqc.sphincs_keygen(1, layers=1, height=1, k=2, a=2, n=8)
    with pytest.raises(TypeError):
        pqc.sphincs_sign(sphincs, "a")
    with pytest.raises(TypeError):
        pqc.sphincs_verify(sphincs.public, "a", pqc.sphincs_sign(sphincs, b"a"))


@settings(max_examples=20, deadline=None)
@given(st.binary(max_size=64))
def test_every_message_round_trips(message):
    key = pqc.sphincs_keygen(2, layers=2, height=1, k=4, a=3, n=8)
    assert pqc.sphincs_verify(key.public, message, pqc.sphincs_sign(key, message))
    horst = pqc.horst_keygen(2, k=4, a=3, n=8)
    assert pqc.horst_verify(horst.public, message, pqc.horst_sign(horst, message))
