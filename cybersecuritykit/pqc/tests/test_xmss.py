"""XMSS stateful Merkle-tree signatures through the public API of cybersecuritykit.pqc."""

import dataclasses

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def _sign_all(key, messages):
    signatures = []
    for message in messages:
        signed = pqc.xmss_sign(key, message)
        signatures.append((message, signed.signature))
        key = signed.key
    return key, signatures


def test_each_signature_uses_the_next_leaf_and_verifies_against_the_root():
    key = pqc.xmss_keygen(5, height=3, n=16, w=16)
    key, signatures = _sign_all(key, [b"block 0", b"block 1", b"block 2"])
    assert key.next_index == 3
    assert [s.index for _, s in signatures] == [0, 1, 2]
    for message, signature in signatures:
        assert len(signature.auth_path) == 3
        assert pqc.xmss_verify(key.public, message, signature)
    # One root vouches for every leaf: each auth path is different.
    assert len({s.auth_path for _, s in signatures}) == 3


def test_a_signature_does_not_verify_once_altered():
    key = pqc.xmss_keygen(5, height=3, n=16, w=16)
    signature = pqc.xmss_sign(key, b"block 0").signature
    public = key.public
    assert not pqc.xmss_verify(public, b"block 1", signature)
    assert not pqc.xmss_verify(public, b"block 0", dataclasses.replace(signature, index=1))
    assert not pqc.xmss_verify(public, b"block 0", dataclasses.replace(signature, index=8))
    assert not pqc.xmss_verify(public, b"block 0", dataclasses.replace(signature, index=-1))
    short_path = dataclasses.replace(signature, auth_path=signature.auth_path[:-1])
    assert not pqc.xmss_verify(public, b"block 0", short_path)
    short_wots = dataclasses.replace(
        signature, wots=pqc.WinternitzSignature(signature.wots.chains[:-1])
    )
    assert not pqc.xmss_verify(public, b"block 0", short_wots)
    other = pqc.xmss_keygen(6, height=3, n=16, w=16)
    assert not pqc.xmss_verify(other.public, b"block 0", signature)


def test_the_key_is_spent_after_two_to_the_height_signatures():
    key, _ = _sign_all(pqc.xmss_keygen(5, height=1, n=8), [b"a", b"b"])
    assert key.next_index == 2
    with pytest.raises(ValueError, match="spent"):
        pqc.xmss_sign(key, b"c")


def test_keys_are_reproducible_from_the_seed():
    assert pqc.xmss_keygen(5, height=2) == pqc.xmss_keygen(5, height=2)
    assert pqc.xmss_keygen(5, height=2).public.root != pqc.xmss_keygen(6, height=2).public.root
    assert pqc.xmss_keygen(5, height=2).next_index == 0


def test_without_reuse_the_forger_gets_nowhere():
    key = pqc.xmss_keygen(9, height=2, n=8, w=16)
    _, signatures = _sign_all(key, [b"a", b"b", b"c", b"d"])
    forgery = pqc.xmss_forge(key.public, signatures, max_tries=2000)
    assert forgery.message is None and forgery.signature is None and forgery.tested == 2000


def test_restoring_an_old_state_reuses_a_leaf_and_lets_a_forger_sign():
    # A signer restored from a backup signs again from leaf 0: a one-time key used four times.
    key = pqc.xmss_keygen(9, height=2, n=8, w=16)
    signatures = [(m, pqc.xmss_sign(key, m).signature) for m in (b"a", b"b", b"c", b"d")]
    _, later = _sign_all(pqc.xmss_sign(key, b"e").key, [b"f"])
    forgery = pqc.xmss_forge(key.public, later + signatures, max_tries=20000)
    assert forgery.message is not None and forgery.signature is not None
    assert forgery.signature.index == 0
    assert pqc.xmss_verify(key.public, forgery.message, forgery.signature)


def test_the_forger_rejects_signatures_that_do_not_verify():
    key = pqc.xmss_keygen(9, height=2, n=8)
    signature = pqc.xmss_sign(key, b"a").signature
    with pytest.raises(ValueError, match="verify"):
        pqc.xmss_forge(key.public, [(b"b", signature)])
    with pytest.raises(ValueError, match="at least one"):
        pqc.xmss_forge(key.public, [])


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"height": 0}, ValueError),
        ({"height": 11}, ValueError),
        ({"height": 2.0}, TypeError),
        ({"n": 1}, ValueError),
        ({"w": 3}, ValueError),
    ],
)
def test_keygen_rejects_bad_parameters(kwargs, error):
    with pytest.raises(error):
        pqc.xmss_keygen(1, **kwargs)


def test_bad_inputs_are_rejected():
    key = pqc.xmss_keygen(1, height=1, n=8)
    signature = pqc.xmss_sign(key, b"a").signature
    with pytest.raises(TypeError):
        pqc.xmss_sign(key, "a")
    with pytest.raises(TypeError):
        pqc.xmss_verify(key.public, "a", signature)
    with pytest.raises(ValueError, match="max_tries"):
        pqc.xmss_forge(key.public, [(b"a", signature)], max_tries=0)


@settings(max_examples=20, deadline=None)
@given(st.lists(st.binary(max_size=32), min_size=1, max_size=4))
def test_every_signature_round_trips(messages):
    key, signatures = _sign_all(pqc.xmss_keygen(3, height=2, n=8), messages)
    assert all(pqc.xmss_verify(key.public, m, s) for m, s in signatures)
