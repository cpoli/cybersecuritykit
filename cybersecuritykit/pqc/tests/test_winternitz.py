"""Winternitz one-time signatures through the public API of cybersecuritykit.pqc."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cybersecuritykit as csk

pqc = csk.pqc


def test_digits_append_the_checksum_of_the_missing_steps():
    # 0x12 0x34 in base 16 is 1, 2, 3, 4; the checksum (15-1)+(15-2)+(15-3)+(15-4) = 50
    # is 0x32, written in two more base-16 digits.
    assert pqc.winternitz_digits(b"\x12\x34", 16) == (1, 2, 3, 4, 3, 2)


def test_a_signature_verifies_and_reveals_each_chain_digit_steps_in():
    key = pqc.winternitz_keygen(7, n=16, w=16)
    message = b"pay 5 coins to bob.test"
    signature = pqc.winternitz_sign(key, message)
    assert pqc.winternitz_verify(key.public, message, signature)
    digits = pqc.winternitz_digits(pqc.winternitz_digest(key.public, message), 16)
    assert len(signature.chains) == len(key.public.chains) == len(digits) == 35
    for digit, value, secret, end in zip(
        digits, signature.chains, key.secret, key.public.chains, strict=True
    ):
        # Digit 0 reveals the secret itself; digit w - 1 reveals the public chain end.
        assert (value == secret) == (digit == 0)
        assert (value == end) == (digit == 15)


def test_a_signature_fails_for_another_message_or_key():
    key = pqc.winternitz_keygen(7, n=16, w=16)
    signature = pqc.winternitz_sign(key, b"pay 5 coins")
    assert not pqc.winternitz_verify(key.public, b"pay 6 coins", signature)
    other = pqc.winternitz_keygen(8, n=16, w=16)
    assert not pqc.winternitz_verify(other.public, b"pay 5 coins", signature)
    short = pqc.WinternitzSignature(signature.chains[:-1])
    assert not pqc.winternitz_verify(key.public, b"pay 5 coins", short)


def test_keys_are_reproducible_from_the_seed():
    assert pqc.winternitz_keygen(3, n=8, w=4) == pqc.winternitz_keygen(3, n=8, w=4)
    assert pqc.winternitz_keygen(3, n=8, w=4) != pqc.winternitz_keygen(4, n=8, w=4)
    assert len(pqc.winternitz_keygen(3, n=8, w=4).public.chains) == 32 + 4


def _signed(key, messages):
    return [(m, pqc.winternitz_sign(key, m)) for m in messages]


def test_the_checksum_stops_a_forger_who_saw_one_signature():
    # Raising every message digit lowers the checksum, so no other message is reachable.
    key = pqc.winternitz_keygen(11, n=8, w=16)
    forgery = pqc.winternitz_forge(key.public, _signed(key, [b"only once"]), max_tries=3000)
    assert forgery.message is None and forgery.signature is None
    assert forgery.tested == 3000


def test_a_reused_key_lets_a_forger_sign_a_new_message():
    key = pqc.winternitz_keygen(11, n=8, w=16)
    seen = _signed(key, [b"first", b"second", b"third", b"fourth"])
    forgery = pqc.winternitz_forge(key.public, seen, max_tries=20000)
    assert forgery.message is not None and forgery.signature is not None
    assert forgery.message not in {m for m, _ in seen}
    assert pqc.winternitz_verify(key.public, forgery.message, forgery.signature)
    assert 1 <= forgery.tested <= 20000


def test_the_forger_never_returns_a_message_already_signed():
    key = pqc.winternitz_keygen(11, n=8, w=16)
    # The forger's first candidate is b"forgery 0"; having seen it signed must not count.
    seen = _signed(key, [b"forgery 0", b"a", b"b", b"c", b"d"])
    forgery = pqc.winternitz_forge(key.public, seen, max_tries=20000)
    assert forgery.message not in {m for m, _ in seen}
    assert forgery.tested >= 2


def test_cost_trades_signature_size_for_hashing():
    # n = 16 bytes: w = 4 gives 64 + 4 chains, w = 16 gives 32 + 3, w = 256 gives 16 + 2.
    costs = {w: pqc.winternitz_cost(16, w) for w in (4, 16, 256)}
    assert [costs[w].chains for w in (4, 16, 256)] == [68, 35, 18]
    assert costs[16].signature_bytes == 35 * 16
    assert costs[16].keygen_hashes == 35 * 15
    assert costs[256].keygen_hashes == 18 * 255


def test_the_forger_rejects_bad_observations():
    key = pqc.winternitz_keygen(11, n=8, w=16)
    signature = pqc.winternitz_sign(key, b"a")
    with pytest.raises(ValueError, match="verify"):
        pqc.winternitz_forge(key.public, [(b"b", signature)])
    with pytest.raises(ValueError, match="at least one"):
        pqc.winternitz_forge(key.public, [])
    with pytest.raises(ValueError, match="max_tries"):
        pqc.winternitz_forge(key.public, [(b"a", signature)], max_tries=0)


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"w": 8}, ValueError),
        ({"w": 1}, ValueError),
        ({"w": 16.0}, TypeError),
        ({"n": 1}, ValueError),
        ({"n": 33}, ValueError),
        ({"n": True}, TypeError),
    ],
)
def test_keygen_rejects_bad_parameters(kwargs, error):
    with pytest.raises(error):
        pqc.winternitz_keygen(1, **kwargs)


def test_bad_inputs_are_rejected():
    key = pqc.winternitz_keygen(1, n=8, w=16)
    with pytest.raises(TypeError):
        pqc.winternitz_keygen("1")
    with pytest.raises(TypeError):
        pqc.winternitz_sign(key, "text")
    with pytest.raises(ValueError):
        pqc.winternitz_digits(b"", 16)


@settings(max_examples=25, deadline=None)
@given(st.binary(max_size=64), st.sampled_from(pqc.WINTERNITZ_WIDTHS))
def test_every_message_round_trips(message, w):
    key = pqc.winternitz_keygen(2, n=8, w=w)
    assert pqc.winternitz_verify(key.public, message, pqc.winternitz_sign(key, message))
