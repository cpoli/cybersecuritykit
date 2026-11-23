"""The Enigma I rotor machine and Rejewski's characteristic (1932).

Rotor and reflector wirings are those of the Wehrmacht Enigma I, as given in
the declassified wiring tables reprinted by many sources (for example
D. Hamer, "Enigma: actions involved in the double stepping of the middle
rotor", *Cryptologia* 21(1), 1997). Ring settings are left out (all at A).

M. Rejewski, "An application of the theory of permutations in breaking the
Enigma cipher", *Applicationes Mathematicae* 16(4), 1980, describes how the
doubled message key gave the products AD, BE and CF, whose cycle lengths do
not depend on the plugboard.
"""

from cybersecuritykit.classical.core.base import EnigmaSettings, RejewskiCharacteristic
from cybersecuritykit.classical.utils.text import clean, string, to_letters, to_numbers
from cybersecuritykit.constants import ALPHABET

__all__ = [
    "REFLECTORS",
    "ROTORS",
    "enigma_encrypt",
    "enigma_positions",
    "rejewski_characteristic",
]

ROTORS: dict[str, tuple[str, str]] = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
"""dict: Enigma I rotor wiring and turnover letter, by rotor name."""

REFLECTORS: dict[str, str] = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}
"""dict: Enigma I reflector wiring, by reflector name."""


class EnigmaMachine:
    """A wired Enigma: rotor order, reflector and plugboard, positions supplied per letter.

    Internal to the Enigma and bombe modules; it is not exported.
    """

    def __init__(self, settings: EnigmaSettings) -> None:
        if not isinstance(settings, EnigmaSettings):
            raise TypeError("settings must be an EnigmaSettings")
        rotors, reflector = settings.rotors, settings.reflector
        if not isinstance(rotors, tuple) or len(rotors) != 3 or len(set(rotors)) != 3:
            raise ValueError("rotors must be a tuple of three different rotor names")
        if any(name not in ROTORS for name in rotors):
            raise ValueError(f"rotor names must be among {sorted(ROTORS)}")
        if reflector not in REFLECTORS:
            raise ValueError(f"reflector must be one of {sorted(REFLECTORS)}")
        self.forward = [to_numbers(ROTORS[name][0]) for name in rotors]
        self.backward = [[f.index(i) for i in range(26)] for f in self.forward]
        self.notches = [ALPHABET.index(ROTORS[name][1]) for name in rotors]
        self.reflector = to_numbers(REFLECTORS[reflector])
        self.plugboard = _plugboard(settings.plugboard)

    def step(self, positions: list[int]) -> list[int]:
        left, middle, right = positions
        if middle == self.notches[1]:
            return [(left + 1) % 26, (middle + 1) % 26, (right + 1) % 26]
        if right == self.notches[2]:
            return [left, (middle + 1) % 26, (right + 1) % 26]
        return [left, middle, (right + 1) % 26]

    def letter(self, x: int, positions: list[int]) -> int:
        x = self.plugboard[x]
        for k in (2, 1, 0):
            o = positions[k]
            x = (self.forward[k][(x + o) % 26] - o) % 26
        x = self.reflector[x]
        for k in (0, 1, 2):
            o = positions[k]
            x = (self.backward[k][(x + o) % 26] - o) % 26
        return self.plugboard[x]


def _plugboard(pairs: str) -> list[int]:
    board = list(range(26))
    letters = clean(pairs, "plugboard")
    if len(letters) % 2 or len(set(letters)) != len(letters):
        raise ValueError("plugboard must pair distinct letters, as in 'AB CD'")
    for a, b in zip(to_numbers(letters[::2]), to_numbers(letters[1::2]), strict=True):
        board[a], board[b] = b, a
    return board


def _positions(positions: str) -> list[int]:
    if len(string(positions, "positions")) != 3 or clean(positions) != positions.upper():
        raise ValueError("positions must be three letters, as in 'AAA'")
    return to_numbers(positions.upper())


def enigma_positions(settings: EnigmaSettings, positions: str, count: int) -> tuple[str, ...]:
    """Return the rotor positions in use for each of the next ``count`` letters.

    The rotors step before each letter is enciphered, including the middle
    rotor's double step: at its own turnover letter it moves again, taking
    the left rotor with it.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.enigma_positions(classical.EnigmaSettings(("I", "II", "III")), "AAU", 2)
    ('AAV', 'ABW')
    """
    machine = EnigmaMachine(settings)
    state = _positions(positions)
    out = []
    for _ in range(count):
        state = machine.step(state)
        out.append(to_letters(state))
    return tuple(out)


def enigma_encrypt(text: str, settings: EnigmaSettings, positions: str) -> str:
    """Encipher with an Enigma I; the same call deciphers, since the machine is reciprocal.

    Parameters
    ----------
    text : str
        Text to encipher; non-letters are dropped.
    settings : EnigmaSettings
        Rotor order, reflector and plugboard.
    positions : str
        Starting letters in the windows, left to right.

    Returns
    -------
    str
        Upper-case ciphertext.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.enigma_encrypt("AAAAA", classical.EnigmaSettings(("I", "II", "III")), "AAA")
    'BDZGO'
    """
    machine = EnigmaMachine(settings)
    state = _positions(positions)
    out = []
    for x in to_numbers(clean(text)):
        state = machine.step(state)
        out.append(machine.letter(x, state))
    return to_letters(out)


def _cycle_lengths(perm: list[int]) -> tuple[int, ...]:
    seen = [False] * 26
    lengths = []
    for start in range(26):
        n, x = 0, start
        while not seen[x]:
            seen[x] = True
            x = perm[x]
            n += 1
        if n:
            lengths.append(n)
    return tuple(sorted(lengths, reverse=True))


def rejewski_characteristic(settings: EnigmaSettings, positions: str) -> RejewskiCharacteristic:
    """Return the cycle lengths of AD, BE and CF for a daily key.

    Operators enciphered each three-letter message key twice at the daily
    start ``positions``, so the first and fourth letters were enciphered by
    permutations A and D of one unknown letter. Rejewski collected the
    products AD, BE and CF from a day's traffic; the plugboard only
    conjugates them, so their cycle lengths fingerprint the rotor settings.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> settings = classical.EnigmaSettings(("I", "II", "III"))
    >>> sum(classical.rejewski_characteristic(settings, "AAA").ad)
    26
    """
    machine = EnigmaMachine(settings)
    state = _positions(positions)
    perms = []
    for _ in range(6):
        state = machine.step(state)
        perms.append([machine.letter(x, state) for x in range(26)])
    a, b, c, d, e, f = perms
    return RejewskiCharacteristic(
        _cycle_lengths([d[a[x]] for x in range(26)]),
        _cycle_lengths([e[b[x]] for x in range(26)]),
        _cycle_lengths([f[c[x]] for x in range(26)]),
    )
