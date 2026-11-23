"""Turing and Welchman's bombe (1940): cribs, menus and a search over rotor starts.

A. M. Turing, *Treatise on the Enigma* ("Prof's Book", 1940, National
Archives HW 25/3). Because Enigma never enciphers a letter to itself, a
guessed plaintext (crib) can only sit where no letter coincides with the
ciphertext. The crib's letter pairs form a menu, and its loops let the bombe
reject most of the 17,576 rotor starts at machine speed.
"""

from cybersecuritykit import _validation
from cybersecuritykit.classical.core.base import BombeResult, CribMenu, EnigmaSettings
from cybersecuritykit.classical.systems.enigma import EnigmaMachine
from cybersecuritykit.classical.utils.text import clean, to_letters, to_numbers

__all__ = ["bombe_search", "crib_menu", "crib_positions"]


def _texts(ciphertext: str, crib: str) -> tuple[str, str]:
    c, p = clean(ciphertext, "ciphertext"), clean(crib, "crib")
    if not p or len(p) > len(c):
        raise ValueError("crib must have at least one letter and fit inside the ciphertext")
    return c, p


def crib_positions(ciphertext: str, crib: str) -> tuple[int, ...]:
    """Return the offsets where ``crib`` could lie under ``ciphertext``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.crib_positions("QWERTY", "EW")
    (1, 3, 4)
    """
    c, p = _texts(ciphertext, crib)
    return tuple(
        offset
        for offset in range(len(c) - len(p) + 1)
        if all(a != b for a, b in zip(p, c[offset:], strict=False))
    )


def crib_menu(ciphertext: str, crib: str, offset: int) -> CribMenu:
    """Build the menu: one edge per crib letter, joining it to its ciphertext letter.

    Raises
    ------
    ValueError
        The crib does not fit at ``offset``, or a letter there meets itself.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> classical.crib_menu("EW", "WE", 0).loops
    1
    """
    c, p = _texts(ciphertext, crib)
    _validation.integer(offset, "offset")
    if offset not in crib_positions(c, p):
        raise ValueError("crib cannot sit at this offset")
    edges = tuple((a, b, offset + i) for i, (a, b) in enumerate(zip(p, c[offset:], strict=False)))
    parent = {x: x for edge in edges for x in edge[:2]}

    def root(x: str) -> str:
        while parent[x] != x:
            x = parent[x]
        return x

    components = len(parent)
    for a, b, _ in edges:
        ra, rb = root(a), root(b)
        if ra != rb:
            parent[ra] = rb
            components -= 1
    return CribMenu(edges, len(edges) - len(parent) + components)


def bombe_search(ciphertext: str, crib: str, offset: int, settings: EnigmaSettings) -> BombeResult:
    """Try every rotor start and keep those that encipher the crib into the ciphertext.

    The real bombe also deduced plugboard pairs by following the menu's loops;
    this teaching version assumes an unplugged machine, so a start survives
    only if it reproduces every crib letter exactly.

    Raises
    ------
    ValueError
        ``settings`` has a plugboard, or the crib does not fit at ``offset``.

    Examples
    --------
    >>> from cybersecuritykit import classical
    >>> settings = classical.EnigmaSettings(("I", "II", "III"))
    >>> c = classical.enigma_encrypt("ATTACKATDAWN", settings, "ABC")
    >>> classical.bombe_search(c, "ATTACKAT", 0, settings).positions
    ('ABC',)
    """
    machine = EnigmaMachine(settings)
    if settings.plugboard:
        raise ValueError("the bombe models an unplugged machine; settings must have no plugboard")
    menu = crib_menu(ciphertext, crib, offset)
    pairs = [(to_numbers(a)[0], to_numbers(b)[0], step) for a, b, step in menu.edges]
    found = []
    for start in range(26**3):
        begin = [start // 676, start // 26 % 26, start % 26]
        state = begin
        for _ in range(offset):
            state = machine.step(state)
        for a, b, _ in pairs:
            state = machine.step(state)
            if machine.letter(a, state) != b:
                break
        else:
            found.append(to_letters(begin))
    return BombeResult(tuple(found), 26**3)
