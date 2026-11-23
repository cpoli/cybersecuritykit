"""Frozen result dataclasses for :mod:`cybersecuritykit.classical`."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

__all__ = [
    "ADFGVXBreakResult",
    "BombeResult",
    "CoincidenceProfile",
    "CribDragHit",
    "CribMenu",
    "EnigmaSettings",
    "HillBreakResult",
    "HillClimbResult",
    "HomophonicResult",
    "KasiskiResult",
    "LorenzWheels",
    "PeriodTest",
    "PlayfairBreakResult",
    "RejewskiCharacteristic",
    "SecrecyResult",
    "ShiftBreakResult",
    "SpuriousKeyCount",
    "UnicityResult",
    "VigenereBreakResult",
]


def _freeze(result: object, *names: str) -> None:
    """Replace dict fields of a frozen result with read-only views of copies."""
    for name in names:
        object.__setattr__(result, name, MappingProxyType(dict(getattr(result, name))))


@dataclass(frozen=True)
class ShiftBreakResult:
    """Outcome of breaking a shift cipher by frequency analysis.

    Attributes
    ----------
    shift : int
        The recovered key.
    plaintext : str
        The ciphertext decrypted with ``shift``.
    chi_squared : tuple of float
        The chi-squared score of each of the 26 shifts; the key minimizes it.
    """

    shift: int
    plaintext: str
    chi_squared: tuple[float, ...]


@dataclass(frozen=True)
class KasiskiResult:
    """Repeated fragments of a ciphertext and the keyword length they point to.

    Attributes
    ----------
    repeats : mapping of str to tuple of int
        Each fragment seen more than once, mapped to the positions where it starts.
    factor_counts : mapping of int to int
        For each candidate period, how many gaps between consecutive repeats it divides.
    likely_period : int
        The largest candidate period counted at least 80% as often as the most common one.
    """

    repeats: Mapping[str, tuple[int, ...]]
    factor_counts: Mapping[int, int]
    likely_period: int

    def __post_init__(self) -> None:
        _freeze(self, "repeats", "factor_counts")


@dataclass(frozen=True)
class CoincidenceProfile:
    """Mean index of coincidence of the columns for each candidate period.

    Attributes
    ----------
    periods : tuple of int
        The candidate periods, from 1.
    mean_ic : tuple of float
        For each period, the mean index of coincidence of the columns it defines.
    best_period : int
        The smallest period whose mean is within 90% of the largest; multiples of
        the true period score as high as the period itself.
    """

    periods: tuple[int, ...]
    mean_ic: tuple[float, ...]
    best_period: int


@dataclass(frozen=True)
class VigenereBreakResult:
    """A keyword and plaintext recovered from a Vigenère ciphertext.

    Attributes
    ----------
    key : str
        The recovered keyword.
    plaintext : str
        The ciphertext decrypted with ``key``.
    tested : int
        Candidate shifts scored: 26 per column.
    """

    key: str
    plaintext: str
    tested: int


@dataclass(frozen=True)
class CribDragHit:
    """A crib position in a two-time pad that yields printable text in the other message.

    Attributes
    ----------
    offset : int
        Byte offset at which the crib was placed.
    fragment : bytes
        The bytes of the other plaintext that the crib implies at ``offset``.
    """

    offset: int
    fragment: bytes


@dataclass(frozen=True)
class HillBreakResult:
    """A Hill key recovered from matching plaintext and ciphertext.

    Attributes
    ----------
    key : tuple of tuple of int
        The recovered key matrix, rows of integers mod 26.
    blocks : tuple of int
        Indices of the plaintext blocks whose matrix was invertible and used.
    tested : int
        Choices of blocks tried, the last one included.
    """

    key: tuple[tuple[int, ...], ...]
    blocks: tuple[int, ...]
    tested: int


@dataclass(frozen=True)
class EnigmaSettings:
    """The wiring of an Enigma I for a day: rotor order, reflector and plugboard.

    The start positions are not part of it, since operators changed them for
    every message and the attacks search over them.

    Attributes
    ----------
    rotors : tuple of str
        Three different rotor names from ``ROTORS``, left to right.
    reflector : str, optional
        A reflector name from ``REFLECTORS``.
    plugboard : str, optional
        Letter pairs swapped before and after the rotors, as in ``"AB CD"``.
    """

    rotors: tuple[str, ...]
    reflector: str = "B"
    plugboard: str = ""


@dataclass(frozen=True)
class RejewskiCharacteristic:
    """Cycle lengths of the products of the Enigma's first six permutations.

    Attributes
    ----------
    ad, be, cf : tuple of int
        Cycle lengths, longest first, of the permutation products that Rejewski
        called AD, BE and CF.
    """

    ad: tuple[int, ...]
    be: tuple[int, ...]
    cf: tuple[int, ...]


@dataclass(frozen=True)
class CribMenu:
    """The letter graph a bombe is wired from.

    Attributes
    ----------
    edges : tuple of tuple
        ``(plain, cipher, step)`` for each letter of the crib.
    loops : int
        Independent cycles of the graph (edges minus letters plus components);
        each loop is a constraint that prunes wrong rotor starts.
    """

    edges: tuple[tuple[str, str, int], ...]
    loops: int


@dataclass(frozen=True)
class BombeResult:
    """Rotor starts that survive a bombe run.

    Attributes
    ----------
    positions : tuple of str
        Start positions consistent with the crib.
    tested : int
        Number of start positions tried.
    """

    positions: tuple[str, ...]
    tested: int


@dataclass(frozen=True)
class LorenzWheels:
    """Cam patterns of a Lorenz SZ40 model.

    Attributes
    ----------
    chi : tuple of tuple of int
        Five chi wheels of 41, 31, 29, 26 and 23 cams, one per teleprinter impulse.
    psi : tuple of tuple of int
        Five psi wheels of 43, 47, 51, 53 and 59 cams.
    motor : tuple of int
        One motor wheel of 61 cams; where it shows 1 the psi wheels move.
    """

    chi: tuple[tuple[int, ...], ...]
    psi: tuple[tuple[int, ...], ...]
    motor: tuple[int, ...]


@dataclass(frozen=True)
class PeriodTest:
    """How often a bit stream's delta agrees with itself at each shift.

    Attributes
    ----------
    periods : tuple of int
        Shifts tried.
    agreement : tuple of float
        Fraction of positions where the delta stream equals itself shifted.
    best_period : int
        The shift with the highest agreement.
    """

    periods: tuple[int, ...]
    agreement: tuple[float, ...]
    best_period: int


@dataclass(frozen=True)
class SecrecyResult:
    """What an eavesdropper learns about the message from one ciphertext.

    Attributes
    ----------
    prior : mapping of str to float
        Probability of each message before the ciphertext is seen.
    posterior : mapping of str to float
        Probability of each message given the ciphertext.
    perfect : bool
        Whether the posterior equals the prior, Shannon's perfect secrecy.
    """

    prior: Mapping[str, float]
    posterior: Mapping[str, float]
    perfect: bool

    def __post_init__(self) -> None:
        _freeze(self, "prior", "posterior")


@dataclass(frozen=True)
class UnicityResult:
    """Shannon's estimate of how much ciphertext fixes the key.

    Attributes
    ----------
    key_entropy : float
        Bits of uncertainty in the key, ``log2`` of the key space.
    redundancy : float
        Bits per letter by which the language falls short of random letters.
    distance : float
        Letters of ciphertext beyond which one key is expected to remain.
    """

    key_entropy: float
    redundancy: float
    distance: float


@dataclass(frozen=True)
class HillClimbResult:
    """Best substitution key found by hill climbing.

    Attributes
    ----------
    key : str
        Encryption key: the cipher letter for each of A-Z.
    plaintext : str
        The ciphertext decrypted with ``key``.
    score : float
        Bigram log-likelihood of ``plaintext``.
    history : tuple of float
        Best score so far after every accepted swap, across all restarts.
    tested : int
        Candidate keys scored.
    """

    key: str
    plaintext: str
    score: float
    history: tuple[float, ...]
    tested: int


@dataclass(frozen=True)
class HomophonicResult:
    """Best symbol-to-letter assignment found for a homophonic ciphertext.

    Attributes
    ----------
    mapping : mapping of int to str
        Letter assigned to each cipher symbol.
    plaintext : str
        The ciphertext read through ``mapping``.
    score : float
        Minus :math:`N` times the Kullback-Leibler divergence of the bigrams of
        ``plaintext`` from English; at most 0, and higher is more English-like.
    tested : int
        Candidate assignments scored.
    """

    mapping: Mapping[int, str]
    plaintext: str
    score: float
    tested: int

    def __post_init__(self) -> None:
        _freeze(self, "mapping")


@dataclass(frozen=True)
class PlayfairBreakResult:
    """Best Playfair key square found by simulated annealing.

    Attributes
    ----------
    square : tuple of str
        The five rows of the recovered square. Any cyclic shift of its rows
        and columns encrypts the same way.
    plaintext : str
        The ciphertext decrypted with ``square``, padding letters included.
    score : float
        Bigram log-likelihood of ``plaintext``.
    tested : int
        Candidate squares scored.
    """

    square: tuple[str, ...]
    plaintext: str
    score: float
    tested: int


@dataclass(frozen=True)
class ADFGVXBreakResult:
    """Column order and plaintext recovered from an ADFGVX ciphertext.

    Attributes
    ----------
    order : tuple of int
        The columns in the order they were read out, as the keyword sorts them.
    plaintext : str
        The text, with each coordinate pair solved as a substitution letter.
        Digits cannot be told from letters this way, so they come out as letters.
    tested : int
        Column orders scored plus substitution keys scored.
    """

    order: tuple[int, ...]
    plaintext: str
    tested: int


@dataclass(frozen=True)
class SpuriousKeyCount:
    """How many shift keys give English-looking text as the ciphertext grows.

    Attributes
    ----------
    lengths : tuple of int
        Prefix lengths of the ciphertext, from 1.
    counts : tuple of int
        For each length, the keys whose decryption has the fewest letter pairs
        unseen in English; all but one are spurious.
    unique_from : int or None
        The shortest length from which exactly one key survives to the end, or
        ``None`` if more than one survives the whole ciphertext.
    """

    lengths: tuple[int, ...]
    counts: tuple[int, ...]
    unique_from: int | None
