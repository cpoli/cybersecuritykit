"""Classical ciphers and their cryptanalysis, from Caesar to Enigma."""

from cybersecuritykit.classical.core.base import (
    ADFGVXBreakResult,
    BombeResult,
    CoincidenceProfile,
    CribDragHit,
    CribMenu,
    EnigmaSettings,
    HillBreakResult,
    HillClimbResult,
    HomophonicResult,
    KasiskiResult,
    LorenzWheels,
    PeriodTest,
    PlayfairBreakResult,
    RejewskiCharacteristic,
    SecrecyResult,
    ShiftBreakResult,
    SpuriousKeyCount,
    UnicityResult,
    VigenereBreakResult,
)
from cybersecuritykit.classical.systems.adfgvx import (
    adfgvx_decrypt,
    adfgvx_encrypt,
    break_adfgvx,
)
from cybersecuritykit.classical.systems.alberti import (
    alberti_decrypt,
    alberti_encrypt,
)
from cybersecuritykit.classical.systems.bombe import (
    bombe_search,
    crib_menu,
    crib_positions,
)
from cybersecuritykit.classical.systems.coincidence import (
    break_vigenere,
    coincidence_profile,
    index_of_coincidence,
)
from cybersecuritykit.classical.systems.enigma import (
    REFLECTORS,
    ROTORS,
    enigma_encrypt,
    enigma_positions,
    rejewski_characteristic,
)
from cybersecuritykit.classical.systems.frequency import (
    break_shift_cipher,
    chi_squared,
    letter_frequencies,
    shift_decrypt,
    shift_encrypt,
)
from cybersecuritykit.classical.systems.hill import (
    hill_decrypt,
    hill_encrypt,
    hill_inverse,
    hill_known_plaintext,
)
from cybersecuritykit.classical.systems.hillclimb import (
    hill_climb_substitution,
    substitution_decrypt,
    substitution_encrypt,
)
from cybersecuritykit.classical.systems.homophonic import (
    homophonic_decrypt,
    homophonic_encrypt,
    homophonic_key,
    solve_homophonic,
)
from cybersecuritykit.classical.systems.kasiski import kasiski_examination
from cybersecuritykit.classical.systems.lorenz import (
    lorenz_keystream,
    lorenz_wheels,
    tutte_period_test,
)
from cybersecuritykit.classical.systems.playfair import (
    break_playfair,
    playfair_decrypt,
    playfair_encrypt,
    playfair_square,
)
from cybersecuritykit.classical.systems.shannon import (
    one_time_pad_posterior,
    shift_cipher_posterior,
    spurious_shift_keys,
    unicity_distance,
)
from cybersecuritykit.classical.systems.vernam import (
    crib_drag,
    two_time_pad,
    vernam_encrypt,
)
from cybersecuritykit.classical.systems.vigenere import (
    vigenere_decrypt,
    vigenere_encrypt,
)

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
    "break_shift_cipher",
    "chi_squared",
    "letter_frequencies",
    "shift_decrypt",
    "shift_encrypt",
    "alberti_decrypt",
    "alberti_encrypt",
    "vigenere_decrypt",
    "vigenere_encrypt",
    "playfair_decrypt",
    "playfair_encrypt",
    "playfair_square",
    "break_playfair",
    "kasiski_examination",
    "break_vigenere",
    "coincidence_profile",
    "index_of_coincidence",
    "adfgvx_decrypt",
    "adfgvx_encrypt",
    "break_adfgvx",
    "crib_drag",
    "two_time_pad",
    "vernam_encrypt",
    "hill_decrypt",
    "hill_encrypt",
    "hill_inverse",
    "hill_known_plaintext",
    "REFLECTORS",
    "ROTORS",
    "enigma_encrypt",
    "enigma_positions",
    "rejewski_characteristic",
    "bombe_search",
    "crib_menu",
    "crib_positions",
    "lorenz_keystream",
    "lorenz_wheels",
    "tutte_period_test",
    "one_time_pad_posterior",
    "shift_cipher_posterior",
    "unicity_distance",
    "spurious_shift_keys",
    "hill_climb_substitution",
    "substitution_decrypt",
    "substitution_encrypt",
    "homophonic_decrypt",
    "homophonic_encrypt",
    "homophonic_key",
    "solve_homophonic",
]
