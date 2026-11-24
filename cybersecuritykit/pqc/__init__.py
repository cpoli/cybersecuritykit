"""Post-quantum cryptography: the quantum threat and lattice, code and hash schemes."""

__all__: list[str] = []

# --- slice B: codes and multivariate ---
from cybersecuritykit.pqc.core.base import (  # noqa: E402
    GoppaCode,
    ISDResult,
    McElieceBreakResult,
    McElieceKeyPair,
    McEliecePrivateKey,
    McEliecePublicKey,
    NiederreiterKeyPair,
    NiederreiterPrivateKey,
    NiederreiterPublicKey,
)
from cybersecuritykit.pqc.systems.isd import (  # noqa: E402
    prange_isd,
    prange_success_probability,
    syndrome,
)
from cybersecuritykit.pqc.systems.mceliece import (  # noqa: E402
    break_mceliece,
    break_niederreiter,
    goppa_code,
    goppa_decode,
    mceliece_decrypt,
    mceliece_encrypt,
    mceliece_keygen,
    niederreiter_decrypt,
    niederreiter_encrypt,
    niederreiter_keygen,
)

__all__ += [
    "GoppaCode",
    "ISDResult",
    "McElieceBreakResult",
    "McElieceKeyPair",
    "McEliecePrivateKey",
    "McEliecePublicKey",
    "NiederreiterKeyPair",
    "NiederreiterPrivateKey",
    "NiederreiterPublicKey",
    "break_mceliece",
    "break_niederreiter",
    "goppa_code",
    "goppa_decode",
    "mceliece_decrypt",
    "mceliece_encrypt",
    "mceliece_keygen",
    "niederreiter_decrypt",
    "niederreiter_encrypt",
    "niederreiter_keygen",
    "prange_isd",
    "prange_success_probability",
    "syndrome",
]
# --- end slice B ---
