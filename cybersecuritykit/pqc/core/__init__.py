"""Result types for :mod:`cybersecuritykit.pqc`."""

__all__: list[str] = []

# --- slice B: codes and multivariate ---
from cybersecuritykit.pqc.core.base import (  # noqa: E402
    GoppaCode,
    ISDResult,
    LinearizationResult,
    MatsumotoImaiKeyPair,
    MatsumotoImaiPrivateKey,
    McElieceBreakResult,
    McElieceKeyPair,
    McEliecePrivateKey,
    McEliecePublicKey,
    NiederreiterKeyPair,
    NiederreiterPrivateKey,
    NiederreiterPublicKey,
    OilVinegarKeyPair,
    OilVinegarPrivateKey,
    QuadraticMap,
    RainbowBreakResult,
)

__all__ += [
    "GoppaCode",
    "ISDResult",
    "LinearizationResult",
    "MatsumotoImaiKeyPair",
    "MatsumotoImaiPrivateKey",
    "McElieceBreakResult",
    "McElieceKeyPair",
    "McEliecePrivateKey",
    "McEliecePublicKey",
    "NiederreiterKeyPair",
    "NiederreiterPrivateKey",
    "NiederreiterPublicKey",
    "OilVinegarKeyPair",
    "OilVinegarPrivateKey",
    "QuadraticMap",
    "RainbowBreakResult",
]
# --- end slice B ---
