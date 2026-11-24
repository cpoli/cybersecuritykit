"""Result types for :mod:`cybersecuritykit.pqc`."""

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
]
# --- end slice B ---
