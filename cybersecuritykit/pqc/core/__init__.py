"""Result types for :mod:`cybersecuritykit.pqc`."""

# --- slice B: codes and multivariate ---
# --- end slice B ---
# --- slice C ---
from cybersecuritykit.pqc.core.base import (
    GoppaCode,
    HORSTForgery,
    HORSTKey,
    HORSTPublicKey,
    HORSTSignature,
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
    SPHINCSKey,
    SPHINCSPublicKey,
    SPHINCSSignature,
    WinternitzCost,
    WinternitzForgery,
    WinternitzKey,
    WinternitzPublicKey,
    WinternitzSignature,
    XMSSForgery,
    XMSSKey,
    XMSSPublicKey,
    XMSSSignature,
    XMSSSigned,
)

# --- end slice C ---

__all__: list[str] = [
    # --- slice B: codes and multivariate ---
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
    # --- end slice B ---
    # --- slice C ---
    "HORSTForgery",
    "HORSTKey",
    "HORSTPublicKey",
    "HORSTSignature",
    "SPHINCSKey",
    "SPHINCSPublicKey",
    "SPHINCSSignature",
    "WinternitzCost",
    "WinternitzForgery",
    "WinternitzKey",
    "WinternitzPublicKey",
    "WinternitzSignature",
    "XMSSForgery",
    "XMSSKey",
    "XMSSPublicKey",
    "XMSSSignature",
    "XMSSSigned",
    # --- end slice C ---
]
