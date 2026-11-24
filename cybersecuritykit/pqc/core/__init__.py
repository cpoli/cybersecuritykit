"""Result types for :mod:`cybersecuritykit.pqc`."""

# --- slice C ---
from cybersecuritykit.pqc.core.base import (
    HORSTForgery,
    HORSTKey,
    HORSTPublicKey,
    HORSTSignature,
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
