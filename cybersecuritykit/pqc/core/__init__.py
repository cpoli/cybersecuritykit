"""Result types for :mod:`cybersecuritykit.pqc`."""

# --- slice A ---
from cybersecuritykit.pqc.core.base import (
    AjtaiKey,
    GroverResult,
    KyberCiphertext,
    KyberEncapsulation,
    KyberKeyPair,
    KyberPublicKey,
    LLLResult,
    LWEAttackResult,
    LWECiphertext,
    LWEKeyPair,
    LWEPublicKey,
    LyubashevskyKeyPair,
    LyubashevskyPublicKey,
    LyubashevskySignature,
    NTRUAttackResult,
    NTRUKeyPair,
    NTRUPublicKey,
    RingLWECiphertext,
    RingLWEKeyPair,
    RingLWEPublicKey,
    ShorResult,
    SignatureLeakage,
    SISCollision,
)

# isort: split
# --- end slice A ---

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
    # --- slice A ---
    "AjtaiKey",
    "GroverResult",
    "KyberCiphertext",
    "KyberEncapsulation",
    "KyberKeyPair",
    "KyberPublicKey",
    "LLLResult",
    "LWEAttackResult",
    "LWECiphertext",
    "LWEKeyPair",
    "LWEPublicKey",
    "LyubashevskyKeyPair",
    "LyubashevskyPublicKey",
    "LyubashevskySignature",
    "NTRUAttackResult",
    "NTRUKeyPair",
    "NTRUPublicKey",
    "RingLWECiphertext",
    "RingLWEKeyPair",
    "RingLWEPublicKey",
    "SISCollision",
    "ShorResult",
    "SignatureLeakage",
    # --- end slice A ---
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
