"""Post-quantum cryptography: the quantum threat and lattice, code and hash schemes."""

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
from cybersecuritykit.pqc.systems.aborts import (
    lyubashevsky_keygen,
    lyubashevsky_leakage,
    lyubashevsky_sign,
    lyubashevsky_verify,
)
from cybersecuritykit.pqc.systems.ajtai import (
    ajtai_collision,
    ajtai_hash,
    ajtai_keygen,
)
from cybersecuritykit.pqc.systems.grover import (
    grover_iterations,
    grover_search,
)
from cybersecuritykit.pqc.systems.kyber import (
    kyber_decapsulate,
    kyber_encapsulate,
    kyber_keygen,
)
from cybersecuritykit.pqc.systems.lattice import lll_reduce
from cybersecuritykit.pqc.systems.lwe import (
    lwe_decrypt,
    lwe_encrypt,
    lwe_gaussian_attack,
    lwe_keygen,
)
from cybersecuritykit.pqc.systems.ntru import (
    ntru_decrypt,
    ntru_encrypt,
    ntru_keygen,
    ntru_keypair,
    ntru_lattice_attack,
)
from cybersecuritykit.pqc.systems.ring_lwe import (
    ring_lwe_decrypt,
    ring_lwe_encrypt,
    ring_lwe_keygen,
)
from cybersecuritykit.pqc.systems.shor import (
    shor_distribution,
    shor_factor,
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
from cybersecuritykit.pqc.systems.sphincs import (
    few_time_security,
    horst_forge,
    horst_indices,
    horst_keygen,
    horst_sign,
    horst_verify,
    sphincs_keygen,
    sphincs_sign,
    sphincs_verify,
)
from cybersecuritykit.pqc.systems.winternitz import (
    WINTERNITZ_WIDTHS,
    winternitz_cost,
    winternitz_digest,
    winternitz_digits,
    winternitz_forge,
    winternitz_keygen,
    winternitz_sign,
    winternitz_verify,
)
from cybersecuritykit.pqc.systems.xmss import (
    xmss_forge,
    xmss_keygen,
    xmss_sign,
    xmss_verify,
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
    "ajtai_collision",
    "ajtai_hash",
    "ajtai_keygen",
    "grover_iterations",
    "grover_search",
    "kyber_decapsulate",
    "kyber_encapsulate",
    "kyber_keygen",
    "lll_reduce",
    "lwe_decrypt",
    "lwe_encrypt",
    "lwe_gaussian_attack",
    "lwe_keygen",
    "lyubashevsky_keygen",
    "lyubashevsky_leakage",
    "lyubashevsky_sign",
    "lyubashevsky_verify",
    "ntru_decrypt",
    "ntru_encrypt",
    "ntru_keygen",
    "ntru_keypair",
    "ntru_lattice_attack",
    "ring_lwe_decrypt",
    "ring_lwe_encrypt",
    "ring_lwe_keygen",
    "shor_distribution",
    "shor_factor",
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
    "WINTERNITZ_WIDTHS",
    "winternitz_cost",
    "winternitz_digest",
    "winternitz_digits",
    "winternitz_forge",
    "winternitz_keygen",
    "winternitz_sign",
    "winternitz_verify",
    "few_time_security",
    "horst_forge",
    "horst_indices",
    "horst_keygen",
    "horst_sign",
    "horst_verify",
    "sphincs_keygen",
    "sphincs_sign",
    "sphincs_verify",
    "xmss_forge",
    "xmss_keygen",
    "xmss_sign",
    "xmss_verify",
    # --- end slice C ---
]
