"""Models and algorithms for :mod:`cybersecuritykit.pqc`."""

# --- slice B: codes and multivariate ---
from cybersecuritykit.pqc.systems.isd import (
    prange_isd,
    prange_success_probability,
    syndrome,
)
from cybersecuritykit.pqc.systems.mceliece import (
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
from cybersecuritykit.pqc.systems.multivariate import (
    matsumoto_imai_decrypt,
    matsumoto_imai_encrypt,
    matsumoto_imai_keygen,
    patarin_linearization,
)
from cybersecuritykit.pqc.systems.oil_vinegar import (
    beullens_rainbow_attack,
    oil_vinegar_sign,
    oil_vinegar_verify,
    rainbow_keygen,
    uov_keygen,
)

# --- end slice B ---
# --- slice C ---
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
    # --- slice B: codes and multivariate ---
    "beullens_rainbow_attack",
    "break_mceliece",
    "break_niederreiter",
    "goppa_code",
    "goppa_decode",
    "matsumoto_imai_decrypt",
    "matsumoto_imai_encrypt",
    "matsumoto_imai_keygen",
    "mceliece_decrypt",
    "mceliece_encrypt",
    "mceliece_keygen",
    "niederreiter_decrypt",
    "niederreiter_encrypt",
    "niederreiter_keygen",
    "oil_vinegar_sign",
    "oil_vinegar_verify",
    "patarin_linearization",
    "prange_isd",
    "prange_success_probability",
    "rainbow_keygen",
    "syndrome",
    "uov_keygen",
    # --- end slice B ---
    # --- slice C ---
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
