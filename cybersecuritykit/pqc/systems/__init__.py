"""Models and algorithms for :mod:`cybersecuritykit.pqc`."""

__all__: list[str] = []

# --- slice B: codes and multivariate ---
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
from cybersecuritykit.pqc.systems.multivariate import (  # noqa: E402
    matsumoto_imai_decrypt,
    matsumoto_imai_encrypt,
    matsumoto_imai_keygen,
    patarin_linearization,
)
from cybersecuritykit.pqc.systems.oil_vinegar import (  # noqa: E402
    beullens_rainbow_attack,
    oil_vinegar_sign,
    oil_vinegar_verify,
    rainbow_keygen,
    uov_keygen,
)

__all__ += [
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
]
# --- end slice B ---
