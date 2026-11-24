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

__all__ += [
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
