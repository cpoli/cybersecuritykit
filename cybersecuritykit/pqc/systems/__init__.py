"""Models and algorithms for :mod:`cybersecuritykit.pqc`."""

__all__: list[str] = []

# --- slice A: lattices and the quantum threat ---
from cybersecuritykit.pqc.systems.aborts import (  # noqa: E402
    lyubashevsky_keygen,
    lyubashevsky_leakage,
    lyubashevsky_sign,
    lyubashevsky_verify,
)
from cybersecuritykit.pqc.systems.ajtai import (  # noqa: E402
    ajtai_collision,
    ajtai_hash,
    ajtai_keygen,
)
from cybersecuritykit.pqc.systems.grover import (  # noqa: E402
    grover_iterations,
    grover_search,
)
from cybersecuritykit.pqc.systems.kyber import (  # noqa: E402
    kyber_decapsulate,
    kyber_encapsulate,
    kyber_keygen,
)
from cybersecuritykit.pqc.systems.lattice import lll_reduce  # noqa: E402
from cybersecuritykit.pqc.systems.lwe import (  # noqa: E402
    lwe_decrypt,
    lwe_encrypt,
    lwe_gaussian_attack,
    lwe_keygen,
)
from cybersecuritykit.pqc.systems.ntru import (  # noqa: E402
    ntru_decrypt,
    ntru_encrypt,
    ntru_keygen,
    ntru_keypair,
    ntru_lattice_attack,
)
from cybersecuritykit.pqc.systems.ring_lwe import (  # noqa: E402
    ring_lwe_decrypt,
    ring_lwe_encrypt,
    ring_lwe_keygen,
)
from cybersecuritykit.pqc.systems.shor import (  # noqa: E402
    shor_distribution,
    shor_factor,
)

__all__ += [
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
]
# --- end slice A ---
