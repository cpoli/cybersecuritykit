"""cybersecuritykit: cybersecurity breakthroughs as simulated Python experiments.

Every experiment runs on toy keys, simulated systems or synthetic data; nothing
here touches a real network, host or account.

>>> import cybersecuritykit as csk
>>> csk.__version__
'0.1.0'
"""

from cybersecuritykit import (
    access,
    auth,
    classical,
    detection,
    malware,
    network,
    pqc,
    privacy,
    protocols,
    risk,
    sidechannel,
    software,
    symmetric,
)
from cybersecuritykit.constants import DEFAULT_SEED

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_SEED",
    "classical",
    "symmetric",
    "pqc",
    "protocols",
    "auth",
    "access",
    "software",
    "sidechannel",
    "malware",
    "network",
    "detection",
    "privacy",
    "risk",
]
