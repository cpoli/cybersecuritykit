"""Constants shared across cybersecuritykit.

Every value a subpackage would otherwise hard-code twice lives here: the
default seed, the Latin alphabet of the classical ciphers, and the reserved
names and address blocks that every simulated network uses, so no example can
ever name a real host.

>>> from cybersecuritykit import constants
>>> len(constants.ALPHABET)
26
"""

DEFAULT_SEED = 2026
"""int: Seed used by examples and tests when the caller does not pass one."""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"""str: The 26-letter alphabet that the classical ciphers act on."""

EXAMPLE_DOMAIN = "example.test"
"""str: Domain for simulated hosts; ``.test`` is reserved by RFC 2606 and never resolves."""

DOCUMENTATION_NETWORKS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
"""tuple[str, ...]: IPv4 blocks reserved for documentation (RFC 5737), used for simulated hosts."""
