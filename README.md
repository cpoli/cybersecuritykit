# cybersecuritykit

| | |
|:--|:-:|
| Quality | [![License](https://img.shields.io/github/license/cpoli/cybersecuritykit)](https://github.com/cpoli/cybersecuritykit/blob/main/LICENSE) [![CI](https://github.com/cpoli/cybersecuritykit/actions/workflows/ci.yml/badge.svg)](https://github.com/cpoli/cybersecuritykit/actions/workflows/ci.yml) [![Coverage](https://badgen.net/badge/coverage/100%25/green)](#development) |
| Documentation | [![Docs](https://badgen.net/badge/docs/cpoli.github.io%2Fcybersecuritykit/blue)](https://cpoli.github.io/cybersecuritykit/) |
| Code style | [![Ruff](https://badgen.net/badge/code%20style/ruff/purple)](https://github.com/astral-sh/ruff) |

**Cybersecurity, understood through simulated experiments.**
cybersecuritykit is a Python toolkit for learning and teaching how attacks and
defences work, from al-Kindi's frequency analysis to lattice-based encryption.
Each idea is followed from its history and mathematics to a small, typed,
inspectable implementation, a figure, and an experiment you can change.

> **Everything is simulated.** Toy ciphers and keys, a toy machine for
> memory-safety bugs, synthetic packets, logs and traces, and epidemic models
> instead of malware. Nothing in the package opens a socket, scans a host, or
> runs an exploit against a real system. See the
> [scope page](https://cpoli.github.io/cybersecuritykit/scope.html).

## Subpackages

| Subpackage | Covers |
|:--|:--|
| `classical` | Substitution and transposition ciphers, frequency analysis, Kasiski, rotor machines, Shannon |
| `symmetric` | Feistel networks, toy DES and AES, differential and linear cryptanalysis, modes, padding oracles |
| `pqc` | Shor and Grover threat models, learning with errors, McEliece, hash-based signatures |
| `protocols` | Needham-Schroeder and Lowe, Dolev-Yao, Kerberos, BAN logic, toy TLS |
| `auth` | Password guessing, salted and slow hashing, rainbow tables, HOTP and TOTP |
| `access` | Access matrix, Bell-LaPadula, Biba, Clark-Wilson, HRU, RBAC |
| `software` | Stack smashing and ROP on a toy VM, canaries, ASLR, fuzzing, symbolic execution |
| `sidechannel` | Timing attacks, simple and differential power analysis, cache timing, fault attacks |
| `malware` | Worm epidemics (Morris, Code Red, Slammer), scanning strategies, botnets, containment |
| `network` | Packet filters, simulated scans and floods, SYN cookies, spoofing, traceback |
| `detection` | Denning's IDS model, signature matching, anomaly detection, the base-rate fallacy |
| `privacy` | Re-identification, k-anonymity, randomized response, differential privacy |
| `risk` | Attack trees, CVSS, the Gordon-Loeb model, Stackelberg security games |

Hashes, elliptic curves, signatures and zero knowledge live in the sibling
package [blockchainkit](https://cpoli.github.io/blockchainkit/).

## Install

```bash
pip install cybersecuritykit
```

`import cybersecuritykit` loads only the standard library; Matplotlib and NumPy
are used by each subpackage's `visualizers`. Conventionally imported as `csk`.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
ruff check . && mypy && pytest --cov=cybersecuritykit --cov-branch
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Coverage is held at 100% for
statements and branches.

## License

MIT. See [LICENSE](LICENSE).
