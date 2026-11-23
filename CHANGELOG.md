# Changelog

## [Unreleased]

### Added

- Package scaffold: thirteen subpackages (`classical`, `symmetric`, `pqc`,
  `protocols`, `auth`, `access`, `software`, `sidechannel`, `malware`,
  `network`, `detection`, `privacy`, `risk`), shared argument validation and
  constants, documentation skeleton with the simulation-only scope page, and
  CI, docs and release workflows.
- `classical`: shift, Alberti, Vigenère, Playfair, ADFGVX, Vernam, Hill,
  Enigma I and Lorenz ciphers with their historical attacks (frequency
  analysis, Kasiski, index of coincidence, Playfair annealing, a Painvin-style
  ADFGVX break, two-time pad crib dragging, Hill known-plaintext, Rejewski's
  characteristics, a crib-driven bombe, Tutte's period test), Shannon's
  perfect secrecy, unicity distance and spurious-key counts, and
  hill-climbing and annealing solvers for simple and homophonic substitution;
  attack results report how many candidates they scored;
  a 16-entry history page, 16 gallery examples and ten exercises.
