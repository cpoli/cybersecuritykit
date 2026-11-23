Scope and model boundaries
==========================

cybersecuritykit teaches how attacks and defences work by **simulating** them.
These boundaries hold for every subpackage, and a change that would cross one
is out of scope.

- **No live targets.** Nothing opens a socket, sends a packet, resolves a
  name, or touches the file system outside a temporary directory. Simulated
  hosts use the reserved ``.test`` domain (RFC 2606) and the documentation
  address blocks of RFC 5737, from ``cybersecuritykit.constants``.
- **Toy cryptography.** Ciphers are small-block or reduced-round teaching
  versions, keys are short enough to search, and arithmetic is variable-time
  on purpose. None of it protects real data.
- **Toy machines, not real exploits.** Memory-safety bugs, return-oriented
  programming and fuzzing run on a small deterministic virtual machine with
  its own instruction set, never on native code.
- **Models, not malware.** Worms and botnets are epidemic and graph models.
  No code in the package replicates, persists, or hides itself.
- **Synthetic data.** Traffic, logs, power traces and personal records are
  generated from explicit seeds. Re-identification experiments use generated
  populations, never real datasets about people.
- **Hashes, elliptic curves, signatures and zero knowledge** belong to the
  sibling package `blockchainkit <https://cpoli.github.io/blockchainkit/>`__;
  cybersecuritykit uses public-key cryptography only where a protocol or an
  attack needs it.
