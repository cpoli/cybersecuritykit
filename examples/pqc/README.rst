cybersecuritykit.pqc
====================

Gallery examples for :mod:`cybersecuritykit.pqc`. Each one reproduces a breakthrough from
:doc:`the history page </history/pqc_breakthroughs>`, on toy keys, simulated
systems or synthetic data.

The examples are grouped by family, in this order:

- *Code-based cryptography* (30-32): Prange's decoding, McEliece and Niederreiter.
- *Hash-based signatures* (60-62): Winternitz, XMSS and SPHINCS.
- *Lattice signatures* (08): Fiat-Shamir with aborts.
- *Lattices* (01, 04, 05): LLL reduction, Ajtai's SIS hash and NTRU.
- *Learning with errors* (06, 07, 09): Regev's LWE, Ring-LWE and Kyber.
- *Multivariate cryptography* (33-35): Matsumoto-Imai and Patarin, oil and
  vinegar, and Beullens's break of Rainbow.
- *Quantum algorithms* (02, 03): Shor's period finding and Grover's search.

To read them as the history unfolds, start with the quantum algorithms, which
set the threat, and follow the dates on the history page.

Each script is self-contained: download it as a Python file or a notebook, or run
it in the browser with JupyterLite.
