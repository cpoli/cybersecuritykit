# Spec: cybersecuritykit from scaffold to 0.1.0

Status: ready-for-agent

Source: ROADMAP.md (R1-R4), PLAN.md decisions D1-D5.

## Problem Statement

cybersecuritykit has a finished scaffold and nothing to teach. All thirteen
domain subpackages (`classical`, `symmetric`, `pqc`, `protocols`, `auth`,
`access`, `software`, `sidechannel`, `malware`, `network`, `detection`,
`privacy`, `risk`) export an empty `__all__`. Their history, API and exercise
pages are stubs, the gallery is empty, and the landing pages list the domains
only as generated cards. A learner who installs `csk` gets a version string and
the shared constants. A maintainer cannot release: there is no repository, no
trusted publisher and no Zenodo DOI. The sibling kits (blockchainkit,
mathematicskit and the rest) each teach a field from history and mathematics
down to runnable code. cybersecuritykit does not do that yet, and doing it
carelessly could produce dual-use material that the scope rule forbids.

## Solution

Build out the kit in the order ROADMAP.md sets:

- **R1.** The user sets up the repository and release plumbing.
- **R2.** Thirteen domain sessions (S1-S13) run in two waves. Each delivers one
  domain to the kit standard: systems modules, frozen results, plots, tests at
  100% statement and branch coverage, a history page with at least 15
  breakthroughs, one gallery example per breakthrough, and an exercise page.
- **R3.** An integration session (S14) gives the documentation a front door:
  README and index bullets with one figure per subpackage, a hero image,
  glossary, start-here and quickstart pages, a quickstart notebook, three or
  four cross-domain tutorials, a logo, and a cleanup of the conf.py aliases.
- **R4.** Release 0.1.0 to PyPI, then record the release's own Zenodo version
  DOI.

Everything runs against toy targets defined in the package: toy ciphers and key
sizes, a toy VM, simulated host stacks, synthetic traffic, logs and
populations, and epidemic models in place of malware. When a breakthrough
cannot be taught faithfully under that rule, it is replaced.

## User Stories

### Learners

1. As a learner, I want `import cybersecuritykit as csk` to give me thirteen populated domains, so that I can explore security from one entry point.
2. As a learner, I want each domain's history page to tell the story of at least 15 breakthroughs in date order, so that I understand why each idea arose.
3. As a learner, I want every history entry to state the original problem and its key mechanism in a math block, so that I learn the idea and not just the name.
4. As a learner, I want every history entry to link the API that implements it, so that I can run the idea myself.
5. As a learner, I want every history entry to say how the teaching version differs from the real system, so that I don't mistake a toy for the real thing.
6. As a learner, I want every history entry to cite a primary source, so that I can read the original paper.
7. As a learner, I want each breakthrough to have its own gallery example whose title names it, so that I can find the experiment for the idea I just read about.
8. As a learner, I want gallery examples to use fixed seeds and small bounded searches, so that they run in seconds and give the same figure every time.
9. As a learner, I want each example to end with an exercise cell, so that I have a next step to try.
10. As a learner, I want an exercise page per domain with doctested problems and solutions in dropdowns, so that I can check my own work.
11. As a learner, I want results returned as frozen dataclasses with named fields, so that I can inspect `result.key_guess` rather than unpack a tuple.
12. As a learner, I want clear errors for invalid inputs (bools passed as ints, negative sizes, empty byte strings), so that my mistakes are caught at the call site.
13. As a learner, I want plot functions that accept `ax=None` and return the Axes, so that I can compose figures.
14. As a learner, I want `import cybersecuritykit` not to pull in matplotlib or numpy, so that the core works in a minimal environment.
15. As a learner of classical ciphers, I want to break Vigenère, Playfair, Hill and substitution ciphers with frequency analysis, Kasiski examination, index of coincidence and hill climbing, so that I see how statistics defeats secrecy.
16. As a learner of classical ciphers, I want toy Enigma and Lorenz models with Rejewski's cycles, the bombe and Tutte's statistics, so that I can follow wartime cryptanalysis step by step.
17. As a learner of classical ciphers, I want Shannon's perfect secrecy and unicity distance computed on real ciphers, so that I connect information theory to breaks.
18. As a learner of symmetric crypto, I want toy Feistel, SP-network, DES-like and AES-like ciphers with reduced rounds, so that differential, linear, integral and slide attacks finish in seconds.
19. As a learner of symmetric crypto, I want to see the ECB penguin, padding oracles, CBC-MAC forgeries, GCM nonce reuse and Sweet32 birthday collisions, so that I learn why modes and composition matter.
20. As a learner of symmetric crypto, I want LFSRs with Berlekamp-Massey, Hellman's time-memory trade-off and meet-in-the-middle, so that I understand generic attacks.
21. As a learner of post-quantum crypto, I want toy LWE, Ring-LWE, Kyber-like, NTRU, McEliece and Niederreiter schemes, so that I can see the hard problems the new standards rest on.
22. As a learner of post-quantum crypto, I want Winternitz, XMSS and SPHINCS-style signatures, so that I go beyond the Lamport scheme that blockchainkit teaches.
23. As a learner of post-quantum crypto, I want small state-vector simulations of Shor and Grover, so that I see why key sizes change.
24. As a learner of post-quantum crypto, I want LLL, information-set decoding, Patarin's linearization and Beullens's Rainbow break on toy parameters, so that I see how each family gets attacked.
25. As a learner of protocols, I want Needham-Schroeder, Lowe's attack, Kerberos, Diffie-Hellman man-in-the-middle and replay modelled against a Dolev-Yao attacker, so that I can watch protocols fail.
26. As a learner of protocols, I want a toy model checker that finds Lowe's attack automatically, so that I understand automated verification.
27. As a learner of protocols, I want Bleichenbacher's attack on toy RSA, downgrade attacks and KRACK-style nonce reuse, so that I see real-world protocol failures.
28. As a learner of protocols, I want toy X3DH, the double ratchet and a TLS 1.3-shaped handshake, so that I see modern designs.
29. As a learner of authentication, I want salted hashing, bcrypt and Argon2-style cost and memory, rainbow tables, dictionary and PCFG guessing on synthetic password corpora, so that I learn password storage and cracking without real credentials.
30. As a learner of authentication, I want HOTP and TOTP checked against the RFC test vectors, Lamport hash chains and honeywords, so that I trust the implementations.
31. As a learner of authentication, I want FAR/FRR curves from simulated biometric scores and an origin-binding model for WebAuthn, so that I understand the trade-offs beyond passwords.
32. As a learner of access control, I want access matrices, Bell-LaPadula, Biba, Clark-Wilson, Chinese wall, RBAC, ABAC and Zanzibar-style relationship checks, so that I can compare models on the same scenario.
33. As a learner of access control, I want a bounded HRU and take-grant safety search, so that I see why safety is undecidable in general.
34. As a learner of software security, I want a toy VM where I can trigger stack overflows, format-string bugs, return-into-libc, ROP and a Heartbleed-style over-read, so that I learn memory-safety bugs with no real exploits.
35. As a learner of software security, I want canaries, W^X, ASLR and CFI as switchable mitigations on that VM, so that I see what each one stops.
36. As a learner of software security, I want random, coverage-guided and concolic fuzzers that find planted bugs in toy programs, so that I understand testing for vulnerabilities.
37. As a learner of software security, I want SQL injection and XSS demonstrated on a toy query language and a toy template engine, so that I see injection without a real database or browser.
38. As a learner of side channels, I want simulated timing, power, cache and fault traces from toy targets, so that I can run Kocher, DPA, CPA, template, prime+probe, Flush+Reload and fault attacks.
39. As a learner of side channels, I want masking and TVLA t-tests, so that I see countermeasures and how to assess them.
40. As a learner of side channels, I want a toy speculative CPU for Spectre/Meltdown and a simulated DRAM for Rowhammer, so that I learn microarchitectural attacks without touching hardware.
41. As a learner of malware, I want SI and SIR epidemic models on contact, scale-free and social graphs, so that I can study worm spread without self-replicating code.
42. As a learner of malware, I want hit lists, permutation scanning, throttling, containment and kill-switch scenarios modelled, so that I understand defence dynamics.
43. As a learner of malware, I want a domain-generation model whose names fall only under `.test`, so that sinkholing is demonstrable and harmless.
44. As a learner of networking, I want simulated TCP/IP host stacks on RFC 5737 addresses for sequence prediction, ARP and DNS poisoning, SYN floods with SYN cookies, and port-scan types, so that I can study attacks with no sockets.
45. As a learner of networking, I want a simulated AS graph for BGP hijacks, amplification arithmetic and traceback by packet marking, so that I understand Internet-scale threats.
46. As a learner of networking, I want firewall rule-anomaly detection, so that I can reason about configurations.
47. As a learner of detection, I want Aho-Corasick, Boyer-Moore and Snort-like rules over synthetic traffic, so that I see signature matching.
48. As a learner of detection, I want ROC curves, the base-rate fallacy, CUSUM, threshold random walk, system-call n-grams and isolation forests on synthetic data, so that I understand anomaly detection and its limits.
49. As a learner of detection, I want reassembly-ambiguity evasion and alert correlation modelled, so that I see the attacker-defender interplay.
50. As a learner of privacy, I want k-anonymity, l-diversity and t-closeness on synthetic populations, and linkage and sparse-data deanonymization attacks, so that I learn why anonymization fails.
51. As a learner of privacy, I want the Laplace and exponential mechanisms, composition theorems, Rényi DP, RAPPOR and a small DP-SGD accountant, so that I learn differential privacy concretely.
52. As a learner of privacy, I want reconstruction (Dinur-Nissim, a Census-style experiment) and membership-inference attacks on synthetic data, so that I see what DP defends against.
53. As a learner of risk, I want fault trees, attack trees, attack graphs and Bayesian attack graphs, so that I can model threats structurally.
54. As a learner of risk, I want ALE, Gordon-Loeb, FAIR, CVSS and EPSS-style calculations, so that I can quantify risk.
55. As a learner of risk, I want security-game, interdependent-security, insurance and heavy-tailed breach models, so that I understand the economics.
56. As a newcomer, I want start-here and quickstart pages and a quickstart notebook, so that I know where to begin.
57. As a newcomer, I want a glossary, so that terms are defined once and used consistently across domains.
58. As a learner, I want cross-domain tutorials such as "one password's life" and "from frequency analysis to side channels", so that I see how the domains connect.
59. As a learner, I want the README and docs index to show one figure per subpackage and a hero image, so that I can see at a glance what each domain does.
60. As a learner who also uses blockchainkit, I want overlapping topics (hashes, signatures, Lamport, one-time pad, PBKDF2/scrypt) to cross-link rather than be re-taught, so that the two kits complement each other.

### Instructors

61. As an instructor, I want every experiment to be deterministic under an explicit seed, so that the numbers in my slides match what students get.
62. As an instructor, I want the scope rule stated in the docs and enforced in code, so that I can assign the kit without dual-use concerns.
63. As an instructor, I want doctested exercises, so that the solutions I hand out are guaranteed to run.

### Maintainers and contributors

64. As a domain-session agent, I want to own only my domain's code, examples and pages, so that thirteen sessions can run in parallel without conflicts.
65. As a domain-session agent, I want every shared registration already in place, so that I never edit the package root, pyproject or the docs toctrees.
66. As a wave-2 agent (pqc, sidechannel, detection), I want to import from wave-1 domains in one direction only, with each import recorded in CLAUDE.md, so that there are no cycles.
67. As a maintainer, I want every session to finish with ruff, mypy strict, pytest at 100% statement and branch coverage, doctests and a clean nitpicky docs build, so that main stays green.
68. As a maintainer, I want shared helpers (validators, constants) reused rather than re-implemented, so that the API is uniform.
69. As a maintainer, I want new docstring types registered in the conf.py aliases or nitpick ignores, and consolidated at integration, so that nitpicky builds pass without clutter.
70. As a maintainer, I want breakthrough dates marked [check] verified against the primary source before the entry is written, so that the history is accurate.
71. As a maintainer, I want unfaithful candidates (for example Castryck-Decru without a faithful toy isogeny model) replaced rather than faked, so that every entry is honest.
72. As a maintainer, I want CHANGELOG entries for each domain, so that the 0.1.0 notes are complete.
73. As a release manager, I want the tag, `__version__`, CITATION.cff and the CHANGELOG heading to agree, so that the release workflow publishes.
74. As a release manager, I want the release's own Zenodo version DOI in CITATION.cff and the README badge, never the concept DOI, so that citations pin the exact version.
75. As a user installing from PyPI, I want `pip install cybersecuritykit` to work on Python 3.10-3.15 on Linux and macOS, so that the kit runs wherever its siblings do.

## Implementation Decisions

- **Order.** Run R1 (the user's step) in parallel with R2. R2 runs as wave 1 (S1 classical, S2 symmetric, S4 protocols, S5 auth, S6 access, S7 software, S9 malware, S10 network, S12 privacy, S13 risk), then wave 2 (S3 pqc, S8 sidechannel, S11 detection). R3 (S14) waits for all domains, and R4 waits for R1 and R3. Each item is one session.
- **Domain layout is fixed.** `core.base` holds shared types and frozen result dataclasses (never bare tuples). `systems` has one module per breakthrough family. `utils` holds helpers that are not models. `visualizers.plots` holds matplotlib functions with `ax=None` that return the Axes. Each subpackage's `__init__` re-exports the `__all__` of `core`, `core.base` and `systems`, and never imports `visualizers`.
- **Public interface.** The public interface of a domain is its subpackage `__all__`, and that is the contract tests and docs link to. Names describe the breakthrough or mechanism (for example a padding-oracle attack function that returns a result dataclass with recovered plaintext and oracle query count). Attack results report the cost (queries, traces, guesses, steps) alongside success, so that examples can plot cost against parameters.
- **Toy targets live with the domain that teaches them.** The toy VM lives in `software`, toy block ciphers in `symmetric`, toy RSA and DH wherever a protocol or attack first needs them, simulated host stacks and synthetic traffic in `network`, and synthetic populations in `privacy`. Wave-2 domains reuse these by import: sidechannel reuses `symmetric` ciphers and toy RSA, detection reuses `network` traffic, and pqc may reuse `symmetric` helpers. Wave 1 never imports wave 2.
- **Shared infrastructure is reused.** Validation goes through the shared validators (integer, seed, probability, positive, byte_string). Seeds, the alphabet, the example domain and the documentation networks come from the shared constants. A domain that needs a new shared constant or validator adds it minimally, re-reading the file immediately before the edit.
- **Determinism.** All randomness comes from `random.Random(seed)` with `DEFAULT_SEED` as the default. There is no global random state and no `secrets`.
- **Stdlib-only core.** Library code uses only the standard library, including `hashlib` and `hmac`. numpy and matplotlib appear only in visualizers and examples.
- **Scope rule (D1).** No sockets, packet capture or injection, real-host scanning, real exploits or shellcode, self-replicating code, credential harvesting or real personal data. Simulated names use `.test` and addresses come from the RFC 5737 blocks. A breakthrough that can't be simulated faithfully is dropped and replaced from the candidate list or a new datable result.
- **blockchainkit boundary (D2).** Hashes, curves, signatures including Lamport, commitments, zero knowledge and PBKDF2/scrypt stay in blockchainkit. Entries that touch them cross-link to it. There is no import dependency between the kits.
- **History pages.** Each page has at least 15 entries in mathematicskit's form: an epigraph, then `YEAR -- Title` headings, prose with a math block, an *Implementation:* line, a *References:* line with a primary source, and a minigallery of the entry's own example(s). Entries contain no admonitions, labelled sub-blocks or doctests. Examples are never shared between entries.
- **Gallery examples.** Grouped in topic folders, each with a README. Each example has a raw docstring title naming its breakthrough, a single import cell, seeded and bounded sections with assertions, `plt.show()` closing the last figure cell, and a final exercise cell.
- **Exercises and tutorials** use doctest directives. Solutions go in dropdowns.
- **Integration (S14).** Glossary, start-here, quickstart, the quickstart notebook, three or four cross-domain tutorials, a logo and hero image, one README and index bullet with a figure per subpackage, and consolidation of the conf.py `napoleon_type_aliases` and `nitpick_ignore` entries.
- **Release (R4).** A CHANGELOG `## [0.1.0] - date` section, CITATION.cff `date-released`, and a `v0.1.0` tag that matches `__version__`. The release workflow publishes to PyPI through the trusted publisher (environment `pypi`), creates the GitHub Release and deploys the docs to gh-pages. Afterwards the release's own Zenodo version DOI goes into CITATION.cff and the README badge.

## Testing Decisions

- **What makes a good test.** Exercise only external behavior through a domain's public `__all__`: inputs and outputs, published test vectors, algebraic identities (decrypt(encrypt(m)) = m, an attack recovers the planted key), and failure behavior (invalid arguments raise, a mitigation stops an attack). Tests never reach into private helpers or assert on intermediate state that isn't part of a returned result. Property tests use hypothesis. Tests compare floats with `abs(a - b) < 1e-10` or `np.allclose`.
- **Seam 1: each domain's public API.** Each domain's tests split as in blockchainkit:
  - Breakthrough-API tests: one or more per breakthrough, showing the mechanism works and the attack succeeds within its stated cost.
  - Boundary-case tests: validation errors, edge sizes, degenerate inputs, and mitigations toggled on and off.
  - Visualizer tests: each plot function draws on a supplied or fresh Axes and returns it.

  Coverage must reach 100% statement and branch through this seam alone, with no exclusions.
- **Seam 2: the package contract test** that already exists. It checks that every name in each subpackage's `__all__` resolves, that each layer's `__all__` is re-exported, that plot functions are callable, the constants' values, that the simulated networks are documentation-only, and that importing cybersecuritykit loads neither matplotlib nor numpy. Domains don't add to it. It must keep passing as `__all__` fills.
- **Seam 3: the docs build.** The HTML build re-executes every gallery example, whose own assertions act as integration tests. The doctest build runs exercise pages, tutorials and module docstrings. Warnings are errors.
- **Published vectors where they exist:** the HOTP and TOTP vectors in RFC 4226 and RFC 6238, the DES and AES vectors in their FIPS documents for any full-strength reference path, and the published Kyber/ML-KEM or LWE parameter checks where toy parameters allow.
- **Prior art:** blockchainkit's per-subpackage breakthrough-API, boundary-case and visualizer tests, and this repo's package contract and validation tests.
- **No new seams.** The user confirmed these three.

## Out of Scope

- R1 itself: `git init`, creating the GitHub repo, the PyPI trusted publisher, gh-pages and the Zenodo hook are the user's steps.
- Anything that touches real networks, hosts, accounts, hardware or personal data, or that would work as a real attack tool, including real exploits, shellcode, scanners and self-replicating code.
- Production-grade or constant-time cryptography, and full-size parameters except as test-vector reference paths.
- Re-teaching blockchainkit's topics, or any import dependency on another kit.
- A conda-forge recipe, papers, and releases after 0.1.0.
- Breakthroughs that can't be simulated faithfully, such as Castryck-Decru without a faithful toy isogeny model.

## Further Notes

- The per-domain candidate lists in PLAN.md are the starting set. Dates marked [check] must be confirmed against the primary source.
- Each domain session should add a short progress note to PLAN.md and tick its ROADMAP item. Wave-2 sessions record each cross-domain import in CLAUDE.md.
- Shared files (conf.py aliases, constants, validators, CHANGELOG) see concurrent edits. Re-read them immediately before every edit and keep each edit minimal.
- Because the work is one ROADMAP item per session, this spec splits naturally into fifteen issues: S1-S13, S14 and R4. Each issue can quote the relevant user stories and decisions above.
