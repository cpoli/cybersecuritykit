# cybersecuritykit plan

## Goal

A teaching toolkit for cybersecurity in the kit family's form: thirteen domain
subpackages, each following its ideas from history and mathematics to a small,
typed, stdlib-only API, a figure, and a gallery experiment, with a history page
of at least 15 breakthroughs that each link to their own example.

## Baseline (2026-11-22)

The scaffold is in place: packaging, shared `_validation.py` and
`constants.py`, thirteen empty subpackage skeletons (`core/base.py`,
`systems/`, `utils/`, `visualizers/plots.py`, `tests/`), every shared
registration file already listing all thirteen domains, the documentation
skeleton (generated grids from `SUBPACKAGES` in `docs/source/conf.py`, stub
api, history and exercise pages, the scope page), and the CI, docs and release
workflows. No domain code yet. Version `0.1.0`, unreleased.

## Decisions

| | Decision | Why |
|:--|:--|:--|
| D1 | **Simulation only.** Toy ciphers and keys, a toy VM for memory-safety bugs, synthetic packets, logs and traces, epidemic models for malware. No sockets, packet capture or injection, scanning, real exploits, shellcode, self-replicating code, or real personal data. Simulated hosts use `constants.EXAMPLE_DOMAIN` and `constants.DOCUMENTATION_NETWORKS`. | Teaching value without dual-use harm; stated in `SECURITY.md` and `docs/source/scope.rst`. A breakthrough that cannot be taught under this rule is dropped. |
| D2 | **Boundary with blockchainkit.** blockchainkit keeps hashes, elliptic curves, signatures (incl. Lamport), commitments and zero knowledge, and PBKDF2/scrypt in `wallets`. cybersecuritykit uses `hashlib` and `hmac` from the stdlib and implements public-key pieces (toy RSA, DH) only where a protocol or attack needs them. `pqc` covers post-quantum signatures beyond Lamport (Winternitz, XMSS, SPHINCS-style, Fiat-Shamir with aborts). `privacy` means data privacy (anonymization, differential privacy), not ledger anonymity. Overlapping topics cross-link instead of duplicating. | No dependency between the kits; no breakthrough taught twice. |
| D3 | **Thirteen domains**, in five categories: Cryptography (`classical`, `symmetric`, `pqc`), Protocols and identity (`protocols`, `auth`, `access`), Systems (`software`, `sidechannel`, `malware`), Networks (`network`, `detection`), Data and decisions (`privacy`, `risk`). | Covers a standard security curriculum; each domain has 15+ datable breakthroughs. |
| D4 | **Parallel build**, one session per domain, then an integration session. Shared registration files are pre-populated so domain sessions only touch their own directories. | Same approach as blockchainkit; see "Parallel work plan". |
| D5 | **Conventions are blockchainkit's** (see `CLAUDE.md`): frozen result dataclasses, explicit seeds, 100% statement and branch coverage, strict mypy, NumPy docstrings citing sources, imported as `csk`. | One family, one API. |

## Phases

- **Phase 0, repository.** `git init`, GitHub repo `cpoli/cybersecuritykit`,
  PyPI trusted publisher (environment `pypi`), gh-pages, Zenodo hook.
  Status: the user's step; not started.
- **Phase 1, scaffold.** Status: done 2026-11-22.
- **Phase 2, domains.** One session per domain (S1-S13): systems modules,
  results, plots, tests at 100%, history page with 15+ breakthroughs, one
  gallery example per breakthrough, exercise page. Status: not started.
- **Phase 3, integration.** Shared `napoleon_type_aliases`/`nitpick_ignore`
  cleanup, README and index bullets and hero images per subpackage,
  `docs/source/glossary.rst`, `start_here.rst`, `quickstart.rst`,
  `notebooks/quickstart.ipynb`, cross-subpackage tutorials, logo. Status: not
  started.
- **Phase 4, release 0.1.0.** CHANGELOG section, CITATION.cff, tag. Then add
  the Zenodo version DOI to CITATION.cff and README. Status: not started.

## Parallel work plan

Each domain session owns `cybersecuritykit/<name>/`, `examples/<name>/`,
`docs/source/api/<name>.rst`, `docs/source/history/<name>_breakthroughs.rst`
and `docs/source/exercises/<name>.rst`. It must not edit another domain's
files. Shared files are already registered for every domain; a session that
needs to change one (a `conf.py` alias, a constant, a validator) re-reads it
immediately before editing and keeps the edit minimal.

- **Wave 1 (independent):** S1 `classical`, S2 `symmetric`, S4 `protocols`,
  S5 `auth`, S6 `access`, S7 `software`, S9 `malware`, S10 `network`,
  S12 `privacy`, S13 `risk`.
- **Wave 2 (may reuse wave 1):** S3 `pqc` (may reuse `symmetric` helpers),
  S8 `sidechannel` (targets toy ciphers from `symmetric` and toy RSA),
  S11 `detection` (consumes synthetic traffic from `network`).
- **S14, integration** (Phase 3), after all domains.

Cross-domain imports go one way only (later wave imports earlier) to avoid
cycles; record each one in `CLAUDE.md`.

## Candidate breakthroughs

Dates marked [check] must be confirmed against the primary source before the
entry is written. Each session picks at least 15 and may replace candidates
that cannot be simulated faithfully.

### classical

1. c. 850 -- al-Kindi's frequency analysis
2. c. 1467 -- Alberti's cipher disk and polyalphabetic substitution
3. 1553 -- Bellaso's keyed polyalphabetic cipher (the "Vigenère")
4. 1854 -- Wheatstone's Playfair digraph cipher
5. 1863 -- Kasiski's examination (Babbage c. 1854 [check])
6. 1883 -- Kerckhoffs's principles
7. 1917 -- Vernam's teleprinter cipher and the two-time pad (cross-link blockchainkit's one-time pad)
8. 1918 -- ADFGVX and Painvin's break
9. 1922 -- Friedman's index of coincidence [check]
10. 1929 -- Hill's matrix cipher and its known-plaintext break
11. 1932 -- Rejewski's characteristic cycles against Enigma
12. 1940 -- Turing's bombe and cribs
13. 1942 -- Tutte's statistical break of the Lorenz cipher
14. 1949 -- Shannon's perfect secrecy
15. 1949 -- Shannon's unicity distance
16. 1995 -- Jakobsen's hill-climbing attack on substitution ciphers [check]
17. 2020 -- the Zodiac 340 solution by homophonic hill climbing

### symmetric

1. 1949 -- Shannon's confusion and diffusion (SP networks)
2. 1969 -- Berlekamp-Massey and the linear complexity of LFSRs
3. 1973 -- Feistel's network and Lucifer
4. 1977 -- DES
5. 1980 -- Hellman's time-memory trade-off
6. 1981 -- meet-in-the-middle against double encryption
7. 1981 -- modes of operation (FIPS 81) and the ECB penguin
8. 1988 -- Luby-Rackoff: a pseudorandom permutation from three rounds
9. 1990 -- Biham and Shamir's differential cryptanalysis
10. 1993 -- Matsui's linear cryptanalysis
11. 1994 -- CBC-MAC and its variable-length forgery (Bellare-Kilian-Rogaway)
12. 1997 -- the Square (integral) attack on reduced AES
13. 1998 -- EFF's DES cracker and exhaustive search
14. 1999 -- Biryukov and Wagner's slide attack
15. 2000 -- Bellare-Namprempre and encrypt-then-MAC
16. 2001 -- Rijndael becomes AES
17. 2001 -- Fluhrer-Mantin-Shamir on RC4 and WEP
18. 2002 -- Vaudenay's padding oracle
19. 2006 -- Joux's forbidden attack on GCM nonce reuse
20. 2016 -- Sweet32: birthday attacks on 64-bit blocks

### pqc

1. 1962 -- Prange's information-set decoding
2. 1978 -- McEliece's code-based encryption
3. 1979 -- Winternitz one-time signatures (Merkle 1979 [check]; Lamport stays in blockchainkit)
4. 1982 -- LLL lattice reduction
5. 1986 -- Niederreiter's dual formulation
6. 1988 -- Matsumoto-Imai multivariate encryption and Patarin's 1995 linearization attack
7. 1994 -- Shor's period finding (small state-vector simulation)
8. 1996 -- Grover's search and halved key-search security
9. 1996 -- Ajtai's worst-case to average-case reduction
10. 1998 -- NTRU
11. 1999 -- Patarin's oil and vinegar signatures [check]
12. 2005 -- Regev's learning with errors
13. 2010 -- Ring-LWE (Lyubashevsky-Peikert-Regev)
14. 2011 -- XMSS and stateful hash-based signatures
15. 2012 -- Lyubashevsky's Fiat-Shamir with aborts
16. 2015 -- SPHINCS: stateless hash-based signatures
17. 2018 -- Kyber (now ML-KEM, FIPS 203, 2024)
18. 2022 -- Beullens's break of Rainbow (toy parameters)
19. 2022 -- Castryck-Decru on SIDH [stretch: only if a toy isogeny model is faithful]

### protocols

1. 1976 -- man-in-the-middle on unauthenticated Diffie-Hellman
2. 1978 -- Needham-Schroeder
3. 1981 -- Denning-Sacco: timestamps against replay
4. 1983 -- the Dolev-Yao attacker
5. 1988 -- Kerberos
6. 1989 -- BAN logic
7. 1992 -- Bellovin-Merritt encrypted key exchange
8. 1993 -- Bellare-Rogaway provable entity authentication
9. 1995 -- Lowe's attack on Needham-Schroeder public key, found by model checking
10. 1996 -- SSL 3.0 and cipher-suite negotiation
11. 1998 -- Bleichenbacher's million-message attack (toy RSA)
12. 2001 -- Blanchet's ProVerif-style automated protocol verification (toy search)
13. 2003 -- Krawczyk's SIGMA and identity protection [check]
14. 2009 -- the TLS renegotiation attack
15. 2015 -- FREAK and Logjam: downgrade to export grade
16. 2016 -- Signal's X3DH and double ratchet
17. 2017 -- KRACK: nonce reuse in the WPA2 handshake
18. 2018 -- TLS 1.3

### auth

1. 1962 -- CTSS and the first password-file leak [check]
2. 1968 -- Wilkes's one-way password storage [check]
3. 1979 -- Morris and Thompson: salt and crypt(3)
4. 1981 -- Lamport's hash-chain one-time passwords
5. 1990 -- Klein's dictionary cracking
6. 1993 -- Daugman's iris codes and the FAR/FRR trade-off
7. 1996 -- challenge-response (CHAP)
8. 1999 -- bcrypt and tunable cost
9. 2003 -- Oechslin's rainbow tables
10. 2005 -- HOTP (RFC 4226)
11. 2009 -- Weir's probabilistic context-free grammar cracking
12. 2011 -- TOTP (RFC 6238) and clock drift
13. 2011 -- composition policies versus length (Komanduri et al.)
14. 2012 -- Bonneau's guessing metrics
15. 2013 -- Juels-Rivest honeywords
16. 2015 -- Argon2 and memory hardness (cross-link blockchainkit's scrypt)
17. 2017 -- Zipf's law in passwords (Wang et al.)
18. 2019 -- WebAuthn origin binding against phishing

### access

1. 1966 -- Dennis and Van Horn's capabilities
2. 1971 -- Lampson's access matrix
3. 1972 -- the Anderson report's reference monitor
4. 1973 -- Bell-LaPadula
5. 1975 -- Saltzer and Schroeder's design principles
6. 1976 -- Harrison-Ruzzo-Ullman: safety is undecidable
7. 1976 -- the take-grant model
8. 1977 -- Biba integrity
9. 1982 -- Goguen-Meseguer noninterference
10. 1985 -- the Orange Book's evaluation classes
11. 1987 -- Clark-Wilson
12. 1988 -- Hardy's confused deputy
13. 1989 -- Brewer-Nash Chinese wall
14. 1992 -- Ferraiolo-Kuhn role-based access control (RBAC96, 1996)
15. 1996 -- Blaze's trust management (PolicyMaker)
16. 2003 -- XACML and attribute-based access control
17. 2019 -- Zanzibar and relationship-based access control

### software

1. 1972 -- the Anderson report's buffer overflow
2. 1976 -- King's symbolic execution
3. 1988 -- the fingerd overflow, on the toy VM
4. 1990 -- Miller's random fuzzing
5. 1996 -- Aleph One's stack smashing
6. 1997 -- return-into-libc
7. 1998 -- StackGuard canaries
8. 1998 -- SQL injection, on a toy query language
9. 2000 -- format-string bugs
10. 2001 -- PaX ASLR and Shacham's 2004 entropy brute force
11. 2004 -- W^X and non-executable stacks
12. 2005 -- Abadi's control-flow integrity
13. 2005 -- DART and concolic testing
14. 2005 -- cross-site scripting, on a toy template engine [check date]
15. 2007 -- Shacham's return-oriented programming
16. 2013 -- AFL and coverage-guided fuzzing
17. 2014 -- Heartbleed: a bounds over-read on the toy VM
18. 2015 -- ownership and borrowing as memory safety [check framing]

### sidechannel

1. 1985 -- van Eck's electromagnetic eavesdropping (simulated signal)
2. 1996 -- Kocher's timing attack on modular exponentiation
3. 1997 -- Boneh-DeMillo-Lipton fault attack on RSA-CRT
4. 1997 -- Biham-Shamir differential fault analysis
5. 1999 -- Kocher-Jaffe-Jun simple and differential power analysis
6. 1999 -- masking (Goubin-Patarin, Chari et al.)
7. 2001 -- Song-Wagner-Tian keystroke timing over SSH
8. 2002 -- template attacks
9. 2003 -- Brumley-Boneh remote timing
10. 2003 -- Ishai-Sahai-Wagner probing model
11. 2004 -- correlation power analysis
12. 2005 -- Bernstein's AES cache timing and Osvik-Shamir-Tromer prime+probe
13. 2011 -- TVLA: leakage assessment by t-test
14. 2013 -- Lucky Thirteen
15. 2014 -- Flush+Reload
16. 2014 -- Rowhammer (simulated DRAM)
17. 2014 -- acoustic cryptanalysis (Genkin-Shamir-Tromer)
18. 2018 -- Spectre and Meltdown, on a toy speculative CPU

### malware

1. 1949 -- von Neumann's self-reproducing automata
2. 1984 -- Cohen: detecting viruses is undecidable
3. 1991 -- Kephart and White's epidemiological model
4. 1988 -- the Morris worm's reinfection rate
5. 1999 -- Melissa and email worms on a contact graph
6. 2001 -- Code Red and the SI fit
7. 2001 -- Pastor-Satorras-Vespignani: no threshold on scale-free graphs
8. 2002 -- Staniford-Paxson-Weaver: hit lists and permutation scanning
9. 2002 -- Zou's two-factor worm model
10. 2002 -- Williamson's virus throttling
11. 2003 -- Slammer and bandwidth-limited spread
12. 2003 -- Moore et al.: containment requirements
13. 2005 -- the Samy worm on a social network
14. 2007 -- Storm's peer-to-peer botnet resilience
15. 2009 -- Conficker's domain generation and sinkholing (names in `.test`)
16. 2016 -- Mirai and default credentials
17. 2017 -- WannaCry's kill switch

### network

1. 1985 -- Morris's TCP sequence-number prediction
2. 1989 -- Bellovin's "Security problems in the TCP/IP protocol suite"
3. 1990 -- ARP cache poisoning [check]
4. 1994 -- Cheswick-Bellovin firewalls and packet filters
5. 1996 -- SYN floods and Bernstein's SYN cookies
6. 1997 -- port-scan types (simulated host stacks)
7. 1998 -- Smurf amplification
8. 2000 -- probabilistic packet marking traceback
9. 2001 -- backscatter analysis
10. 2004 -- Al-Shaer-Hamed firewall rule anomalies
11. 2008 -- Kaminsky's DNS cache poisoning
12. 2008 -- the YouTube BGP prefix hijack on a simulated AS graph
13. 2013 -- ZMap and the arithmetic of Internet-wide scanning
14. 2014 -- amplification factors (Rossow)
15. 2016 -- the Dyn DDoS and capacity planning
16. 2019 -- DNS over HTTPS and what an on-path observer still sees [check]

### detection

1. 1959 -- Neyman-Pearson thresholds and ROC curves for alarms [check framing]
2. 1975 -- Aho-Corasick multi-pattern matching
3. 1977 -- Boyer-Moore
4. 1980 -- Anderson's threat monitoring
5. 1987 -- Denning's intrusion-detection model
6. 1990 -- Stoll's honeypot and the Cuckoo's Egg
7. 1996 -- Forrest's system-call n-grams
8. 1998 -- Ptacek-Newsham evasion by reassembly ambiguity
9. 1998 -- Paxson's Bro
10. 1999 -- Snort rules
11. 2000 -- Axelsson's base-rate fallacy
12. 2000 -- McHugh's critique of the DARPA/KDD datasets
13. 2001 -- probabilistic alert correlation (Valdes-Skinner)
14. 2002 -- CUSUM detection of SYN floods (Wang-Zhang-Shin)
15. 2004 -- Jung's threshold random walk scan detection
16. 2005 -- Polygraph: signatures for polymorphic worms
17. 2008 -- isolation forests
18. 2010 -- Sommer-Paxson: outside the closed world

### privacy

1. 1965 -- Warner's randomized response
2. 1977 -- Dalenius's statistical disclosure
3. 1979 -- Denning's tracker attack on statistical databases
4. 2000 -- Sweeney's linkage of ZIP, sex and birth date
5. 2002 -- k-anonymity
6. 2003 -- Dinur-Nissim reconstruction
7. 2006 -- differential privacy and the Laplace mechanism
8. 2006 -- l-diversity
9. 2007 -- t-closeness
10. 2007 -- the exponential mechanism
11. 2008 -- Narayanan-Shmatikov sparse-data deanonymization (synthetic ratings)
12. 2008 -- Homer et al.: membership in a genomic mixture
13. 2010 -- advanced composition
14. 2014 -- RAPPOR and local differential privacy
15. 2016 -- DP-SGD and the moments accountant
16. 2017 -- membership inference
17. 2017 -- Rényi differential privacy
18. 2018 -- the Census reconstruction experiment (synthetic population)

### risk

1. 1962 -- fault-tree analysis
2. 1979 -- annualized loss expectancy (FIPS 65)
3. 1999 -- Schneier's attack trees
4. 2000 -- Arbaugh's windows of vulnerability
5. 2001 -- Anderson: why information security is hard (economics)
6. 2002 -- attack graphs by model checking (Sheyner et al.)
7. 2002 -- the Gordon-Loeb investment model
8. 2003 -- Kunreuther-Heal interdependent security
9. 2004 -- Varian's weakest link, total effort and best shot
10. 2005 -- CVSS
11. 2006 -- FAIR quantitative risk
12. 2008 -- Stackelberg security games (ARMOR)
13. 2009 -- Herley's rational rejection of security advice
14. 2010 -- cyber-insurance market models (Böhme-Schwartz)
15. 2011 -- the kill chain and defence in depth
16. 2012 -- Bayesian attack graphs
17. 2016 -- heavy-tailed breach sizes (Edwards-Hofmeyr-Forrest)
18. 2019 -- EPSS: exploit prediction

## Progress notes

- 2026-11-22: name chosen (free on PyPI and conda-forge), domains and the
  parallel plan decided, scaffold written and checked (ruff, mypy, pytest at
  100%, docs build).
- 2026-11-23: S1 `classical` done: 16 breakthroughs, each with its own gallery
  example; Kerckhoffs's principles (1883) dropped, since it has no mechanism
  to implement, and quoted through Shannon's epigraph instead. The dates
  marked [check] were verified: Babbage is mentioned without a date, Friedman
  is Riverbank Publication No. 22 (1922), Jakobsen is *Cryptologia* 19(3)
  (1995).

## Verification

```bash
source .venv/bin/activate
ruff check . && ruff format --check .
mypy
pytest -q --cov=cybersecuritykit --cov-branch --cov-report=term-missing
pytest --doctest-modules cybersecuritykit --ignore-glob="*/tests/*"
cd docs && MPLBACKEND=Agg make html && MPLBACKEND=Agg make doctest
```
