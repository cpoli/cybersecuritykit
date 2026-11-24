# 12: S3 pqc domain

**What to build:** Learners can run toy post-quantum schemes and the attacks that shape them: LWE, Ring-LWE, a Kyber-like KEM, NTRU, McEliece and Niederreiter with information-set decoding, Winternitz, XMSS and SPHINCS-style signatures, Fiat-Shamir with aborts, multivariate schemes with Patarin's and Beullens's attacks, LLL, and small state-vector Shor and Grover simulations. User stories 21-24.

**Blocked by:** 03 (symmetric)

**Status:** resolved

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [x] `csk.pqc.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [x] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [x] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [x] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [x] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [x] API page and exercise page (doctested, solutions in dropdowns) filled in
- [x] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [x] Overlaps with blockchainkit cross-link instead of re-teaching
- [x] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [x] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [x] Any import from symmetric is recorded in CLAUDE.md's cross-domain list
- [x] Lamport stays in blockchainkit and is cross-linked; Castryck-Decru only if a faithful toy isogeny model exists

## Comments

- 2026-11-24: Resolved on `pqc-integration`. It went ahead before 03 (symmetric) because pqc imports nothing from symmetric. Hashing uses stdlib `hashlib`, so CLAUDE.md's cross-domain list stays unchanged.
