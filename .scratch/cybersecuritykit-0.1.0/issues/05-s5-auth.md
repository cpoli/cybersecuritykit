# 05: S5 auth domain

**What to build:** Learners can study authentication end to end on synthetic corpora: salted hashing and crypt(3), bcrypt and Argon2-style cost and memory hardness, dictionary, PCFG and rainbow-table cracking, guessing metrics and Zipf fits, Lamport hash chains, CHAP, HOTP/TOTP with clock drift, honeywords, biometric FAR/FRR, and WebAuthn origin binding. User stories 29-31.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `csk.auth.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [ ] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [ ] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [ ] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [ ] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [ ] API page and exercise page (doctested, solutions in dropdowns) filled in
- [ ] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [ ] Overlaps with blockchainkit cross-link instead of re-teaching
- [ ] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [ ] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [ ] HOTP and TOTP pass the RFC 4226 and RFC 6238 test vectors
- [ ] No real password lists; corpora are generated from seeded models
- [ ] Argon2/scrypt entries cross-link blockchainkit's PBKDF2/scrypt
