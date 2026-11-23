# 02: S1 classical domain

**What to build:** Learners can run and break the classical ciphers from al-Kindi to the Zodiac 340: frequency analysis, polyalphabetic and digraph ciphers, Kasiski and index of coincidence, Hill's known-plaintext break, toy Enigma and Lorenz cryptanalysis, Shannon's perfect secrecy and unicity distance, and hill-climbing solvers. User stories 15-17.

**Blocked by:** None (can start immediately)

**Status:** resolved

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [x] `csk.classical.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [x] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [x] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [x] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [x] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [x] API page and exercise page (doctested, solutions in dropdowns) filled in
- [x] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [x] Overlaps with blockchainkit cross-link instead of re-teaching
- [x] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [x] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [x] Built on `constants.ALPHABET`; the two-time pad entry cross-links blockchainkit's one-time pad
