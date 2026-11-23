# 03: S2 symmetric domain

**What to build:** Learners can build reduced-round toy Feistel, SP-network, DES-like and AES-like ciphers and run the generic and structural attacks against them (differential, linear, integral, slide, meet-in-the-middle, time-memory trade-off, Berlekamp-Massey), and see mode and composition failures (ECB penguin, padding oracle, CBC-MAC forgery, GCM nonce reuse, Sweet32, RC4/WEP). User stories 18-20.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `csk.symmetric.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [ ] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [ ] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [ ] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [ ] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [ ] API page and exercise page (doctested, solutions in dropdowns) filled in
- [ ] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [ ] Overlaps with blockchainkit cross-link instead of re-teaching
- [ ] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [ ] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [ ] Toy ciphers expose a stable public interface that sidechannel (13) and pqc (12) can import
- [ ] Any full-strength reference path matches the published FIPS vectors
