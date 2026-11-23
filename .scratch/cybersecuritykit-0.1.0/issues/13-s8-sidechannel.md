# 13: S8 sidechannel domain

**What to build:** Learners can attack the toy ciphers and toy RSA through simulated leakage: timing (Kocher, Brumley-Boneh, Lucky Thirteen), power (SPA, DPA, CPA, templates), cache (Bernstein, prime+probe, Flush+Reload), faults (Boneh-DeMillo-Lipton, DFA), keystroke timing, acoustic and EM signals, Rowhammer on simulated DRAM, Spectre/Meltdown on a toy speculative CPU, plus masking, the probing model and TVLA. User stories 38-40.

**Blocked by:** 03 (symmetric), 04 (protocols)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `csk.sidechannel.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [ ] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [ ] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [ ] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [ ] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [ ] API page and exercise page (doctested, solutions in dropdowns) filled in
- [ ] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [ ] Overlaps with blockchainkit cross-link instead of re-teaching
- [ ] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [ ] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [ ] Targets are imported from symmetric and protocols, never re-implemented; each import recorded in CLAUDE.md
- [ ] No hardware access, timers or real measurements; all traces simulated and seeded
