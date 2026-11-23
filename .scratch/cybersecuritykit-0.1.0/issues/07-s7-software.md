# 07: S7 software domain

**What to build:** Learners can trigger and mitigate memory-safety bugs on a toy VM (stack smashing, format strings, return-into-libc, ROP, a Heartbleed-style over-read) with canaries, W^X, ASLR and CFI as switches; find planted bugs with random, coverage-guided and concolic fuzzers and symbolic execution; and see SQL injection and XSS on a toy query language and toy template engine. User stories 34-37.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `csk.software.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [ ] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [ ] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [ ] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [ ] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [ ] API page and exercise page (doctested, solutions in dropdowns) filled in
- [ ] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [ ] Overlaps with blockchainkit cross-link instead of re-teaching
- [ ] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [ ] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [ ] The toy VM's instruction set cannot express host system calls, file or network access
