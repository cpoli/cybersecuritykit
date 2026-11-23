# 09: S10 network domain

**What to build:** Learners can attack and defend simulated TCP/IP host stacks on RFC 5737 addresses: sequence-number prediction, ARP and DNS cache poisoning, SYN floods and SYN cookies, scan types, Smurf and amplification arithmetic, packet-marking traceback, backscatter, firewall rule anomalies, BGP hijack on a simulated AS graph, Internet-scale scan arithmetic, DDoS capacity, and what DoH hides. User stories 44-46.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `csk.network.__all__` exposes the breakthrough APIs; every result is a frozen dataclass; inputs go through the shared validators; randomness is explicitly seeded
- [ ] Library code is stdlib-only; plots take `ax=None` and return the Axes; the package contract test still passes
- [ ] Tests through the public API only (breakthrough-API, boundary-case and visualizer tests, as in blockchainkit); 100% statement and branch coverage, no exclusions; published vectors where they exist
- [ ] History page with an epigraph and at least 15 breakthroughs in the house form; every `[check]` date verified against its primary source; unfaithful candidates replaced, not faked
- [ ] One gallery example per breakthrough (title names it, seeded, bounded, asserts, final exercise cell); no example shared between entries
- [ ] API page and exercise page (doctested, solutions in dropdowns) filled in
- [ ] Scope rule holds: toy targets only, `.test` names and RFC 5737 addresses for anything host-like
- [ ] Overlaps with blockchainkit cross-link instead of re-teaching
- [ ] ruff, mypy strict, pytest, doctests and a clean nitpicky `make html` / `make doctest` all pass
- [ ] CHANGELOG entry added (re-read the file first); PLAN.md progress note and ROADMAP R2 tick for this domain
- [ ] Owns a seeded synthetic-traffic generator with a stable public interface that detection (14) can import
- [ ] No sockets or raw packets anywhere
