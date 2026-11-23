# 15: S14 integration: landing pages, tutorials and glossary

**What to build:** A newcomer lands on the README or docs index and can find their way in: one bullet and figure per subpackage, a hero image and logo, start-here and quickstart pages, a quickstart notebook, a glossary, and three or four cross-domain tutorials (for example "one password's life" and "from frequency analysis to side channels"). User stories 56-60.

**Blocked by:** 02-14 (all domain tickets)

**Status:** ready-for-agent

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] README and docs index list every subpackage with one figure each, plus a hero image and logo
- [ ] Glossary, start-here and quickstart pages written; quickstart notebook runs top to bottom
- [ ] Three or four cross-domain tutorials using doctest directives, each drawing on at least two domains
- [ ] conf.py `napoleon_type_aliases` / `nitpick_ignore` consolidated with no new warnings
- [ ] Scope page and SECURITY.md still accurate for what was built
- [ ] Full verification (ruff, mypy, pytest at 100%, doctests, nitpicky `make html` / `make doctest`) passes; ROADMAP R3 ticked
