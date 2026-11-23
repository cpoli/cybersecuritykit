# cybersecuritykit roadmap

What isn't done yet, in priority order. `PLAN.md` holds the decisions, the
parallel session plan, and the candidate breakthroughs.

## Conventions

- One item per session. Domain sessions own only their own directories (see
  `PLAN.md`, "Parallel work plan").
- Every item ends with ruff, mypy, pytest at 100% coverage, and a clean
  `make html` passing.
- Simulation only (`SECURITY.md`); a breakthrough that cannot be simulated
  faithfully is replaced, not approximated with live tooling.

## R1. Repository and release plumbing

**Why:** CI, docs deploy and PyPI publishing need the GitHub repo.
**Now:** local files only; no git.
**Approach:** the user runs `git init`, creates `cpoli/cybersecuritykit`,
configures the PyPI trusted publisher (environment `pypi`), gh-pages and the
Zenodo hook.

## R2. Domain subpackages (S1-S13)

**Why:** the subpackages are empty.
**Now:** skeletons with empty `__all__`, stub history, api and exercise pages.
**Approach:** one session per domain, wave 1 then wave 2 as in `PLAN.md`. Each
delivers systems modules, frozen results, plots, tests, a history page with at
least 15 breakthroughs, one gallery example per breakthrough, and an exercise
page.
**Done:** S1 `classical` (2026-11-23).

## R3. Integration (S14)

**Why:** the landing pages need content from every domain.
**Now:** the index lists subpackages only through generated cards; no hero
images, glossary, quickstart, tutorials or logo.
**Approach:** README and index bullets with one figure per subpackage, a hero
image, glossary, start-here and quickstart pages, `notebooks/quickstart.ipynb`,
three or four cross-domain tutorials (for example "one password's life",
"from frequency analysis to side channels"), a logo, and conf.py alias cleanup.

## R4. Release 0.1.0

**Why:** publish to PyPI and get a Zenodo version DOI.
**Approach:** CHANGELOG `## [0.1.0] - date`, CITATION.cff `date-released`, tag
`v0.1.0`; then add the release's own Zenodo version DOI (never the concept DOI)
to CITATION.cff and the README badge.
