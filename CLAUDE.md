# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An educational, typed Python toolkit for cybersecurity: thirteen domain subpackages (`classical`, `symmetric`, `pqc`, `protocols`, `auth`, `access`, `software`, `sidechannel`, `malware`, `network`, `detection`, `privacy`, `risk`) that follow each idea from its history and mathematics to a small API, a gallery experiment, and a notebook. Conventionally imported as `csk`. It is deliberately *not* production security code: toy ciphers and key sizes, a toy VM for memory-safety bugs, synthetic traffic and logs, and epidemic models instead of malware. Keep those model boundaries explicit.

cybersecuritykit is a sibling of `../blockchainkit`, `../mathematicskit`, `../physicskit` and the other kits, and follows blockchainkit's architecture and conventions. When a convention here seems underspecified, check how blockchainkit handles the equivalent case rather than inventing a new one. `PLAN.md` holds the decisions, the parallel session plan and the candidate breakthroughs; `ROADMAP.md` holds what is left.

## Scope rule (non-negotiable)

Everything is simulated. No sockets, packet capture or injection, scanning of real hosts, real exploits or shellcode, self-replicating code, credential harvesting, or real personal data. Attacks run against toy targets defined in this package (a toy VM, toy ciphers, simulated host stacks, synthetic datasets). Simulated hosts use `constants.EXAMPLE_DOMAIN` (`.test`, RFC 2606) and `constants.DOCUMENTATION_NETWORKS` (RFC 5737). A breakthrough that cannot be taught under this rule is replaced, not approximated with live tooling. See `SECURITY.md` and `docs/source/scope.rst`.

**Boundary with blockchainkit:** blockchainkit owns hashes, elliptic curves, signatures (including Lamport), commitments, zero knowledge and PBKDF2/scrypt. Here, use `hashlib`/`hmac` from the stdlib, implement public-key pieces (toy RSA, DH) only where a protocol or attack needs them, and cross-link overlapping topics instead of re-teaching them. There is no import dependency between the kits. `privacy` means data privacy (anonymization, differential privacy).

## Commands

```bash
# setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

# lint / format (line length 100)
ruff check .
ruff format .

# unit tests: must stay at 100% statement and branch coverage
pytest -q --cov=cybersecuritykit --cov-branch --cov-report=term-missing
pytest cybersecuritykit/classical/tests

# docstring examples
pytest --doctest-modules cybersecuritykit --ignore-glob="*/tests/*"

# type check (strict, blocking in CI)
mypy

# docs: re-executes every examples/*/*/plot_*.py; warnings are errors (nitpicky = True)
cd docs && MPLBACKEND=Agg make html && MPLBACKEND=Agg make doctest

python -m build
```

CI: `.github/workflows/ci.yml` runs lint, tests on Python 3.10-3.15 on Linux and macOS, the package build (`twine check`), and mypy; `docs.yml` runs the HTML and doctest builds. `release.yml` runs on a `vX.Y.Z` tag: the tag must match `__version__`, CITATION.cff's `version` and a `## [X.Y.Z] - date` CHANGELOG section; it publishes to PyPI (trusted publisher, environment `pypi`), creates the GitHub Release, and deploys the docs to gh-pages.

## Architecture

**One subpackage per domain**, each at `cybersecuritykit/<name>/` with its own `tests/`. Every subpackage uses the same layout: `core/base.py` (shared types and frozen result dataclasses, never bare tuples), `systems/` (one module per breakthrough family), `utils/` (helpers that are not a model themselves), `visualizers/plots.py` (matplotlib; functions take `ax=None` and return the `Axes`), and `tests/`. `import cybersecuritykit` must stay stdlib-only: nothing outside `visualizers/` imports matplotlib or numpy, and subpackage `__init__.py` files do not import `visualizers`. Each subpackage's `__init__.py` re-exports the `__all__` of `core`, `core.base` and `systems`; `cybersecuritykit/tests/test_package.py` checks that and the stdlib-only import.

Shared across all subpackages:
- `cybersecuritykit/_validation.py`: `integer()` (rejects bools and non-ints, inclusive lower bound), `seed()`, `probability()`, `positive()`, and `byte_string()` (exactly `bytes`, optionally non-empty).
- `cybersecuritykit/constants.py`: `DEFAULT_SEED`, `ALPHABET`, `EXAMPLE_DOMAIN`, `DOCUMENTATION_NETWORKS`. Shared constants live here, never inlined.

**Already registered for every domain** (do not re-add): the subpackage import and `__all__` entry in `cybersecuritykit/__init__.py`, `testpaths` in `pyproject.toml`, the `SUBPACKAGES` table in `docs/source/conf.py` (which generates the grids), the api/history/examples/exercises index toctrees, and the stub pages `docs/source/api/<name>.rst`, `docs/source/history/<name>_breakthroughs.rst`, `docs/source/exercises/<name>.rst`, `examples/<name>/README.rst`.

**Parallel sessions:** domains are built one per session (see `PLAN.md`). A domain session edits only its own directories and pages. Before editing any shared file (`conf.py` aliases, `constants.py`, `_validation.py`, `CHANGELOG.md`), re-read it immediately before the edit and keep the change minimal. Cross-domain imports go one way only (wave 2 may import wave 1); record each one here:

- (none yet)

Determinism is a design requirement: randomness comes from explicit seeds (`random.Random(seed)`), never global state or `secrets`.

## Conventions

- Coverage is 100% (enforced in `pyproject.toml`); add real boundary and failure tests, never exclusions. Tests use `hypothesis` for property tests and check independent vectors (published test vectors where they exist), algebraic identities, or failure behavior.
- Math single-letter names (`n`, `k`, `x`, `p`, `q`) are intentional; see the ruff ignores in `pyproject.toml`.
- Public functions need type annotations and NumPy-style docstrings. Sphinx uses napoleon with `nitpicky`, so new types referenced in docstrings may need `napoleon_type_aliases` or `nitpick_ignore` entries in `docs/source/conf.py`. New algorithms cite their source.
- History is a first-class deliverable: one page per subpackage, `docs/source/history/<subpackage>_breakthroughs.rst`, with at least 15 breakthroughs. Entries follow mathematicskit's form: a `YEAR -- Title` heading, prose on the original problem and key mechanism with a `.. math::` block, an *Implementation:* line that links the API and states how the teaching version differs from the real system, a *References:* line citing a primary source, and `.. minigallery::` linking its own gallery example(s). Each page opens with an epigraph. No labelled sub-blocks, admonitions or doctests inside entries. No example is shared between two breakthroughs, and each example's title names its breakthrough.
- Tutorials (`docs/source/tutorials/`) and exercise pages (`docs/source/exercises/<subpackage>.rst`) use `.. doctest::`; exercise solutions sit in `.. dropdown::` boxes.
- Examples live in `examples/<subpackage>/<topic>/plot_NN_<name>.py`, each topic folder with a `README.rst`; sphinx-gallery renders them under `docs/source/api/gallery/` (generated; never edit). Examples use an `r"""` docstring with the title and plain paragraphs, one `# %%` cell holding every import, then `# %%` sections with fixed seeds, small bounded searches and assertions, `plt.show()` closing the last figure cell, and a final `# Exercise` cell.
- Releases cite the release's own Zenodo version DOI, never the concept DOI.

## Agent skills

### Issue tracker

Issues live as local markdown under `.scratch/<feature>/` (no remote yet). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five roles (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root, created lazily. See `docs/agents/domain.md`.
