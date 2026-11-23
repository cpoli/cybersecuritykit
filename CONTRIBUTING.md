# Contributing

Keep the teaching chain intact: historical motivation, mathematical mechanism,
typed public API, checked example, and explicit model assumptions.

cybersecuritykit is organized as one subpackage per domain
(`cybersecuritykit/<name>/`), each with its own `core/` (result dataclasses),
`systems/` (models, attacks and defences, one module per family), `utils/`
(supporting helpers), `visualizers/` (Matplotlib), and `tests/` directory. Code
shared by every subpackage lives at the top level: argument validation in
`_validation.py` and shared constants in `constants.py`.

**Everything is simulated.** Read the scope rule in [SECURITY.md](https://github.com/cpoli/cybersecuritykit/blob/main/SECURITY.md)
before contributing: no network access, no real exploits, no self-replicating
code, no real personal data.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pre-commit install
```

## Required checks

```bash
ruff check .
ruff format --check .
mypy
pytest --cov=cybersecuritykit --cov-branch --cov-report=term-missing
pytest --doctest-modules cybersecuritykit --ignore-glob="*/tests/*"
cd docs && MPLBACKEND=Agg make html && MPLBACKEND=Agg make doctest && cd ..
python -m build
```

Coverage must reach 100% for statements and branches across all package
modules; `pyproject.toml` enforces it. Add meaningful boundary and failure
tests; do not exclude code to meet the target. Tests compare published test
vectors, algebraic identities, or failure behavior rather than merely
asserting that a function returns.

## History is part of the implementation

`docs/source/history/` is a first-class deliverable: one page per subpackage,
`<subpackage>_breakthroughs.rst`, with at least 15 breakthroughs. A new entry
must cite a primary source in a *References:* line, explain the original
problem, give the key equation or mechanism, link to a concrete public API,
and link its own gallery example(s) with `.. minigallery::`. No example is
shared between two breakthroughs, and each example's title names its
breakthrough. Distinguish the original attack or system from the teaching
simulation.

## Examples

Examples live in `examples/<subpackage>/<topic>/plot_NN_<name>.py`, and each
topic folder has a `README.rst` header. Sphinx-Gallery runs every script during
the docs build and offers each one as a downloadable notebook and a JupyterLite
launch. Use fixed seeds, small bounded searches, assertions of the expected
result, and an exercise. Plot with the subpackage's `visualizers` where one
fits.
