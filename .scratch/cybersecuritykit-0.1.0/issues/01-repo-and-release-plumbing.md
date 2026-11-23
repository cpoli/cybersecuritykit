# 01: Repository and release plumbing (R1)

**What to build:** The project has a home: a git repository and GitHub repo, so CI runs, docs deploy, and tagged releases publish to PyPI and mint a Zenodo DOI. This is the user's manual step; agents must not `git init` or push.

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

Context: the spec (`../spec.md`); candidate breakthroughs in PLAN.md; conventions in CLAUDE.md.

- [ ] `git init` and the GitHub repository created (owner's choice of name per ROADMAP R1)
- [ ] PyPI trusted publisher configured for the release workflow (environment `pypi`)
- [ ] gh-pages enabled for docs deploy
- [ ] Zenodo GitHub hook enabled
- [ ] CI and docs workflows run green on the first push
- [ ] Optionally re-run `/setup-matt-pocock-skills` to switch the tracker to GitHub
