# AGENTS.md

Instructions for AI agents working in this repository. People follow the same rules, written in [docs/contributing/](docs/contributing.md); this file is their short form. If it disagrees with a page there, the page wins.

## Every task

- ritueel teaches first; its tools only simplify the rituals, and the person stays in charge (ADR 0007). Judge every page and feature against that: `docs/contributing/design.md`.
- `main` is the only long-lived branch. Never push to `main`; every change goes through a pull request. Merging is rebase-only: never force-push (rebuild the branch instead) and never stack pull requests.
- One change, one worktree: check `git remote -v`, then `git worktree add --no-track -b <type>/<short-name> <dir> origin/main`. Push with an explicit refspec: `git push origin <branch>:<branch>`.
- Work in a fresh clone or worktree in your scratch area, never in someone else's checkout. Your shell may reset its working directory between calls: use absolute paths (`git -C <abs>`, or `cd <abs> && <cmd>` in one call). Run the narrow recipes (`just check-rules`, `site-lint`, `site-build`) and rely on CI for the rest: `docs/contributing/tools.md`.
- Tools come from devbox. Run the `just` recipe, not the bare tool: `devbox run -- just check` is the gate. No testcontainers; prefer pinned release binaries.
- This repository is public: no real organisation account, hostname, ticket, secret path or person other than the maintainer. Use the example names in `docs/contributing/public-content.md`.
- Never print a secret, a key, a PIN or a token: not in output, logs, commits or pull request text. Use test keys and test devices only.
- The maintainer decides. Settle what the principles settle; ask only real conflicts, with options, pros, cons and a recommendation. You do not merge and never use `--admin`: end with the pull request URL, the head sha and the CI result ("Merging" in `docs/contributing/workflow.md`).
- A fact from outside carries its source and date, and an unverified one stays off the site.
- If a safety check or a permission prompt blocks you, stop and report; do not work around it.

## Before you act, read the page

| Before you | Read and follow |
|---|---|
| answer a design question, or judge a new page or feature | `docs/contributing/design.md` |
| create or edit a file in `docs/decisions/` | `docs/contributing/decisions.md` (skill `new-decision`) |
| run a spike or write up research | `docs/contributing/research.md` |
| write a Learn or Guides page | "Teaching pages" in `docs/contributing/pages.md` (skill `teaching-page`) |
| create or edit any other page under `docs/` | `docs/contributing/pages.md` (skill `docs-page`) |
| change `site/`, the headers, the redirects or how a page looks | "Changing the site" in `docs/contributing/pages.md` (skill `site-change`) |
| create a branch, commit, push, open a pull request or answer a review | `docs/contributing/workflow.md` (skill `open-pr`) |
| write to issues or the board in bulk | "Issues and the board" in `docs/contributing/workflow.md` (skill `maintainer-script`) |
| run a build, a test or a check | `docs/contributing/tools.md` |
| implement a protocol, a format or an algorithm | "Standards first" in `docs/contributing/tools.md` |
| write a test that uses a hardware token or a cloud key | "Hardware tokens and cloud keys" in `docs/contributing/tools.md` |
| write a hostname, an address, an id or a name | `docs/contributing/public-content.md` |
| report a vulnerability you found or suspect | `SECURITY.md`, never an issue or a pull request |
| change `GOVERNANCE.md`, `SECURITY.md` or `LICENSE` | stop: only with the maintainer's request |
| take a role in a team of agents, or report back | `docs/contributing/agents.md` |
