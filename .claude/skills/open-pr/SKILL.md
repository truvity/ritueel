---
name: open-pr
description: Use when starting a change on a new branch or worktree, committing, pushing, opening a pull request against main, answering review feedback on one, or merging one.
---

Read `docs/contributing/workflow.md` and follow it, with `docs/contributing/tools.md` for the checks and `docs/contributing/agents.md` for attribution.

Checklist:

- [ ] `git remote -v` checked; the worktree is off `origin/main` with `--no-track`, on a `type/short-name` branch.
- [ ] One topic in the pull request, with its tests and docs. No stacked pull requests: dependent work is one linear pull request, one commit per part.
- [ ] `devbox run -- just check` passes locally; say what you ran.
- [ ] Commits are conventional and keep the tool's attribution lines.
- [ ] On the current `main`. If `main` moved or the branch has a merge commit, rebuild it on a new branch and a new pull request (cherry-pick, or `git diff <base> <head> | git apply -3`) and close the old one with a pointer. Never force-push.
- [ ] Pushed with an explicit refspec, never to `main`.
- [ ] The pull request follows `.github/pull_request_template.md`.
- [ ] Before each further push, every reviewer and review-bot comment is read and answered.
- [ ] CI is green. Do not merge and never use `--admin`: hand the maintainer the URL, the head sha and the CI result, for `gh pr merge <n> --rebase --match-head-commit <sha>`.
- [ ] After the maintainer merges, check the `Site` workflow on `main` and, for a site change, the `curl` checks of the `site-change` skill; report the result. "Merged" is not "done".
