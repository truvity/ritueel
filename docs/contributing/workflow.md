---
title: Branches and pull requests
description: How a change reaches main in ritueel, from the worktree and branch name to commits, the CHANGELOG, review and the merge gate.
sidebar:
  order: 1
---

## One line of history

`main` is the only long-lived branch. A change never goes to `main` directly; it arrives through a pull request.

## One change, one worktree, one branch

1. Check where you are: `git remote -v` must show the ritueel repository you mean to change.
2. Fetch, then make a worktree for the change off `origin/main`, on a new topic branch that does not track `main`:

   ```sh
   git fetch origin
   git worktree add --no-track -b docs/adr-readme ../ritueel-adr-readme origin/main
   ```

3. Name the branch `type/short-name`, with a conventional-commit type: `feat/software-root`, `docs/adr-readme`.
4. Push with an explicit refspec, so the branch can only land where you name it: `git push origin docs/adr-readme:docs/adr-readme`. Never push to `main`.

## One topic per pull request

- Keep a pull request to one change. Do not stack pull requests on each other.
- A change comes with its tests and its documentation in the same pull request. Changes to a file format, a stored record or the hand-off contract also keep the compatibility rules in [GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md).
- Open a draft pull request early if you want feedback. Mark it ready when the checks are green.
- Rebase onto the current `main` before you ask for the merge. A green pull request on a stale base can still break `main`.
- After someone has reviewed the branch, do not rewrite the commits they read. Add commits instead, and let the rebase merge tidy them; rebase only to catch up with `main`.

## Merging

Merge is by rebase. The maintainer merges. An agent working for the maintainer may merge its own pull request when the checks are green and review is done: `gh pr merge <n> --rebase --admin --match-head-commit <sha>`, with the sha of the commit the checks ran on. It never merges another author's pull request. The rule is in the review rules of [GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md).

## Commits

Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Add `!` after the type for a breaking change, for example `feat!:`. An optional scope names the part, for example `docs(decisions):`.

Write the subject in the imperative, in one short line. Say why in the body when it is not obvious. The history feeds the release notes.

## CHANGELOG

`CHANGELOG.md` is written by hand, for the person who uses a release. A pull request that changes what a user notices adds a bullet under `## Unreleased`. The maintainer renames that heading to the version at release time.

Start a breaking bullet with **Breaking:** and say what to do first. Pure refactors, tests and dependency bumps need no bullet. The changelog names no ticket of a private tracker.

## Checks are the gate

Green CI is the merge gate: a pull request with a red or a skipped required check is not merged. Run the same checks locally first, with `devbox run -- just check` ([Tools, checks and verification](/contributing/tools/)). CI checks the workflows, the repository rules, file names, the agent wiring, and content that must not be public. Maintainers run additional checks before merging.

## Review

- Every pull request is reviewed by the maintainer and by the review agent ([GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md)).
- Before you push again, read every comment on the pull request, from reviewers and from review bots, and answer or fix each one in the same push.
- Expect questions about tests, edge cases and failure modes. Answer them in the pull request, or fix the code.
- Reply to every comment, even if only to say "done". Resolve a thread only when the reviewer agrees.
- Changes to key handling, signing, revocation, trust artifacts or the hand-off contract get a security note in the pull request: what could go wrong, and which test shows it does not.
- Review comments are about the change, not the person.
