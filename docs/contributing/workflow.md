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

- Keep a pull request to one change. Do not stack pull requests on each other: with rebase-only merging, every merge changes the commits under the next pull request, and a stack collapses (four stacked pull requests once became one). Put dependent work in one linear pull request, one commit per part.
- A change comes with its tests and its documentation in the same pull request. Changes to a file format, a stored record or the hand-off contract also keep the compatibility rules in [GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md).
- Open a draft pull request early if you want feedback. Mark it ready when the checks are green.
- Be on the current `main` before you ask for the merge. A green pull request on a stale base can still break `main`. If `main` moved, rebuild the branch (below).
- After someone has reviewed the branch, do not rewrite the commits they read. Add commits instead, and let the rebase merge tidy them.
- Two pull requests that change the same generated file collide when merged back to back. Run the generator again on the second branch after the first lands.

## Rebuild instead of rewriting

Merging is by rebase only, so history is linear and a branch holds no merge commit ("This branch can't be rebased" is the sign of one). Never force-push. When `main` moved under your pull request, or the branch has a merge commit, rebuild it:

1. Fetch, and make a new branch off the current `origin/main`.
2. Bring the work over with `git cherry-pick <commits>`, or with `git diff <base> <head> | git apply -3` and a new commit.
3. Push the new branch and open a new pull request that links the old one.
4. Close the old pull request with a pointer to the new one.

## Merging

Merge is by rebase, and the maintainer merges: a review is required, so the maintainer merges as an administrator. An agent does not merge, and never uses `--admin` or any other way past a required check or review. It ends its work with the pull request URL, the head sha the checks ran on and the CI result. The maintainer then merges with `gh pr merge <n> --rebase --match-head-commit <sha>` (and `--admin` where the required review is theirs to give), so that what was reviewed is what lands. Another push makes the sha stale: report the new one.

### After the merge

"Merged" is not "done". When the maintainer has merged, check the runs that follow on `main`: the `Site` workflow and its `deploy` job (`gh run list --workflow site.yaml --branch main --limit 3`), then, if the change touches the site, the `curl` checks of [Changing the site](/contributing/pages/#changing-the-site), including that every moved page answers 301. Report the result.

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
- Before you push again, read every comment on the pull request, from reviewers and from review bots (cubic, GitHub code scanning), and answer or fix each one in the same push.
- Every thread is read, and fixed or answered with the reason, before the maintainer merges. An open bot thread on a pull request you handed over is a defect in the hand-over.
- Expect questions about tests, edge cases and failure modes. Answer them in the pull request, or fix the code.
- Reply to every comment, even if only to say "done". Resolve a thread only when the reviewer agrees.
- Changes to key handling, signing, revocation, trust artifacts or the hand-off contract get a security note in the pull request: what could go wrong, and which test shows it does not.
- Review comments are about the change, not the person.

## Issues and the board

An agent may open at most a couple of issues itself, and only for a defect or a follow-up it found. Every other write to the board (a bulk create, an edit, a comment, a label, a close) goes into a script that the maintainer runs, written as the `maintainer-script` skill says. The script's contract:

- **Dry run by default,** and `--apply` to write.
- **Idempotent:** create an issue only when no issue has the exact title; add a comment only when the same text is absent; replace a body only while it still equals the reviewed copy.
- **Reads over REST** (`gh api repos/...`), because the GraphQL budget is shared by everyone. Pause briefly after each write, and keep an apply log.
- **Say what failed:** on a failed read, print the real `gh` stderr rather than guessing "rate limit".
- **Pages stay out of shell variables.** A page of issues is hundreds of kilobytes, and in a shell that exports every variable a value over 128 KiB makes each later `gh` or `jq` start fail with "Argument list too long". Write each page to a temporary file and run `jq` on the file.
- **Check before creating:** search open and closed issues by title in this repository, and in the sibling repository for a cross-repository item, so the script never opens a duplicate.
- **Bodies live in files** next to the script. Review the dry-run output, and scan it for private terms, before the maintainer runs it.
