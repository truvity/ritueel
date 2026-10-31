# Changelog

This file is written by hand, for the person who uses a release. It is not a list of commits; the history is in git.

## How it is kept

- A pull request that changes what a user notices adds a bullet under `## Unreleased`: a new command, a changed output, a new file format, a fix for a visible fault.
- The maintainer renames `## Unreleased` to the version and the date at release time, and starts a new `## Unreleased`.
- A breaking bullet starts with **Breaking:** and says what to do first.
- Pure refactors, tests, documentation and dependency bumps need no bullet.
- The file names no ticket of a private tracker, no real account and no person other than the maintainer.
- Versions are never reused. A mistake is fixed by the next version ([GOVERNANCE.md](GOVERNANCE.md)).

## Unreleased

- Nothing is released yet. The first docs, the scope decision and the roadmap are in `docs/`.
