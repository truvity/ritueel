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
- The site has a demo of the local page, the browser view of a ritueel bundle, at `/demo/`: the real page over made-up data, with three example bundles (`acme`, `globex`, `personal`), a switch between them and five scenes for `acme`. It has four entries, To do, Inventory, History and Trust set, and writes nothing. Its commands follow the command reference. The program that serves it is not built.
- The Go module `ritueel.id/ritueel` and the first command, `ritueel version`, which prints the version and the commit of the build. With `--output json` it prints one JSON object, as the command reference says. The exit codes are those of the command reference, and a command line that is not valid exits with 2. The other commands are not built, except `verify root-list`, below.
- The command `ritueel verify root-list`: the host's side of the signed root list. It checks a list and its `.jws` against the list the host holds or its initial pins, and with `--ca-bundle` also a CA bundle, and it signs and writes nothing. It exits 0 when the list is accepted, 3 with the reason code when it is refused, and prints the digests of the files it read. Writing and signing a list is not built.
- The program is built as one static Linux executable, without cgo, and the build checks that the file has no interpreter and no shared library.
