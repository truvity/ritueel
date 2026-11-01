# ritueel

ritueel keeps the roots of trust: the X.509 CA roots and OpenPGP primary keys that every other key depends on. It creates them, vouches for the next one, overlaps the old and the new, supersedes, revokes, and runs the ceremonies where a person is present. It is open source (MIT), written in Go, and a teaching product: the site at [ritueel.id](https://ritueel.id) explains the model before the tools do it for you.

> **Status as of 2026-11-01: design phase, no code yet.** The decision records are accepted and the code starts with milestone M1 of the [roadmap](docs/roadmap.md).

## What ritueel does

| Area | What it covers |
|---|---|
| Roots | Create, vouch for, overlap, supersede, revoke and expire X.509 CA roots and OpenPGP primary keys, across key stores. |
| Intermediate ceremonies | Verify where an intermediate key lives, sign its certificate request, and bind its OpenPGP subkey. |
| Trust products | CA bundles, signed root lists, SSH CA key lists, and keyring `.deb` and `.rpm` packages that your own pipeline publishes. |
| Records | A hash-chained record of every ceremony. |
| Personal OpenPGP | A primary key, a daily subkey born on a card, and keyring upkeep. |
| Teaching | Concepts, one guide per transition, and drills on test keys. |

ritueel does not sign online, issue leaf certificates or store secrets. A system that holds intermediates, such as [sluis](https://sluis.id), does that; the two exchange standard formats through a versioned contract and depend on neither each other nor shared code.

## Read

- [Concepts](docs/concepts/index.md), starting with the [design principles](docs/concepts/principles.md).
- [Decision records](docs/decisions/README.md): six records, each with the roads not taken.
- [Hand-off contract](docs/reference/hand-off-contract.md): what a system that holds intermediates sends and gets back, with [test vectors](testdata/hand-off/).
- [Roadmap](docs/roadmap.md).

## Take part

Read [CONTRIBUTING.md](CONTRIBUTING.md). Who decides what is in [GOVERNANCE.md](GOVERNANCE.md). People and AI agents follow the same rules, written in [docs/contributing](docs/contributing.md) and short-formed in [AGENTS.md](AGENTS.md). Security reports go through [SECURITY.md](SECURITY.md), never through an issue.

## Licence

[MIT](LICENSE).
