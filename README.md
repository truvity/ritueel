# ritueel

ritueel helps one person or a small team keep a private root and an OpenPGP primary key for years without losing it, leaking it, misusing it or letting it expire. It teaches the model first, and its tools run each ceremony with the person deciding.

The site at [ritueel.id](https://ritueel.id) teaches first: the logic of keeping root keys and intermediates, the [custody chain](docs/learn/custody-chain.md), the key stores compared in the open, and the whole life of a root. The tools come after, because the steps are mostly manual ceremonies. ritueel is open source (MIT). The program is written in Go; its local page is written in TypeScript (`ui/`).

The guides, tool pages, specifications and research are written under `docs/` and read here on GitHub: the site publishes only the Learn path, a demo, the glossary, where the project stands and the design in brief.

> **Status as of 2026-11-11: design phase. The program has no code yet; the local page exists as code and as a demo (`ui/`, `proto/`).** The ten decision records are accepted, M0 is done and M1 is the proofs on a rehearsal card, as the [roadmap](docs/roadmap.md) says.

## What ritueel does

| Area | What it covers |
|---|---|
| Roots | Create, vouch for, overlap, supersede, revoke and expire X.509 CA roots and OpenPGP primary keys, across key stores. |
| Intermediate ceremonies | Verify where an intermediate key lives, sign its certificate request, and bind its OpenPGP subkey. |
| Trust files | CA bundles, signed root lists, SSH CA key lists, and keyring `.deb` and `.rpm` packages that your own pipeline publishes. |
| Records | A hash-chained record of every ceremony. |
| Personal OpenPGP | A primary key (an existing one may be adopted), daily subkeys on a card, and keyring upkeep. |
| Teaching | The Learn section, and one guide per ritual and transition with drills on test keys (the guides are read here on GitHub). |
| Guided mode and local page | A guided mode that asks line by line, and a read-only page on localhost. Nothing happens without your confirmation; the PIN and the touch stay on the card. |

ritueel does not sign online, issue leaf certificates or store secrets. A system that holds intermediates, such as [sluis](https://sluis.id), does that; the two exchange standard formats through a versioned contract and depend on neither each other nor shared code.

## Read

- [Learn](docs/learn/index.md), starting with [what a root is](docs/learn/what-is-a-root.md), then the [principles](docs/principles.md).
- [Decision records](docs/decisions/README.md): ten records, each with the roads not taken; the first eighteen are in the history of the repository.
- [Hand-off contract](docs/reference/hand-off-contract.md): what a system that holds intermediates sends and gets back, with [test vectors](testdata/hand-off/).
- [Roadmap](docs/roadmap.md).

## Take part

Read [CONTRIBUTING.md](CONTRIBUTING.md). Who decides what is in [GOVERNANCE.md](GOVERNANCE.md). People and AI agents follow the same rules, written in [docs/contributing](docs/contributing.md) and short-formed in [AGENTS.md](AGENTS.md). Security reports go through [SECURITY.md](SECURITY.md), never through an issue.

## Licence

[MIT](LICENSE).
