# ritueel

ritueel teaches people to manage the root of a PKI and the master key of OpenPGP smoothly and safely, and gives them tools that simplify each ritual, from creating a root to signing intermediates and subkeys onto cards, while the person stays in charge.

The site at [ritueel.id](https://ritueel.id) teaches first: the logic of keeping root keys and intermediates, the [custody chain](docs/learn/custody-chain.md), the key stores compared in the open, and the whole life of a root. The tools come after, because the steps are mostly manual ceremonies. ritueel is open source (MIT) and written in Go.

> **Status as of 2026-11-01: design phase, no code yet.** The decision records are accepted and the code starts with milestone M1 of the [roadmap](docs/roadmap.md).

## What ritueel does

| Area | What it covers |
|---|---|
| Roots | Create, vouch for, overlap, supersede, revoke and expire X.509 CA roots and OpenPGP primary keys, across key stores. |
| Intermediate ceremonies | Verify where an intermediate key lives, sign its certificate request, and bind its OpenPGP subkey. |
| Trust products | CA bundles, signed root lists, SSH CA key lists, and keyring `.deb` and `.rpm` packages that your own pipeline publishes. |
| Records | A hash-chained record of every ceremony. |
| Personal OpenPGP | A primary key, a daily subkey born on a card, and keyring upkeep. |
| Teaching | The Learn section, one guide per ritual and transition, and drills on test keys. |
| Wizard | A guided front end, in the terminal and on localhost only. Nothing happens without your confirmation; the PIN and the touch stay on the card. |

ritueel does not sign online, issue leaf certificates or store secrets. A system that holds intermediates, such as [sluis](https://sluis.id), does that; the two exchange standard formats through a versioned contract and depend on neither each other nor shared code.

## Read

- [Learn](docs/learn/index.md), starting with [what a root is](docs/learn/what-is-a-root.md), then the [principles](docs/principles.md).
- [Decision records](docs/decisions/README.md): seven records, each with the roads not taken.
- [Hand-off contract](docs/reference/hand-off-contract.md): what a system that holds intermediates sends and gets back, with [test vectors](testdata/hand-off/).
- [Roadmap](docs/roadmap.md).

## Take part

Read [CONTRIBUTING.md](CONTRIBUTING.md). Who decides what is in [GOVERNANCE.md](GOVERNANCE.md). People and AI agents follow the same rules, written in [docs/contributing](docs/contributing.md) and short-formed in [AGENTS.md](AGENTS.md). Security reports go through [SECURITY.md](SECURITY.md), never through an issue.

## Licence

[MIT](LICENSE).
