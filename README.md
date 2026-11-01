# ritueel

ritueel keeps the roots of trust: the X.509 CA roots and OpenPGP primary keys that every other key depends on. It creates them, vouches for the next one, overlaps the old and the new, supersedes, revokes, and runs the ceremonies where a person is present. It is open source (MIT), written in Go, and a teaching product: the site at [ritueel.id](https://ritueel.id) explains the model before the tools do it for you.

> **Status: design phase.** There is no release yet. The scope is decided ([ADR 0001](docs/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates.md)), the concepts are written, and the first version is planned in the [roadmap](docs/roadmap.md). The work items are the open [issues](https://github.com/truvity/ritueel/issues).

## The problem

A chain of trust has a few keys that almost never change (the roots) and many that do (the intermediates). The roots are used once a year or less, by a person who has to be present, and they move: from a file to a YubiKey, from a YubiKey to a cloud key service, from an old root to a new one. Each move is easy to get wrong and expensive to repair, because every client that trusts the old root has to learn about the new one.

ritueel makes those moves ordinary: a few commands, a guided wizard, a record of what was done, and a page that explains why.

## What ritueel does

| Area | What it covers |
|---|---|
| Roots | Create, vouch (X.509 cross-certificate or OpenPGP certification), overlap, supersede, revoke and expire X.509 CA roots and OpenPGP primary keys, across key stores. Revocation signatures are made in advance and stored apart from the card. |
| SSH CA key lists | A list of SSH CA public keys that hosts trust, signed by a root and versioned, and the break-glass SSH CA, which ritueel holds offline ([issue #31](https://github.com/truvity/ritueel/issues/31)). |
| Intermediate ceremonies | Verify where a key lives (a YubiKey attestation, an AWS KMS key), sign a certificate request into an intermediate CA certificate, and bind an OpenPGP subkey after checking its back-signature. |
| Trust artifacts | CA bundles, keyrings and signed root lists. The automation and the CLI that build keyring `.deb` and `.rpm` packages; your own pipeline publishes them. |
| Records | A ceremony record for every ceremony. |
| Personal GPG | A primary key, subkeys, cards and keyring upkeep for one person. Company-wide GPG management comes later. |
| Wizards | A CLI wizard, and a web wizard that listens on localhost only. A ceremony is one to three commands; routine work is fully automated. |
| Teaching | Concepts, one guide per transition (software, YubiKey, AWS KMS, in every direction) and drills on test keys. |

The first version supports four key stores behind one ceremony: software, PIV, the OpenPGP card and AWS KMS.

## What ritueel does not do

ritueel does not sign online, issue leaf certificates or store secrets. A system that holds intermediates does that. [sluis](https://sluis.id) is one such system; ritueel does not depend on it, and it does not depend on ritueel. They exchange standard formats: PKCS#10 certificate requests, X.509 certificates, OpenPGP packets and attestation certificates.

## Read

- [Concepts](docs/concepts/index.md): roots, intermediates and transitions; where a key lives.
- [ADR 0001](docs/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates.md): the scope, with the roads not taken.
- [Roadmap](docs/roadmap.md): the milestones of the first version.

## Take part

Read [CONTRIBUTING.md](CONTRIBUTING.md). Who decides what is in [GOVERNANCE.md](GOVERNANCE.md). People and AI agents follow the same rules, written in [docs/contributing](docs/contributing.md) and short-formed in [AGENTS.md](AGENTS.md). Security reports go through [SECURITY.md](SECURITY.md), never through an issue.

## Licence

[MIT](LICENSE).
