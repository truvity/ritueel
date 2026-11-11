# Architecture decisions

One record per decision that shapes ritueel from the outside: what a user must do, what a key store must provide, what the hand-off with another system carries.
A record says why the thing is shaped the way it is, what else was weighed, and what follows.
Explanation pages describe the target state and carry a status badge. When a page and a record disagree, the record is the reasoning and the page is fixed.

How a decision is made is in [GOVERNANCE.md](../../GOVERNANCE.md).

## Numbering

Numbering starts at `0001`. `0000` is the [template](0000-template.md).

## Files

A record is `NNNN-short-title-in-kebab-case.md`. Numbers are taken in the order pull requests open. After the first release a number is never reused, even for a rejected record.

## Format

Every record has these parts, in this order:

- **Status.** One of `Proposed`, `Accepted`, `Rejected`, `Superseded by NNNN`, or `Accepted; amended by NNNN`.
- **Date.** The day the status or the text last changed.
- **Decision.** Numbered plain sentences, one rule each, in the active voice. No sub-headings, tables or code blocks: an exact format is only named and linked to its reference page.
- **Why.** The reasons, in a short paragraph or a few bullets.
- **What it costs.** What gets harder, what must follow. Include costs.
- **Roads not taken.** One line for each other option that was weighed: what it would have given, what it costs, and why it lost. This part is required.
- **Not yet proven or only proposed.** `None.`, or bullets that start `**Not yet proven.**` (decided, waits for a test on a card or an account) or `**Proposed.**` (not decided), each ending in the issue that carries it. A point whose answer could change a numbered sentence is moved here.
- **Replaces.** The records of the first eighteen that flow into this one, or `Nothing; new in the rewrite.`

## Rules

- **One decision per record.** Keep it short: the aim is 900 words for Decision, Why and What it costs together, and the checker allows 1,100. Measurements are cited, not reproduced: they live in dated pages under `docs/research/`. Formats and command tables live under `docs/reference/`.
- **Accepted means decided.** The numbered sentences of an `Accepted` record are decided. A point that is decided but waits for a test, or that is only proposed, sits in its own section with its issue and does not keep the record `Proposed`; an `Open` heading does.
- **Design phase: rewritten in place.** Until the first release of ritueel, the maintainer may have a record rewritten, merged with another, renumbered or removed, so that the set stays small and current. The earlier text stays in git history.
- **After the first release: append-only.** A changed mind gets a new record that supersedes the old one. The old record's status line changes to point at the new one, and its body stays. Typos and links may be fixed in place.
- **Public means generic.** A record names no private deployment, account, hostname, ticket or person other than the maintainer. Use neutral examples.
- **Draft ADRs are internal.** Reasoning starts in internal discussion. Only the final record is written here, once the maintainer has decided.
- **Standards.** A deliberate deviation from a standard ritueel follows needs a record.
- **Scope.** New product scope, and changes to the design model, need a record.

## Index

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-what-ritueel-is.md) | ritueel keeps roots and teaches how; systems that issue every day keep intermediates | Accepted |
| [0002](0002-where-a-key-lives.md) | A key is born in its store and never leaves it; a key file opens with a passkey on each root card | Accepted |
| [0003](0003-root-cards.md) | Roots live on two independent root cards laid out as six rows of four slots | Accepted |
| [0004](0004-the-cloud-root.md) | A cloud root is one dedicated account with three replicated keys, created or adopted | Accepted |
| [0005](0005-a-ceremony-and-where-it-runs.md) | A ceremony has six steps; a key that cannot be copied may be used on the workstation | Accepted |
| [0006](0006-bundle-history-and-trust-files.md) | A bundle is one trust domain; its history is write-once and its trust files are numbered sets | Accepted |
| [0007](0007-changing-and-losing-a-root.md) | A root changes by add, overlap, retire and revoke; revocation material and a drill prove the way back | Accepted |
| [0008](0008-a-persons-own-key.md) | A person uses OpenPGP as their own key, an adopted primary first and card-born primaries later | Accepted |
| [0009](0009-release-keys-and-the-keyring.md) | Release keys are the root primaries; the keyring is a file that ritueel makes and a pipeline packages | Accepted |
| [0010](0010-the-engine-the-process-and-the-page.md) | One engine with three faces, one process on one fixed port, and a page that cannot confirm anything | Accepted |
| [0011](0011-publishing-and-what-to-do-after-a-ceremony.md) | ritueel changes only your bundle; it sends out one public key and prints what to do after a ceremony | Accepted |

## The first eighteen records

The first set of records, 0001 to 0018, was rewritten on 2026-11-11 from a checked list of decisions into the ten records above. Record 0011 was added later, on 2026-11-11, for a new subject; it replaces none of the old ones, so the old 0011 in the table below (the wizards, now in 0010) is not the new 0011: read an old number in the table, a new one in the index. The numbers 0001 to 0010 are now used again, which the design phase allows; a number is never reused after the first release. The old files are in git at commit [d0ae12d](https://github.com/truvity/ritueel/tree/d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee/docs/decisions), and their old site addresses redirect to them. Old titles in the table are quoted as they were written; "trust products" and the staff-key design are no longer part of ritueel. Each new record's "Replaces" section says which parts flow into it; where an old number appears in an issue, a pull request or a note, read it in this table.

| Old | Old title | Flows into |
|-----|-----------|------------|
| 0001 | Scope: roots and transitions; systems like sluis hold intermediates | [0001], [0002], [0005], [0006], [0007], [0008], [0010] |
| 0002 | Key custody: every key is born in its store; two root cards, or one KMS root and a replica | [0001], [0002], [0003], [0004], [0005], [0007] |
| 0003 | Key stores and the card layer | [0002], [0003], [0004], [0005], [0006], [0008], [0010] |
| 0004 | Ceremonies: plan, confirm, reserve, sign, verify, record | [0002], [0003], [0004], [0005], [0006], [0007], [0008], [0010] |
| 0005 | Trust products: the root list, the CA bundle, the SSH CA key list, CRLs and the trust sequence | [0004], [0006], [0007], [0009] |
| 0006 | Release keys and the keyring package | [0001], [0006], [0009] |
| 0007 | ritueel teaches, and its tools simplify the ceremonies | [0001], [0002], [0005], [0006], [0007], [0010] |
| 0008 | The operator prepares the holder; ritueel creates, attests and verifies the root | [0001], [0002], [0003], [0004], [0005], [0010] |
| 0009 | Root transitions: vouch, overlap, retire and revoke | [0006], [0007] |
| 0010 | Readiness is made at birth and proved by a drill | [0006], [0007], [0009] |
| 0011 | The wizards: one engine, three faces, and a web page that cannot confirm anything | [0010] |
| 0012 | Personal OpenPGP: the primary offline in a file, the daily subkey on a card | [0003], [0008] |
| 0013 | The KMS ceremony role is the only signer, and ritueel asks nothing of its sign-in | [0004] |
| 0014 | Staff OpenPGP: primaries sealed in sluis, subkeys born on cards; ritueel makes the card ready and runs the delegation | [0001], [0008] |
| 0015 | Key files open with a passkey on each root card, and card secrets are sealed in the bundle | [0002], [0003], [0006], [0007] |
| 0016 | Several bundles share one pair of root cards, and the bundle keeps a card inventory | [0003], [0005], [0006], [0007] |
| 0017 | A person's OpenPGP key in two stages: an adopted primary first, then card-born primaries | [0002], [0008] |
| 0018 | A cloud root may be an existing key that ritueel adopts | [0004], [0006] |

[0001]: 0001-what-ritueel-is.md
[0002]: 0002-where-a-key-lives.md
[0003]: 0003-root-cards.md
[0004]: 0004-the-cloud-root.md
[0005]: 0005-a-ceremony-and-where-it-runs.md
[0006]: 0006-bundle-history-and-trust-files.md
[0007]: 0007-changing-and-losing-a-root.md
[0008]: 0008-a-persons-own-key.md
[0009]: 0009-release-keys-and-the-keyring.md
[0010]: 0010-the-engine-the-process-and-the-page.md
[0011]: 0011-publishing-and-what-to-do-after-a-ceremony.md
