# Architecture decisions

One record per decision that shapes ritueel from the outside: what a user must do, what a key store must provide, what the hand-off with another system carries.
A record says why the thing is shaped the way it is, what else was weighed, and what follows.
Explanation pages describe the target state and say what is built. When a page and a record disagree, the record is the reasoning and the page is fixed.

How a decision is made is in [GOVERNANCE.md](../../GOVERNANCE.md).

## Numbering

Numbering starts at `0001`. `0000` is the [template](0000-template.md).

## Files

A record is `NNNN-short-title-in-kebab-case.md`. Numbers are taken in the order pull requests open. After the first release a number is never reused, even for a rejected record. A record has no history section; earlier versions are in the git history.

## Format

Every record has these parts, in this order:

- **Status.** One of `Proposed`, `Accepted`, `Rejected`, `Superseded by NNNN`, or `Accepted; amended by NNNN`.
- **Date.** The day the status or the text last changed.
- **Decision.** Numbered plain sentences, one rule each, in the active voice. No sub-headings, tables or code blocks: an exact format is only named and linked to its reference page.
- **Why.** The reasons, in a short paragraph or a few bullets.
- **What it costs.** What gets harder, what must follow. Include costs.
- **Roads not taken.** One line for each other option that was weighed: what it would have given, what it costs, and why it lost. This part is required.
- **Not yet proven or only proposed.** `None.`, or bullets that start `**Not yet proven.**` (decided, waits for a test on a card or an account) or `**Proposed.**` (not decided), each ending in the issue that carries it. A point whose answer could change a numbered sentence is moved here.

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
| [0002](0002-where-a-key-lives.md) | A key is born in its key store and never leaves it; a key file opens with a passkey on a card named for it | Accepted |
| [0003](0003-root-cards.md) | Root keys live on two independent root cards laid out as six rows of four slots | Accepted |
| [0004](0004-the-cloud-root.md) | Cloud keys are replicated keys in an account the holder chooses, one for each kind of root, created or adopted | Accepted |
| [0005](0005-a-ceremony-and-where-it-runs.md) | A ceremony applies what is wanted and not applied yet, in one act; a key that cannot be copied may be used on the workstation | Accepted |
| [0006](0006-bundle-history-and-trust-files.md) | A bundle is for one organisation or one person; a person writes only wanted files, its history is write-once and its trust files are numbered sets | Accepted |
| [0007](0007-changing-and-losing-a-root.md) | A root changes by add, overlap, retire and revoke; revocation material and a drill prove the way back | Accepted |
| [0008](0008-a-persons-own-key.md) | A person uses OpenPGP as their own key, an adopted primary first and card-born primaries later | Accepted |
| [0009](0009-release-keys-and-the-keyring.md) | Release keys are the root primaries; the keyring is a file that ritueel makes and a pipeline packages | Accepted |
| [0010](0010-the-engine-the-process-and-the-page.md) | One engine with three faces, one process on one fixed port, and a page that cannot confirm anything | Accepted |
| [0011](0011-publishing-and-what-to-do-after-a-ceremony.md) | ritueel changes only your bundle, sends out only a public OpenPGP key, and prints what to do after a ceremony | Accepted |
