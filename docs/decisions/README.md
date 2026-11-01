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
- **Context.** The forces at play. What problem, what constraints, what the reader needs to know.
- **Decision.** What we do, in the active voice.
- **Consequences.** What gets easier, what gets harder, what must follow. Include costs.
- **Roads not taken.** One line for each other option that was weighed: what it would have given, what it costs, and why it lost. This part is required.
- **Follow-ups.** Tasks that verify or implement the decision and cannot change it, each with the issue that carries it, or `None.`. A task whose result could change the decision is not a follow-up: it is an open part, and the record stays `Proposed`.

## Rules

- **One decision per record.** Keep it short. A page of reasoning is better than ten. Measurements are cited, not reproduced: they live in dated pages under `docs/research/`. Formats and command tables live under `docs/reference/`.
- **Accepted means decided.** A record is `Accepted` when every part is decided. Follow-ups do not keep it `Proposed`; an open part does.
- **Design phase: rewritten in place.** Until the first release of ritueel, the maintainer may have a record rewritten, merged with another, renumbered or removed, so that the set stays small and current. The earlier text stays in git history. A renumbered or removed record's address on the site redirects to its successor (`site/public/_redirects`).
- **After the first release: append-only.** A changed mind gets a new record that supersedes the old one. The old record's status line changes to point at the new one, and its body stays. Typos and links may be fixed in place.
- **Public means generic.** A record names no private deployment, account, hostname, ticket or person other than the maintainer. Use neutral examples.
- **Draft ADRs are internal.** Reasoning starts in internal discussion. Only the final record is written here, once the maintainer has decided.
- **Standards.** A deliberate deviation from a standard ritueel follows needs a record.
- **Scope.** New product scope, and changes to the design model, need a record.

## Index

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates.md) | Scope: roots and transitions; systems like sluis hold intermediates | Accepted |
| [0002](0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica.md) | Key custody: every key is born in its store; two root cards, or one KMS root and a replica | Accepted |
| [0003](0003-key-stores-and-the-card-layer.md) | Key stores and the card layer | Accepted |
| [0004](0004-ceremonies-plan-confirm-reserve-sign-verify-record.md) | Ceremonies: plan, confirm, reserve, sign, verify, record | Accepted |
| [0005](0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence.md) | Trust products: the root list, the CA bundle, the SSH CA key list, CRLs and the trust sequence | Accepted |
| [0006](0006-release-keys-and-the-keyring-package.md) | Release keys and the keyring package | Accepted |
