# Architecture decisions

One record per decision that shapes ritueel from the outside: what a user must do, what a key store must provide, what the hand-off with another system carries.
A record says why the thing is shaped the way it is, what else was weighed, and what follows.
Explanation pages describe the target state and carry a status badge. When a page and a record disagree, the record is the reasoning and the page is fixed.

How a decision is made is in [GOVERNANCE.md](../../GOVERNANCE.md).

## Numbering

Numbering starts at `0001`. `0000` is the [template](0000-template.md).

## Files

A record is `NNNN-short-title-in-kebab-case.md`. Numbers are taken in the order pull requests open. A number is never reused, even for a rejected record.

## Format

Every record has these parts, in this order:

- **Status.** One of `Proposed`, `Accepted`, `Rejected`, `Superseded by NNNN`, or `Accepted; amended by NNNN`.
- **Date.** The day the status last changed.
- **Context.** The forces at play. What problem, what constraints, what the reader needs to know.
- **Decision.** What we do, in the active voice.
- **Consequences.** What gets easier, what gets harder, what must follow. Include costs.
- **Roads not taken.** Each other option that was weighed, with its pros and cons and the reason it lost. This part is required.

## Rules

- **Never edit history.** A changed mind gets a new record that supersedes the old one. The old record's status line changes to point at the new one. Its body stays.
- **Typos and links** may be fixed in place.
- **One decision per record.** Keep it short. A page of reasoning is better than ten.
- **Public means generic.** A record names no private deployment, account, hostname, ticket or person other than the maintainer. Use neutral examples.
- **Draft ADRs are internal.** Reasoning starts in internal discussion. Only the final record is written here, once the maintainer has decided.
- **Standards.** A deliberate deviation from a standard ritueel follows needs a record.
- **Scope.** New product scope, and changes to the design model, need a record.

## Index

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates.md) | Scope: roots and transitions; systems like sluis hold intermediates | Accepted |
| [0002](0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation.md) | Every key is born in its store; two roots, one holder, yearly alternation | Accepted |
| [0003](0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands.md) | Ceremonies: plan, confirm, reserve, sign, record; and the ritueel commands | Proposed |
