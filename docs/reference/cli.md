---
title: Commands
description: The ritueel commands, the flags every ceremony shares, and the exit codes, as decided for the first version. Not built yet.
sidebar:
  order: 2
---

*Not built yet. This is the command set decided in [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/); the code is [issue #10](https://github.com/truvity/ritueel/issues/10) and [issue #30](https://github.com/truvity/ritueel/issues/30).*

## Commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init` | Creates the directory, the roots (`--roots N`, default 2, both cards present) with their attestations and revocation signatures, and the first trust products. | Yes |
| `ritueel yearly` | The yearly ceremony: renews every registered intermediate by re-signing, with the root of the year, extends that root, and publishes the next trust sequence. | Yes |
| `ritueel intermediate add NAME` | Registers an intermediate and certifies its first request. | Yes |
| `ritueel intermediate replace NAME` | The event path: certifies a new key for a registered intermediate. `--revoke` also revokes the old one, with a reason. | Yes |
| `ritueel intermediate revoke NAME` | Revokes the certificate and subkey binding of an intermediate, with a reason, without a replacement. | Yes |
| `ritueel root add` | Creates a new root in a store and has an existing root vouch for it. This starts an overlap. | Yes |
| `ritueel root retire ROOT` | Ends an overlap: removes the root from the next trust products. | Yes |
| `ritueel root revoke ROOT` | Revokes a lost, stolen or compromised root, and builds the trust products without it. | Yes |
| `ritueel status` | Lists roots, intermediates, the root list and unresolved attempts, with what expires when. | No |
| `ritueel handoff check REQUEST` | Runs every check of the [hand-off contract](/reference/hand-off-contract/) on a request, and signs nothing. | No |
| `ritueel bundle build`, `ritueel keyring build` | Build the CA bundle and the [keyring package](/reference/keyring-package/) from the directory. Same directory, same bytes. | No |
| `ritueel records list`, `records verify`, `records close` | Read the ceremony records, check their hash chain, and close an unresolved attempt. | `close` only |
| `ritueel wizard` | A guided front end to the commands above, in the terminal or in a browser on localhost. | Yes |

The verbs of a transition map onto the commands: *create* and *vouch* are `root add`, *overlap* is a state and not a command, *supersede* is `root retire`, and *revoke* is `root revoke`.

## Flags every ceremony shares

| Flag | Meaning |
|---|---|
| `--dir DIR` | The directory. The default is the current directory when it holds `ritueel.yaml`. |
| `--plan-only` | Write the plan and stop. |
| `--plan FILE` | Run from a plan made earlier, after checking it still matches the directory. |
| `--confirm DIGEST` | Confirm a plan from a script; the digest must be the plan's. |
| `--root ROOT` | Sign with this root instead of the root of the year; the reason is recorded. |
| `--allow-missing NAME` | `yearly` only: go on without a request for this intermediate, and record it. |
| `--passphrase-fd N` | Software roots: read the passphrase from this file descriptor. |
| `--test-root` | Software roots: no passphrase, marked `TEST ONLY` everywhere. Products refuse to mix test and real roots. |

A PIN is never a flag or an environment variable; the holder types it at the terminal.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `status`, nothing due. |
| 1 | Failure. |
| 2 | Usage error. |
| 3 | Refused by a check or by the policy. |
| 4 | Refused by the card or its PIN state. |
| 5 | Not confirmed. |
| 10, 11, 12 | `status` only: notice, alert and critical. Intermediates warn at 60, 30 and 14 days, the root list at 60, 30 and 14 days, roots at 6 months, 3 months and 30 days. The highest finding wins. |
