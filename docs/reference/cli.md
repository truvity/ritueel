---
title: Commands
description: The ritueel commands, their arguments and files, the shared flags, the exit codes and the JSON output, as decided for the first version. Not built yet.
sidebar:
  order: 2
---

*Not built yet. This is the command set decided in [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/); the code is [issue #10](https://github.com/truvity/ritueel/issues/10) and [issue #30](https://github.com/truvity/ritueel/issues/30). The commands of M1, with their arguments and files, are in [The first version's commands](/reference/cli/#the-first-versions-commands).*

## Commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init` | Creates the directory, the roots (`--roots N`, default 2, both cards present) with their attestations and revocation signatures, and the first trust products. | Yes |
| `ritueel yearly` | The yearly ceremony: renews every registered intermediate by re-signing, with the root of the year, extends that root, and publishes the next trust sequence. | Yes |
| `ritueel intermediate add NAME --request STEM` | Registers an intermediate and certifies its first request. | Yes |
| `ritueel intermediate replace NAME` | The event path: certifies a new key for a registered intermediate. `--revoke` also revokes the old one, with a reason. | Yes |
| `ritueel intermediate revoke NAME` | Revokes the certificate and subkey binding of an intermediate, with a reason, without a replacement. | Yes |
| `ritueel root add` | Creates a new root in a store and has an existing root vouch for it. This starts an overlap. | Yes |
| `ritueel root retire ROOT` | Ends an overlap: removes the root from the next trust products. | Yes |
| `ritueel root revoke ROOT` | Revokes a lost, stolen or compromised root, and builds the trust products without it. | Yes |
| `ritueel status` | Lists roots, intermediates, the root list and unresolved attempts, with what expires when. | No |
| `ritueel handoff check STEM` | Runs every check of the [hand-off contract](/reference/hand-off-contract/) on the request `STEM`, and signs nothing. | No |
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
| `--key-dir DIR` | Software roots: the directory of the [key files](/reference/directory/#the-software-roots-key-files). Refused when it is inside `--dir`. |
| `--test-root` | Software roots: no passphrase, marked `TEST ONLY` everywhere. Products refuse to mix test and real roots. |
| `--output json` | Every command, ceremony or not: print one JSON object on standard output ([below](/reference/cli/#machine-readable-output)). The default is `--output text`. |

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
| 10, 11, 12 | `status` only: notice, alert and critical. Intermediates warn at 60, 30 and 14 days, the root list at 60, 30 and 14 days, roots at 6 months, 3 months and 30 days. An unresolved attempt is critical, because it may mean a signature that was made and never recorded. The highest finding wins. |

## The first version's commands

M1 builds these, with the software store only ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9), [issue #10](https://github.com/truvity/ritueel/issues/10)). The paths are those of [the directory](/reference/directory/#the-layout). A ceremony writes its [plan, attempt, record and transcript](/reference/ceremony-record/), and the trust products of its new trust sequence under `products/<sequence>/`.

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `ritueel version` | Nothing. | The version and the commit it was built from. | 0 |
| `ritueel init --store software [--roots N] [--test-root] --key-dir DIR` | `ritueel.yaml`, which the operator writes first. | `roots/<label>/` for each root (`A`, then `B`), the key files in `DIR`, and the first trust products (`products/1/`). | 0, 1, 2, 3, 5 |
| `ritueel intermediate add NAME --request STEM` | The entry `NAME` of `ritueel.yaml`, and the request `requests/STEM.*`. | The answer `answers/STEM.*`, and the trust products. | 0, 1, 2, 3, 5 |
| `ritueel handoff check STEM [--intermediate NAME]` | The request `requests/STEM.*`, `ritueel.yaml`. | Nothing. | 0, 1, 2, 3 |
| `ritueel status` | The directory. | Nothing. | 0, 1, 2, 10, 11, 12 |
| `ritueel records list` | `records/`. | Nothing. | 0, 1, 2 |
| `ritueel records verify` | The directory. | Nothing. | 0, 1, 2, 3 |
| `ritueel records close CEREMONY --reason TEXT` | `attempts/CEREMONY.json`. | A closing record and its transcript. | 0, 1, 2, 3, 5 |
| `ritueel bundle build [--out FILE]` | The roots and the newest root list. | The CA bundle, to `FILE` or standard output. | 0, 1, 2, 3 |
| `ritueel root-list verify FILE (--held FILE \| --pin SHA256...) [--bundle FILE]` | A root list, the list the host holds or its initial pins, and a CA bundle. | Nothing. | 0, 1, 2, 3 |

- **`init`** makes `--roots N` roots, 2 by default, 1 allowed for a software root. It refuses a directory that already has a root, and a key directory that already has key files. The passphrase is asked once for each root, or read from `--passphrase-fd`; `--test-root` asks none. It prints the accepted limit, and the record says so.
- **`intermediate add`** refuses a `NAME` that `ritueel.yaml` does not declare, or that an earlier record registered, and a request whose type is not the entry's `type` or whose stem already has an answer. It runs the contract's checks 1 to 9, then the six steps; the person's confirmation is check 10, and a person may [decline](/reference/ceremony-record/#declining) the request instead (`--decline REASON` with `--plan FILE` from a script), which writes the answer with the code `declined` and a record (exit code 3). A plan that no longer matches the directory is refused with `plan-stale` (exit code 3). A request refused by a check gets `answers/STEM.result.json` with `outcome` `refused` and its code, and nothing else is written: no plan, no attempt, no record (exit code 3).
- **`handoff check`** runs checks 1 to 9 of the [hand-off contract](/reference/hand-off-contract/#what-the-certifier-checks) and signs nothing. Without `--intermediate`, the rules that belong to one intermediate (name constraints, KMS read roles) are reported as not run, never as passed. It exits 0 when every check that ran passed, and 3 with the code when one refused.
- **`status`** exits with the highest finding ([Exit codes](/reference/cli/#exit-codes)). An unresolved attempt is critical (12).
- **`records verify`** checks the [hash chain](/reference/ceremony-record/#the-hash-chain); a break is exit code 3.
- **`records close`** shows the attempt and asks the person to type the first eight characters of its plan digest, or takes `--confirm DIGEST`. Its record says that signatures may exist from that plan.
- **`bundle build`** gives the bytes of `products/<sequence>/ca-bundle.pem` for the newest sequence, and refuses to mix test and real roots.
- **`root-list verify`** is the host's side: it runs [the host's checks](/reference/root-list/#how-a-host-reads-it) on `FILE` (a `root-list.json`, with its `.jws` beside it) against `--held FILE`, the list the host holds, or `--pin`, its initial pins. `--bundle FILE` also checks a CA bundle against the list. It exits 0 when the list is accepted and 3 with the code when it is refused; a held list that has expired is a warning in the output. It needs no directory.

`yearly`, `intermediate replace` and `revoke`, the `root` commands, `keyring build` and `wizard` come with M2 to M4.

:::note[Proposed]
`init` reads a `ritueel.yaml` the operator wrote rather than taking the name, the release address and the policy as flags, so that ritueel never rewrites that file. `--key-dir`, `handoff check --intermediate`, `records close --reason`, `bundle build --out`, `--decline` and the arguments of `root-list verify` are the arguments this page adds to the commands of ADR 0004.
:::

### A script's ceremony

A test harness drives a ceremony in two runs, so that it confirms only a plan it has read. With a test root there is no passphrase; a software root with one adds `--passphrase-fd N` to the second run.

```sh
ritueel --dir ca intermediate add example-ca --request req-1 --key-dir keys \
  --plan-only --output json > plan.json
ritueel --dir ca intermediate add example-ca --request req-1 --key-dir keys \
  --plan "$(jq -r .plan.path plan.json)" --confirm "$(jq -r .plan.sha256 plan.json)" --output json
```

## Machine-readable output

With `--output json`, a command prints **one JSON object on standard output** when it ends, followed by a newline, whatever its outcome. Everything a person reads (the plan in words, prompts, progress, warnings) goes to standard error, and the transcript holds it. Only arguments so broken that `--output json` cannot be read print no object; the exit code is then 2.

Every object has these members:

| Member | Meaning |
|---|---|
| `output` | The version of this format, `1`. |
| `command` | The command, as in the plan: `intermediate add`. |
| `exit_code` | The exit code the command returns. |
| `outcome` | `done`, `refused`, `not-confirmed`, `usage` or `failed`, matching the exit code. |
| `reasons` | When refused: the codes, as in the [hand-off contract](/reference/hand-off-contract/#the-answer) or the [root list](/reference/root-list/#how-a-host-reads-it) where they apply, and `plan-stale` for a plan that no longer matches the directory. |
| `error` | When failed or a usage error: a message for a person. Its wording is not part of the format. |

And these where they apply:

| Member | Commands | Meaning |
|---|---|---|
| `version`, `commit` | `version` | The release version and the commit. |
| `ceremony` | ceremonies | The ceremony's name. |
| `plan` | ceremonies | `{ "path", "sha256", "prefix" }`: the plan file, its digest, and the eight characters a person types. With `--plan-only`, this is the result. |
| `record` | ceremonies, `records close` | `{ "path", "sha256" }`. |
| `artifacts` | ceremonies, `bundle build` | A list of `{ "path", "sha256" }`, as in the record. |
| `trust_sequence` | ceremonies | The trust sequence of the trust products written. |
| `roots` | `init`, `status` | A list of `{ "label", "store", "test", "x509_spki_sha256", "openpgp_fingerprint", "not_after" }`. |
| `answer` | `intermediate add` | `{ "stem", "outcome", "reasons", "artifacts" }`, as in `result.json`. |
| `checks` | `handoff check` | A list of `{ "n", "result" }` for checks 1 to 9, where `result` is `passed`, `failed` or `not-run`. |
| `findings` | `status` | A list of `{ "level", "kind", "name", "expires_at", "days_left" }`: `level` is `notice`, `alert` or `critical`, `kind` is `intermediate`, `root`, `root-list` or `attempt`. |
| `records` | `records list` | A list of `{ "ceremony", "command", "outcome", "sha256" }`, in chain order. |

The members are named with lower-case words and underscores, times and digests are written as in the [hand-off contract](/reference/hand-off-contract/#messages-and-files), and the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.
