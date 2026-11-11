---
title: Commands
description: The ritueel commands, their arguments and files, the shared flags, the exit codes and the JSON output, as decided for the first version. Not built yet.
sidebar:
  order: 2
---

*Not built yet. This is the command set decided in [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/); the code is [issue #10](https://github.com/truvity/ritueel/issues/10) and [issue #30](https://github.com/truvity/ritueel/issues/30). The commands of M2, with their arguments and files, are in [The first version's commands](/reference/cli/#the-first-versions-commands).*

## Commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init` | Creates the directory, the roots (`--roots N`, default 2, both cards present) with their attestations, their revocation signatures (one for each of two reasons) and their removal authorisations, and the first trust products. | Yes |
| `ritueel due [--allow-missing NAME]` | Writes the plans for what is due: each renewal is a separate action in a plan, with the root of the year, and the plan includes the advisory review. It stops when the request of a registered intermediate is missing, unless `--allow-missing NAME` is given and recorded. It signs nothing. There is no `yearly` command ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony)). | No |
| `ritueel run PLAN --confirm DIGEST` | Executes a saved plan after checking that it still matches the directory, then the steps of the ceremony from reserve to record. It replaces a `--plan FILE` flag: there is one way to execute a plan. | Yes |
| `ritueel intermediate add NAME --request STEM` | Registers an intermediate and certifies its first request. | Yes |
| `ritueel intermediate replace NAME` | The event path: certifies a new key for a registered intermediate. `--revoke` also revokes the old one, with a reason. | Yes |
| `ritueel intermediate revoke NAME` | Revokes the certificate and subkey binding of an intermediate, or withdraws its SSH CA key, with a reason (`--reason compromise`, `superseded` or `cessation`), without a replacement. It lists the intermediate's unexpired certificates on the [CRL](/reference/crl/) of each root that issued them, so it needs those roots' cards. | Yes |
| `ritueel root add --store S [--replaces LABEL --overlap-until DATE \| --target N]` | Creates a new root in a store and has an existing root vouch for it; every active root and the new one sign the next root list. With `--replaces`, this starts an overlap that ends on the day given ([root transitions](/reference/transitions/#the-commands)). | Yes |
| `ritueel root retire LABEL` | Ends an overlap: removes the root from the next trust products, after the checks of [root transitions](/reference/transitions/#root-retire). Every active root signs. | Yes |
| `ritueel root revoke LABEL --reason REASON --revocation FILE [--removal FILE]` | Revokes a lost, stolen or compromised root with its stored revocation signature, and builds the trust products without it; the other roots sign, and the root's stored removal authorisation stands in for its signature. | Yes |
| `ritueel revocation make`, `revocation check` | Make one more revocation signature, or the removal authorisation again, while the root's key exists, and check a stored one without printing it ([revocation material](/reference/revocation-material/#making-one-later-and-checking-one)). | `make` only |
| `ritueel drill restore` | The restore check on a clean machine: the records, the roots against their holders, the revocation signatures. It signs nothing ([drills](/reference/drill/#the-restore-check)). | No |
| `ritueel status` | Lists roots, intermediates, the root list and unresolved attempts, with what expires when. | No |
| `ritueel renew` | Later (M7). A cloud root only: renews, as the renewal role and under the declared renewal policy, what the directory already holds, over the same keys, with the next trust sequence. Non-interactive, for the operator's scheduler; it never prompts, and refuses a card or software root with `not-in-policy`, an early run with `too-early`, and anything new with `key-not-in-ledger`. Exit codes 0, 1, 2, 3, 4 ([renewal under a policy](/reference/kms-root/#renewal-under-a-policy)). | No |
| `ritueel handoff check STEM` | Runs every check of the [hand-off contract](/reference/hand-off-contract/) on the request `STEM`, and signs nothing. | No |
| `ritueel bundle build`, `ritueel keyring build` | Build the CA bundle and the [keyring package](/reference/keyring-package/) from the directory. Same directory, same bytes. | No |
| `ritueel root-list verify`, `ssh-ca-keys verify`, `crl verify`, `keyring verify` | The host's and the relying party's side of each trust product: run its checks on a file, signing and writing nothing. | No |
| `ritueel ssh-ca break-glass ROOT` | Makes the break-glass SSH CA of a root that was made before ritueel made one at `init` and `root add`, and lists it. | Yes |
| `ritueel records list`, `records verify`, `records close` | Read the ceremony records, check their hash chain, and close an unresolved attempt. | `close` only |
| `ritueel personal subkey add NAME --card SERIAL` | In a personal directory: the card makes the daily subkey and its back-signature, and the person's primary binds it ([personal OpenPGP](/reference/personal-openpgp/#the-commands)). `init --kind personal` makes the directory. | Yes |
| `ritueel card adopt` | Adopts a card: replaces the management key and the PUK with random ones, seals them in the directory, and registers the card in the inventory. The holder has set the PIN ([root cards](/reference/cards/), [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)). | Yes |
| `ritueel card check` | The read-only check of a card against the built-in layout. It writes `cards.yaml` and `cards/NAME.yaml` and changes nothing on the card ([root cards](/reference/cards/#what-is-checked-on-a-card)). | No |
| `ritueel wizard [--web]` | The guided mode, which asks line by line in the terminal; with `--web`, also a read-only page served on localhost. The page cannot confirm anything; it ends with a preview and the command to run, and can save the plan file ([the wizard](/reference/wizard/)). The page calls the same API as the commands; the process writes the saved plan where `--plan-only` writes it. The loopback listener exists only while `--web` runs. | Yes |
| `ritueel stop` | Proposed. Ends the ritueel process of this directory, if one runs, and exits 0 also when none runs. The process otherwise ends by itself after an idle time ([the process](/reference/wizard/#the-ritueel-process)). | No |

The verbs of a transition map onto the commands: *create* and *vouch* are `root add`, *overlap* is a state and not a command, *supersede* is `root retire`, and *revoke* is `root revoke`.

## Flags every ceremony shares

| Flag | Meaning |
|---|---|
| `--dir DIR` | The directory. The default is the current directory when it holds `ritueel.yaml`. |
| `--plan-only` | Write the plan (`ledger/<ceremony>/plan.json`) and stop. |
| `--confirm DIGEST` | Confirm a plan from a script; the digest must be the plan's. With `run PLAN`, it is how a saved plan is executed. |
| `--root ROOT` | Sign with this root instead of the root of the year; the reason is recorded. |
| `--allow-missing NAME` | `due` only: plan without a request for this intermediate, and record it. |
| `--card [LABEL=]SERIAL` | `piv` roots: the card that holds the root `LABEL`, by serial. `init` takes one for each root (`--card A=00000001 --card B=00000002`); `root add` takes one. Without it, the only card connected is used, and two cards are refused with `card-ambiguous` ([cards](/reference/cards/#what-is-checked-on-a-card)). |
| `--extra-intermediates FILE` | `piv` roots: PEM certificates of the maker's intermediates that the bundle lacks. Helpers only: each must chain to the pinned root ([the bundle](/reference/cards/#the-attestation-bundle)). |
| `--revocation-dir DIR` | Every command that makes revocation signatures for a root that is not an encrypted-file software root: where to write them. Refused inside the directory or its repository ([revocation material](/reference/revocation-material/#where-it-is-written)). `--reasons` chooses the reasons. |
| `--backend file\|onepassword\|keyring` | Software roots: the backend ([the software store](/reference/software-store/)). `--op-vault NAME` names the vault for `onepassword`. `init --kind personal` makes a personal directory. |
| `--passphrase-fd N` | Software roots whose key file is opened by a passphrase (a test root, a script, a holder without cards): read the passphrase from this file descriptor. |
| `--key-dir DIR` | Software roots: the directory of the [key files](/reference/directory/#the-software-roots-key-files). Refused when it is inside `--dir`. |
| `--test-root` | A test root: marked `TEST ONLY` everywhere, and products refuse to mix test and real roots. With a software store it has no passphrase; its key may also live on a rehearsal card. It may run its ceremonies on the workstation or on a rehearsal card; the program checks nothing about where it runs, and there is no flag for that. |
| `--output json` | Every command, ceremony or not: print one JSON object on standard output ([below](/reference/cli/#machine-readable-output)). The default is `--output text`. |

A PIN is never a flag or an environment variable; the holder types it at the terminal. The ritueel process never keeps one between calls.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `status`, nothing due. |
| 1 | Failure. |
| 2 | Usage error. |
| 3 | Refused by a check or by the policy. |
| 4 | Refused by the card or its PIN state, or by the key store backend: a locked store, or a KMS session that is not a session of the ceremony role, or has expired (`kms-session`). |
| 5 | Not confirmed. |
| 10, 11, 12 | `status` only: notice, alert and critical. Intermediates warn at 60, 30 and 14 days, the root list, the SSH CA key list and each CRL at 60, 30 and 14 days, roots at 6 months, 3 months and 30 days. An unresolved attempt is critical, because it may mean a signature that was made and never recorded. A short root set is an alert, an overdue overlap an alert and a running one a notice ([root transitions](/reference/transitions/#the-target)); a restore drill older than 13 months is a notice ([drills](/reference/drill/#when-it-is-due)). The highest finding wins. |

## The first version's commands

M2 builds these, with the software store and the cloud store ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9), [issue #10](https://github.com/truvity/ritueel/issues/10)). The paths are those of [the directory](/reference/directory/#the-layout). A ceremony writes its [plan, attempt, record and transcript](/reference/ceremony-record/), and the trust products of its new trust sequence under `products/<sequence>/`.

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `ritueel version` | Nothing. | The version and the commit it was built from. | 0 |
| `ritueel stop [--dir DIR]` | The socket of the directory. | Nothing; it asks the process to end. | 0, 1, 2 |
| `ritueel init --store software [--roots N] [--test-root] --key-dir DIR` | `ritueel.yaml`, which the operator writes first. | `roots/<label>/` for each root (`A`, then `B`), the key files in `DIR`, and the first trust products (`products/1/`). | 0, 1, 2, 3, 5 |
| `ritueel intermediate add NAME --request STEM` | The entry `NAME` of `ritueel.yaml`, and the request `requests/STEM.*`. | The answer `answers/STEM.*`, and the trust products. | 0, 1, 2, 3, 5 |
| `ritueel handoff check STEM [--intermediate NAME]` | The request `requests/STEM.*`, `ritueel.yaml`. | Nothing. | 0, 1, 2, 3 |
| `ritueel status` | The directory. | Nothing. | 0, 1, 2, 10, 11, 12 |
| `ritueel records list` | `ledger/`. | Nothing. | 0, 1, 2 |
| `ritueel records verify` | The directory. | Nothing. | 0, 1, 2, 3 |
| `ritueel records close CEREMONY --reason TEXT` | `ledger/CEREMONY/attempt.json`. | A closing record and its transcript. | 0, 1, 2, 3, 5 |
| `ritueel bundle build [--out FILE]` | The roots and the newest root list. | The CA bundle, to `FILE` or standard output. | 0, 1, 2, 3 |
| `ritueel root-list verify FILE (--held FILE \| --pin SHA256...) [--bundle FILE]` | A root list, the list the host holds or its initial pins, and a CA bundle. | Nothing. | 0, 1, 2, 3 |

- **`init`** makes `--roots N` roots, 2 by default, 1 allowed for a software root. It refuses a directory that already has a root, and a key directory that already has key files. The key files are opened as [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/) says; a passphrase, where one is used, is asked once for each root, or read from `--passphrase-fd`; `--test-root` asks none. It prints the accepted limit, and the record says so.
- **`intermediate add`** refuses a `NAME` that `ritueel.yaml` does not declare, or that an earlier record registered, and a request whose type is not the entry's `type` or whose stem already has an answer. It runs the contract's checks 1 to 9, then the six steps; the person's confirmation is check 10, and a person may [decline](/reference/ceremony-record/#declining) the request instead (`--decline REASON` with `run PLAN` from a script), which writes the answer with the code `declined` and a record (exit code 3). A plan that no longer matches the directory is refused with `plan-stale` (exit code 3). A request refused by a check gets `answers/STEM.result.json` with `outcome` `refused` and its code, and nothing else is written: no plan, no attempt, no record (exit code 3).
- **`handoff check`** runs checks 1 to 9 of the [hand-off contract](/reference/hand-off-contract/#what-the-certifier-checks) and signs nothing. Without `--intermediate`, the rules that belong to one intermediate (name constraints, KMS read roles) are reported as not run, never as passed. It exits 0 when every check that ran passed, and 3 with the code when one refused.
- **`status`** exits with the highest finding ([Exit codes](/reference/cli/#exit-codes)). An unresolved attempt is critical (12).
- **`records verify`** checks the [hash chain](/reference/ceremony-record/#the-hash-chain); a break is exit code 3.
- **`records close`** shows the attempt and asks the person to type the first eight characters of its plan digest, or takes `--confirm DIGEST`. Its record says that signatures may exist from that plan.
- **`bundle build`** gives the bytes of `products/<sequence>/ca-bundle.pem` for the newest sequence, and refuses to mix test and real roots.
- **`root-list verify`** is the host's side: it runs [the host's checks](/reference/root-list/#how-a-host-reads-it) on `FILE` (a `root-list.json`, with its `.jws` beside it) against `--held FILE`, the list the host holds, or `--pin`, its initial pins. `--bundle FILE` also checks a CA bundle against the list. It exits 0 when the list is accepted and 3 with the code when it is refused; a held list that has expired is a warning in the output. It needs no directory.

`due` and `run` come with M2, `card adopt` with M6 and `card check` with M2 (the names of these two commands and of `stop` are proposed, awaiting the maintainer). `intermediate replace` and `revoke` and the `root` commands come with M4, `keyring build` with M5, and `renew` and the guided mode come after the first signed release; the read-only page of `wizard --web` comes with M2. The commands of the trust products that come later are below.

## Commands for the trust products that come later

These are the arguments of the commands that build and check the CRLs (M4, [issue #30](https://github.com/truvity/ritueel/issues/30)), the SSH CA key list (M4, [issue #55](https://github.com/truvity/ritueel/issues/55)) and the keyring package (M5, [issue #15](https://github.com/truvity/ritueel/issues/15)). The formats are on [the CRL page](/reference/crl/), [the SSH CA key list page](/reference/ssh-ca-key-list/) and [the keyring package page](/reference/keyring-package/).

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `ritueel crl verify FILE --bundle FILE [--held FILE] [--cert FILE]` | A CRL, the CA bundle of the roots the party trusts, the CRL it holds and a certificate. | Nothing. | 0, 1, 2, 3 |
| `ritueel ssh-ca-keys verify FILE (--held FILE \| --root-list FILE) [--user-keys FILE]` | An SSH CA key list, the list the host holds or the root list it holds (with its `.jws`), and the file for sshd. | Nothing. | 0, 1, 2, 3 |
| `ritueel keyring build --name NAME [--out DIR]` | The roots and the bindings in the directory, and the newest root list. | The packages and plain files, to `products/<sequence>/keyring/` or `DIR`. | 0, 1, 2, 3 |
| `ritueel keyring verify FILE... --root-list FILE [--dir DIR]` | Packages or plain files, the root list, and the directory. | Nothing. | 0, 1, 2, 3 |
| `ritueel ssh-ca break-glass ROOT` | The root's entry in the directory. | A break-glass SSH CA in the root's store, its public key `roots/<label>/ssh-break-glass.pub`, and the next trust products. | 0, 1, 2, 3, 4, 5 |

- **`crl verify`** exits 0 when the CRL is accepted and 3 with the code when it is refused; a held CRL that has expired is a warning in the output. With `--cert`, a certificate the CRL lists exits 3 with the code `revoked`. It needs no directory.
- **`ssh-ca-keys verify`** exits 0 when the list is accepted and 3 with the code, including `user-keys-mismatch` for the file for sshd; it needs no directory.
- **`keyring build`** refuses to mix test and real roots, as `bundle build` does, and verifies its output before it writes it. A ceremony writes the keyring with its other trust products once the builder exists.
- **`keyring verify`** exits 0 when every check passes and 3 with the code. Without `--dir` it cannot check what a revocation dropped.
- **`ssh-ca break-glass`** is a ceremony: it has the plan, the confirmation and the record of every other, and needs the card of `ROOT`.

The codes of the new objects are in the output as `reasons`, like the others; `trust_sequence` and `artifacts` are written by the commands that write trust products.

:::note[Proposed]
`init` reads a `ritueel.yaml` the operator wrote rather than taking the name, the release address and the policy as flags, so that ritueel never rewrites that file. `--key-dir`, `handoff check --intermediate`, `records close --reason`, `bundle build --out`, `--decline` and the arguments of `root-list verify` are the arguments this page adds to the commands of ADR 0004.
:::

### A script's ceremony

A test harness drives a ceremony in two runs, so that it confirms only a plan it has read. With a test root there is no passphrase; a software root whose key file is opened by a passphrase adds `--passphrase-fd N` to the second run.

```sh
ritueel --dir ca intermediate add example-ca --request req-1 --key-dir keys \
  --plan-only --output json > plan.json
ritueel --dir ca run "$(jq -r .plan.path plan.json)" --key-dir keys \
  --confirm "$(jq -r .plan.sha256 plan.json)" --output json
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
| `reasons` | When refused: the codes, as in the [hand-off contract](/reference/hand-off-contract/#the-answer) or the [root list](/reference/root-list/#how-a-host-reads-it) where they apply, the codes of [a card](/reference/cards/#what-is-checked-on-a-card) and of [a KMS root](/reference/kms-root/#the-checks), and `plan-stale` for a plan that no longer matches the directory. |
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
| `findings` | `status` | A list of `{ "level", "kind", "name", "expires_at", "days_left" }`: `level` is `notice`, `alert` or `critical`, `kind` is `intermediate`, `root`, `root-list`, `ssh-ca-keys`, `crl`, `attempt`, `root-set`, `root-overlap` or `drill`. |
| `records` | `records list` | A list of `{ "ceremony", "command", "outcome", "sha256" }`, in chain order. |

The members are named with lower-case words and underscores, times and digests are written as in the [hand-off contract](/reference/hand-off-contract/#messages-and-files), and the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.
