---
title: Commands
description: The thirteen ritueel commands, their forms, the shared flags, the exit codes and the JSON output. Only `version` is built.
sidebar:
  order: 2
---

*Only `version` is built; the other commands are not. This is the command set of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md) and [record 0006](../decisions/0006-bundle-history-and-trust-files.md), with the commands of [record 0007](../decisions/0007-changing-and-losing-a-root.md), [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) and [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md); the code is [issue #10](https://github.com/truvity/ritueel/issues/10) and [issue #30](https://github.com/truvity/ritueel/issues/30). The commands of M2, with their files, are in [The first version's commands](/reference/cli/#the-first-versions-commands).*

You write what you want in wanted files. ritueel finds what is not applied yet, and `apply` does it in one ceremony. There are thirteen command words: `new`, `status`, `want`, `apply`, `revoke`, `check`, `publish`, `close`, `verify`, `wizard`, `stop`, `version` and `join`.

## Commands

:::note[Proposed]
These names and flags are proposed, awaiting the maintainer: the template names of `new`, the spelling of `--test-root` ([#136](https://github.com/truvity/ritueel/issues/136)), `--with`, `--material`, `--delegation`, `--reason` of `apply`, `close` and `revoke`, `--card` of `revoke`, the exit code 3 of `join`, and `--decline`. `status`, `close` and `join` read the [trace area](/reference/trace-area/) first (0005 rule 39), and the flag that names the area is proposed here as `--area SOURCE`, a device or a copy of it; which command prepares the trace area is open too ([#181](https://github.com/truvity/ritueel/issues/181)). `want accept` and `want decline` are later and belong to [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md). The flag `--only` and an age limit of a plan are not decided ([#143](https://github.com/truvity/ritueel/issues/143), [#142](https://github.com/truvity/ritueel/issues/142)); the page names them, but they are not rules.
:::

| Command | Does | Needs a person | Decided by |
|---|---|---|---|
| `ritueel new [--template two-cards\|cloud\|personal\|file] [--test-root] DIR` | Makes the bundle folder and the starter wanted files. It touches no card and makes no key. The first `apply` makes the keys. | No | 0005 rule 20; 0006 rule 5 |
| `ritueel status [cards\|keys\|certs\|ceremonies]` | With no argument: what is not applied yet, by object, with its source and what it needs; the findings; the due dates. With an argument: that list. A fork and an unresolved attempt are critical; on the stick an open ceremony in the [trace area](/reference/trace-area/) is an unresolved attempt. A deleted wanted line is shown as a finding (0005 rule 5); the name of the finding is fixed with the code. Exit codes 10, 11 and 12. | No | 0005 rules 4, 5, 10 and 39; 0007 rules 6 and 18; 0006 rule 35 |
| `ritueel want [OBJECT]` | Opens the wanted file of `OBJECT` in `$EDITOR`; with no `OBJECT`, lists the wanted files. It checks the file (strict YAML, a label twice, a delegation under no root, the only key of a root retired) and shows the changes that are now not applied yet. It writes only what the person saves. | Only the editor | 0006 rule 5; 0005 rule 4 |
| `ritueel want accept ID`, `want decline ID` | Proposed, later (record 0010). Take or refuse a proposal made in the local page. `accept` would show the edit first. | `accept` only | [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) |
| `ritueel apply [--plan-only] [--with CARD...] [--reason TEXT] [--allow-missing NAME] [--confirm DIGEST]` | Does the changes that are not applied yet, in one ceremony. It shows the plan: what it applies and what it leaves out, with the reason. The person types the first eight characters of the plan's digest and nothing more. A change of the set of root keys runs alone, never with renewals. A card is adopted only on the workstation. `--plan-only` stops after the plan. | Yes | 0005 rules 1, 7, 9, 13, 16 and 19; 0007 rules 9 and 19; 0003 rule 15 |
| `ritueel apply PLAN [--with CARD...] [--reason TEXT] [--confirm DIGEST]` | Runs a saved plan, in the offline system or for another holder. It first checks that the end of the history and the trust sequence are those the plan was made against, then asks for the first eight characters. | Yes | 0005 rules 13, 30 and 32 |
| `ritueel revoke KEY... \| --card CARD --reason REASON [--material FILE]` | The act. It revokes now and alone, with the stored revocation material or the cards that issued. It reads no wanted file and no plan, and it is no part of `apply`. | Yes | 0007 rules 11, 12 and 14 |
| `ritueel check cards\|request STEM\|history\|restore\|material FILE` | Reads and compares; it signs nothing. `cards`: the card against the built-in layout. `request`: the hand-off checks of a request. `history`: the hash chain, and every file a ceremony record lists against its digest. `restore`: the restore check. `material`: a stored revocation, a verdict only. | No | 0003 rule 6; 0006 rules 8 and 31; 0007 rule 24 |
| `ritueel check tls HOST:PORT` | Proposed (record 0011). Reads the chain a live service presents and says which delegation and root it shows. It is not proof that a key is not revoked. | No | [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md) |
| `ritueel publish [--revocation FILE]` | A separate process, never inside a ceremony. Sends the public OpenPGP key to the keyservers in `ritueel.yaml` after a typed confirmation, then reads it back. With `--revocation FILE` it sends the revocation signature the holder keeps apart. The block `keyservers`, the read-back and the flag `--revocation` are proposed. Details are in [After a ceremony](/reference/cli/#after-a-ceremony). | Yes | [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md) |
| `ritueel close CEREMONY --reason TEXT [--confirm DIGEST]` | Closes an unresolved attempt: prints the birth journal and the journal of signatures, and writes a closing record. On the stick it reads the trace area first, makes the missing files from it and shows an act that has no result. | Yes | 0005 rules 10, 14, 38 and 39 |
| `ritueel verify root-list\|crl\|ssh-ca-keys\|keyring FILE...` | The host's and the relying party's side of each trust file. It runs the checks on a file, signs and writes nothing, and needs no bundle. | No | 0006 rules 21, 24 and 26; [record 0009](../decisions/0009-release-keys-and-the-keyring.md) |
| `ritueel wizard [--web]` | The guided mode, which asks line by line in the terminal; with `--web`, also a read-only page served on localhost. The page has four entries, shows the plan and its digest in History, and cannot confirm anything; its one write, built later, is an inert proposal ([the page](/reference/wizard/)). The page calls the same API as the commands, served by the same ritueel process on one fixed loopback port; `--web` prints its address, and the name of the flag is proposed ([the process](/reference/wizard/#the-ritueel-process)). | Yes | [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) rules 2, 3, 6, 11 and 12 |
| `ritueel stop` | Ends the ritueel process if one runs (record 0010, rule 10). Proposed: it exits 0 also when none runs. The process otherwise ends by itself after an idle time. | No | [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) rule 10 |
| `ritueel version` | Prints the version and the commit. | No | None |
| `ritueel join SOURCE` | Adds to the bundle the files of another copy (the stick, a clone; coming back from the stick is a join, 0006 rule 35) that it lacks. It never merges text. It stops when one name has two contents, or when one request has two answers. It prints the end of the history: the first eight characters of the digest of its ceremony record, and the count of ceremony records. Two ends are a fork, shown as a critical finding; the repair of a fork is not decided ([#138](https://github.com/truvity/ritueel/issues/138)). Given the trace area of the stick, it first makes the missing attempt and journal files from it. | No | 0006 rules 11 and 35; 0005 rule 39 |

ritueel also prints the end of the history after every ceremony.

:::note[Proposed]
Three more lines are proposed and are not rules. `apply` could refuse to make a new plan while an attempt is open, or only refuse to run the plan that has the attempt ([#140](https://github.com/truvity/ritueel/issues/140)). `revoke` could stop a ceremony that runs on the same machine, or wait for it, and could leave a ceremony record like any ceremony ([#141](https://github.com/truvity/ritueel/issues/141)). An adoption could leave a ceremony record, and could be a plan of its own that is applied before the plan that makes keys ([#144](https://github.com/truvity/ritueel/issues/144)).
:::

*The age limit and `--only`.* A scheduled run needs a guard that a plan made long ago, or a change added last week, is not signed without a look. Two ideas are proposed: an age limit of a plan, and a flag `--only OBJECT...` that a script must pass to confirm, and that narrows the plan to those objects. Neither is decided. No number and no spelling is fixed ([#142](https://github.com/truvity/ritueel/issues/142), [#143](https://github.com/truvity/ritueel/issues/143)).

### Earlier names

An older page or record may use these words. Each went into one of the thirteen.

| Earlier name | Now |
|---|---|
| `init` | `new`, then the first `apply` |
| `due` | `status` shows it; `apply` does it |
| `run PLAN` | `apply PLAN` |
| `intermediate add`, `intermediate replace` | A wanted delegation file, then `apply` |
| `intermediate revoke`, `root revoke` | `revoke` |
| `root add`, `root retire` | The keys and the retirement date in the wanted root file, then `apply` |
| `revocation make` | The reasons listed in the wanted root file, then `apply` |
| `revocation check` | `check material` |
| `personal subkey add` | A wanted delegation file for a key on a daily card, then `apply` |
| `personal userid change` | An edit of the wanted user IDs, then `apply`: one plan certifies the new user ID and revokes the old one ([record 0008](../decisions/0008-a-persons-own-key.md), rule 16) |
| `card adopt` | A wanted card file, then `apply`; the order against the first plan that makes keys is open (record 0003) |
| `card check` | `check cards` |
| `root extend`, `subkey extend`, `crl renew`, `root-list sign` | A change found from the end date; `apply` does it |
| `handoff check` | `check request` |
| `ca-bundle build`, `keyring build` | Written into the trust set by `apply` |
| `root-list verify`, `crl verify`, `ssh-ca-keys verify`, `keyring verify` | `verify` with the same word after it |
| `records list`, `records verify`, `records close` | `status ceremonies`, `check history`, `close` |
| `drill restore` | `check restore` |

### How a root changes

The verbs of a transition map onto the wanted root file and the commands. *Create* and *vouch* are a key added to the wanted root file and applied. *Overlap* is a period with a wanted end date, and not a command. *Supersede* is the retirement date reached and applied. *Revoke* is `revoke` ([root transitions](/reference/transitions/)).

There is no command that renames an X.509 root key. Its name is inside its certificate, and every delegation's certificate names it as issuer. A new name is a new key: add it to the wanted root file, run an overlap, then retire the old one ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 4).

## Flags every ceremony shares

| Flag | Meaning |
|---|---|
| `--dir DIR` | The bundle. The default is the current directory when it holds `ritueel.yaml`. |
| `--plan-only` | `apply` only: write the plan (`history/<ceremony>/plan.json`) and stop. |
| `--confirm DIGEST` | Confirm a plan from a script; the digest must be the plan's (0005 rule 9); `close` takes it too (0005 rule 14). Without it, `apply` asks the person for the first eight characters. |
| `--with CARD` | `apply`: name the cards at hand when none is connected (for `--plan-only`). It also names the card that signs instead of the card of the year, and must when that card is absent; `--reason` is recorded ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 16). Without it, a ceremony that signs with one card uses the only card connected, and two cards at hand are refused with `card-ambiguous` ([cards](/reference/cards/#what-is-checked-on-a-card)); the first `apply` and an added root key need both cards. `CARD` is the name of a card file. |
| `--allow-missing NAME` | `apply` only: plan without a request for this delegation, and record it. |
| `--decline REASON` | `apply PLAN` from a script: decline the request, and write the answer with the code `declined` ([declining](/reference/ceremony-record/#declining)). |
| `--extra-intermediates FILE` | `piv` roots: PEM certificates of the maker's intermediates that the attestation bundle lacks. Helpers only: each must chain to the pinned root ([the attestation bundle](/reference/cards/#the-attestation-bundle)). |
| `--revocation-dir DIR` | Every command that makes revocation signatures for a root key that is not in an encrypted-file software store: where to write them. Refused inside the bundle or its repository ([revocation material](/reference/revocation-material/#where-it-is-written)). The reasons are listed in the wanted root file. |
| `--backend file\|onepassword\|keyring` | Software roots: the backend ([the software store](/reference/software-store/)). `--op-vault NAME` names the vault for `onepassword`. |
| `--passphrase-fd N` | Software roots whose key file is opened by a passphrase (a script root that is not a test root, a holder without cards): read the passphrase from this file descriptor (0005 rule 27). |
| `--key-dir DIR` | Software roots: the directory of the [key files](/reference/bundle/#the-software-roots-key-files). Refused when it is inside `--dir`. |
| `--test-root` | `new` only (the place of the mark and the spelling are open, [#136](https://github.com/truvity/ritueel/issues/136)): marks the roots as test roots at birth. A test root is marked `TEST ONLY` everywhere, and no trust set holds a test root and a real root together. With a software store it has no passphrase; its key may also live on a rehearsal card. It may run its ceremonies on the workstation or on a rehearsal card; the program checks nothing about where it runs. |
| `--output json` | Every command, ceremony or not: print one JSON object on standard output ([below](/reference/cli/#machine-readable-output)). The default is `--output text`. |

The card of a root key is named in its wanted card file, so there is no flag that names a card by serial.

*Earlier flags.* `--root` is now `--with` and a reason. `--roots`, `--kind`, `--reasons`, `--intermediate`, `--request` and `--out` are now the wanted files, or are gone.

Proposed. The text output writes a root key across bundles as `acme/A`. What `acme/A` names when one letter labels the keys of several roots is open ([#137](https://github.com/truvity/ritueel/issues/137)). The JSON output is unchanged.

A PIN is never a flag or an environment variable; the holder types it at the terminal. The ritueel process never keeps one between calls.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `status`, nothing due. |
| 1 | Failure. |
| 2 | Usage error. |
| 3 | Refused by a check or by the policy. `join` also stops with this code (proposed). |
| 4 | Refused by the card or its PIN state, or by the key store backend: a locked key store, or a KMS session that is not a session of the ceremony role, or has expired (`kms-session`). |
| 5 | Not confirmed. |
| 10, 11, 12 | `status` only: notice, alert and critical. Delegations warn at 60, 30 and 14 days, the root list, the SSH CA key list and each CRL at 60, 30 and 14 days, root keys at 6 months, 3 months and 30 days. An unresolved attempt is critical, because it may mean a signature that was made and never recorded. A fork is critical. A short set of root keys is an alert (finding `root-set`), an overdue overlap an alert and a running one a notice (finding `root-overlap`) (0007 rule 6; [root transitions](/reference/transitions/#the-target)); a restore check older than 13 months is a notice ([drills](/reference/drill/#when-it-is-due)). The highest finding wins. |

## The first version's commands

M2 builds these, with the software store and the cloud store ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9), [issue #10](https://github.com/truvity/ritueel/issues/10)). The paths are those of [the bundle](/reference/bundle/#the-layout). A ceremony writes its [plan, attempt, journals, transcript and ceremony record](/reference/ceremony-record/) in its ceremony folder, and the trust set of its new trust sequence beside them. Every name it writes carries its identity, and the ceremony record is written last ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31).

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `ritueel version` | Nothing. | The version and the commit it was built from. | 0 |
| `ritueel stop` | The ritueel process, if one runs. | Nothing; it asks the process to end. | 0, 1, 2 |
| `ritueel new [--test-root] DIR` | Nothing. | The bundle folder and the starter wanted files, among them `ritueel.yaml`. | 0, 1, 2 |
| `ritueel apply [--plan-only] --key-dir DIR` | The wanted files, the history, the requests. | The ceremony folder (plan, exact copies of the wanted files it used, attempt, birth journal, journal of signatures, transcript, ceremony record), the answers beside the requests in `requests/STEM/`, the key files in `DIR`, and the trust set. | 0, 1, 2, 3, 5 |
| `ritueel check request STEM [--delegation NAME]` | The request in `requests/STEM/`, the wanted files. | Nothing. | 0, 1, 2, 3 |
| `ritueel status` | The bundle and, on the stick, the trace area. | Nothing. | 0, 1, 2, 10, 11, 12 |
| `ritueel check history` | The bundle. | Nothing. | 0, 1, 2, 3 |
| `ritueel close CEREMONY --reason TEXT [--confirm DIGEST]` | `history/CEREMONY/attempt.json` and the journals, or the trace area. | A closing record and its transcript. | 0, 1, 2, 3, 5 |
| `ritueel join SOURCE` | The bundle and the other copy, with its trace area if it has one. | The files the bundle lacked. | 0, 1, 2, 3 (3 proposed) |
| `ritueel verify root-list FILE (--held FILE \| --pin SHA256...) [--ca-bundle FILE]` | A root list, the list the host holds or its initial pins, and a CA bundle. | Nothing. | 0, 1, 2, 3 |

- **`new`** and the first **`apply`** make a bundle. `new` touches no card. The first `apply` makes the keys of the roots: two keys of each root by default, both cards present; a cloud root or a personal bundle has one key; Proposed: a software root may have one key. It refuses a key directory that already has key files. The key files are opened as [record 0002](../decisions/0002-where-a-key-lives.md) says; a passphrase, where one is used, is asked once for each key, or read from `--passphrase-fd`; a test root asks none. It prints the accepted limit, and the ceremony record says so.
- **`apply`, for a request,** refuses a request under no declared delegation with the code `policy`. It also refuses a request whose type is not the delegation's `type`, and a request whose folder already has an answer. It runs the contract's checks 1 to 9, then the ceremony; the person's confirmation is check 10. A person may [decline](/reference/ceremony-record/#declining) the request instead (`--decline REASON` with `apply PLAN` from a script), which writes the answer with the code `declined` and a ceremony record (exit code 3). A plan that no longer matches the bundle is refused with `plan-stale` (exit code 3). A request refused by a check gets `STEM.result.json` beside the request in `requests/STEM/` with `outcome` `refused` and its code, and nothing else is written: no plan, no attempt, no ceremony record (exit code 3).
- **`check request`** runs checks 1 to 9 of the [hand-off contract](/reference/hand-off-contract/#what-the-certifier-checks) and signs nothing. Without `--delegation`, the rules that belong to one delegation (name constraints, KMS read roles) are reported as not run, never as passed. It exits 0 when every check that ran passed, and 3 with the code when one refused.
- **`status`** exits with the highest finding ([Exit codes](/reference/cli/#exit-codes)). An unresolved attempt is critical (12).
- **`check history`** checks the [hash chain](/reference/ceremony-record/#the-hash-chain), and that every file a ceremony record lists matches its digest. The findings, with their names, are in the table of [the hash chain](/reference/ceremony-record/#the-hash-chain). A finding is exit code 3, and its name is in `reasons`; `unfinished-ceremony` is a notice with exit code 0, and its name is in `warnings`. A clean run prints `history: N ceremony records, end XXXXXXXX`: the count of ceremony records and the first eight characters of the digest of the end ([the end of the history](/reference/bundle/#the-end-of-the-history)). A history with no ceremony record exits 0.
- **`close`** shows the attempt and asks the person to type the first eight characters of its plan digest, or takes `--confirm DIGEST` (0005 rule 14). Its closing record says that signatures may exist from that plan.
- **`join`** adds files and never changes one. It prints the end of the history. It stops when one name has two contents or one request has two answers, with exit code 3 (proposed), and shows a fork as a critical finding.
- **`verify root-list`** is the host's side: it runs [the host's checks](/reference/root-list/#how-a-host-reads-it) on `FILE` (a `root-list.json`, with its `.jws` beside it) against `--held FILE`, the list the host holds, or `--pin`, its initial pins. `--ca-bundle FILE` also checks a CA bundle against the list. It exits 0 when the list is accepted and 3 with the code when it is refused; a held list that has expired is the warning `held-expired` ([the output](/reference/cli/#machine-readable-output)). It needs no bundle.

The CA bundle is one of the files `apply` writes into the trust set. A command that prints it alone is proposed. `new`, `apply` and `status` come with M2; the milestone of `want` is not set. The thirteen command words are decided; the flags and the exit codes of `join` are proposed. `check cards` comes with M2 and `check restore` with M4, and the name of `check cards` is proposed. `revoke` comes with M4, `verify keyring` with M5, and the guided mode comes after the first signed release; the read-only page of `wizard --web` comes with M2. The commands of the trust files that come later are below.

## Commands for the trust files that come later

These are the arguments of the commands that check the CRLs (M4, [issue #30](https://github.com/truvity/ritueel/issues/30)), the SSH CA key list (M4, [issue #55](https://github.com/truvity/ritueel/issues/55)) and the keyring package (M5, [issue #15](https://github.com/truvity/ritueel/issues/15)). The formats are on [the CRL page](/reference/crl/), [the SSH CA key list page](/reference/ssh-ca-key-list/) and [the keyring package page](/reference/keyring-package/). The files themselves are written into the trust set by `apply`.

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `ritueel verify crl FILE --ca-bundle FILE [--held FILE] [--cert FILE]` | A CRL, the CA bundle of the roots the party trusts, the CRL it holds and a certificate. | Nothing. | 0, 1, 2, 3 |
| `ritueel verify ssh-ca-keys FILE (--held FILE \| --root-list FILE) [--user-keys FILE]` | An SSH CA key list, the list the host holds or the root list it holds (with its `.jws`), and the file for sshd. | Nothing. | 0, 1, 2, 3 |
| `ritueel verify keyring FILE... --root-list FILE [--dir DIR]` | Packages or plain files, the root list, and the bundle. | Nothing. | 0, 1, 2, 3 |

- **`verify crl`** exits 0 when the CRL is accepted and 3 with the code when it is refused; a held CRL that has expired is the warning `held-expired` ([the output](/reference/cli/#machine-readable-output)). With `--cert`, a certificate the CRL lists exits 3 with the code `revoked`. It needs no bundle.
- **`verify ssh-ca-keys`** exits 0 when the list is accepted and 3 with the code, including `user-keys-mismatch` for the file for sshd; a held list that has expired is the warning `held-expired` ([the output](/reference/cli/#machine-readable-output)). It needs no bundle.
- **`verify keyring`** exits 0 when every check passes and 3 with the code. Without `--dir` it cannot check what a revocation dropped.
- **The keyring file** (the public certificates, binary and armoured) is written into the trust set by `apply`, once M5 builds it. It refuses to mix test and real roots, and is verified before it is written. The release pipeline builds the package from it ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rules 21 to 23).

The codes of these files are in the output as `reasons`, like the others; `trust_sequence` and `artifacts` are written by the commands that write trust files.

:::note[Proposed]
`new` makes the wanted files, and ritueel never rewrites a wanted file on its own ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 5 and 31). `--with`, `--key-dir`, `check request --delegation`, `close --reason`, `--decline` and the arguments of `verify root-list` are the arguments this page adds to the commands of record 0005.
:::

### A script's ceremony

A test harness drives a ceremony in two runs, so that it confirms only a plan it has read. With a test root there is no passphrase; a software root whose key file is opened by a passphrase adds `--passphrase-fd N` to the second run.

```sh
ritueel --dir ca apply --plan-only --key-dir keys --output json > plan.json
ritueel --dir ca apply "$(jq -r .plan.path plan.json)" --key-dir keys \
  --confirm "$(jq -r .plan.sha256 plan.json)" --output json
```

A script that confirms may also have to pass `--only`. That is proposed and not decided ([#143](https://github.com/truvity/ritueel/issues/143)), so the example does not use it.

## After a ceremony

:::note[Proposed]
Every flag, form and list name in this section is proposed, awaiting the maintainer; the command words are decided (the thirteen of the command reference). The rules are [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md). ritueel changes only your bundle, sends out only a public OpenPGP key, and never runs a command with administrator rights.
:::

| Command | Does | Needs a person |
|---|---|---|
| `ritueel publish [--revocation FILE]` | A separate process, never inside a ceremony and absent from the offline build. Rebuilds the public key from the verified ceremony record, shows a preview (every user ID, subkeys, fingerprint, each server, "what is published cannot be withdrawn"), waits for the typed confirmation (the first 8 characters of the fingerprint and the server name; 16 characters for a revocation), sends to the keyservers listed in `ritueel.yaml`, reads back and compares. Refuses a test root and a run while a ceremony runs; reads no token. With `--revocation FILE` it sends the revocation signature the holder keeps apart. | Yes |
| `ritueel check tls HOST:PORT` | Reads the chain a live service presents and says which delegation and root it shows, with the time, the source and the facts; it is not proof that a key is not revoked. Whether Go exposes the full presented chain is not researched. | No |
| `ritueel verify root-list FILE (--held FILE \| --pin SHA256...)` | Run on the two fetched files, the list and its `.jws` (the host checks itself). A form that reads standard input is not decided. | No |

After every ceremony ritueel prints a list of next steps (its name, NEXT STEPS, is proposed): what changed, who needs it, how. Later: `check --local`, which matches installed roots to the bundle by key pin.

Exit codes of these commands are fixed with the code.

## Machine-readable output

With `--output json`, a command prints **one JSON object on standard output** when it ends, followed by a newline, whatever its outcome. Everything a person reads (the plan in words, prompts, progress, warnings) goes to standard error, and the transcript holds it. Only arguments so broken that `--output json` cannot be read print no object; the exit code is then 2.

Every object has these members:

| Member | Meaning |
|---|---|
| `output` | The version of this format, `1`. |
| `command` | The first word of the command, one of the thirteen command words: `apply`, `new`, `join`. For `verify root-list` it is `verify`, and for `check history` it is `check`. |
| `exit_code` | The exit code the command returns. |
| `outcome` | `done`, `refused`, `not-confirmed`, `usage` or `failed`, matching the exit code. |
| `reasons` | When refused: the codes, as in the [hand-off contract](/reference/hand-off-contract/#the-answer) or the [root list](/reference/root-list/#how-a-host-reads-it) where they apply, the codes of [a card](/reference/cards/#what-is-checked-on-a-card) and of [a KMS root](/reference/kms-root/#the-checks), `plan-stale` for a plan that no longer matches the bundle, and the names of the [findings of `check history`](/reference/ceremony-record/#the-hash-chain). |
| `error` | When failed or a usage error: a message for a person. Its wording is not part of the format. |
| `warnings` | A list of strings, one for each warning, empty when there is none. A warning does not change the exit code. The warning of a held list that has expired is `held-expired`. The text output prints each warning on standard error. |

And these where they apply:

| Member | Commands | Meaning |
|---|---|---|
| `version`, `commit` | `version` | The release version and the commit. |
| `ceremony` | ceremonies | The ceremony's name. |
| `plan` | ceremonies | `{ "path", "sha256", "prefix" }`: the plan file, its digest, and the eight characters a person types. With `--plan-only`, this is the result. |
| `record` | ceremonies, `close` | `{ "path", "sha256" }`: the ceremony record. |
| `artifacts` | ceremonies | A list of `{ "path", "sha256" }`, as in the ceremony record. |
| `trust_sequence` | ceremonies | The trust sequence of the trust set written. |
| `roots` | `apply`, `status` | A list of the root keys: `{ "label", "store", "test", "x509_spki_sha256", "openpgp_fingerprint", "not_after" }`, with `openpgp_fingerprint` only when the bundle has an OpenPGP root. |
| `answer` | `apply` | `{ "stem", "outcome", "reasons", "artifacts" }`, as in `result.json`. |
| `checks` | `check request` | A list of `{ "n", "result" }` for checks 1 to 9, where `result` is `passed`, `failed` or `not-run`. |
| `findings` | `status` | A list of `{ "level", "kind", "name", "expires_at", "days_left" }`: `level` is `notice`, `alert` or `critical`, `kind` is `intermediate` (the certificate of a delegation), `root`, `root-list`, `ssh-ca-keys`, `crl`, `attempt`, `root-set`, `root-overlap`, `drill`, `fork` or `wanted` (a wanted file that fails its check, not a deleted line; the name `wanted` is proposed). A deleted wanted line is a finding too (0005 rule 5); its kind is fixed with the code. |
| `records` | `status ceremonies` | A list of `{ "ceremony", "command", "outcome", "sha256" }`, in chain order. |

The members are named with lower-case words and underscores, times and digests are written as in the [hand-off contract](/reference/hand-off-contract/#messages-and-files), and the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.
