---
title: The bundle, the wanted files, root profiles and key files
description: The layout of a ritueel bundle, who writes each part, how a file is written, what join does, and the wanted files and root profiles.
sidebar:
  order: 6
---

*Not built yet. This is the layout the M2 code writes ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9)); the rules it follows are in [record 0006](../decisions/0006-bundle-history-and-trust-files.md) and [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md).*

ritueel keeps everything it knows about one trust domain in one **bundle**, a directory of plain files with a fixed structure ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 1). A person writes only the **wanted files**. ritueel writes the rest, and it only adds files: it never rewrites a file of the history (rule 29). [Learn](/learn/the-history/) advises on where to keep the bundle and how to back it up and restore it. ritueel needs no git (rule 5), and the holder is still advised to keep the bundle in version control (rule 9).

The bundle holds the wanted files, the history, the trust sets, the certificates, public keys and attestations of the root keys, the digests of the revocation signatures, the card files and slot maps, the sealed secrets of cards ([record 0003](../decisions/0003-root-cards.md), rule 10) and, in a personal bundle, the wrapped backup of the person's encryption subkey ([record 0008](../decisions/0008-a-persons-own-key.md), rule 8). It never holds a private key in clear, a PIN the holder types, a passphrase or a revocation signature (record 0006, rule 1). Losing it loses the card files, the attestations and the OpenPGP creation times, so it is part of every key's identity (rules 8 and 9). The private key of a software root key lives in a **key file outside it** ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 26).

## One bundle, one trust domain

A bundle has its own history, trust sequence and one root of each kind it uses (X.509, OpenPGP, SSH CA). A company bundle also has a root list; a personal bundle has none ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 2). The keys of a root are labelled `A` and `B`, then the next letter. A holder with a personal key and a company keeps two bundles, for example `personal/` and `acme/`. Across bundles a root key is written with the bundle's name, `acme/A` (rule 3). Two bundles may share a pair of root cards. Each keeps its own card files, its own sealed copy of the card secrets and its own rows ([the cards page](/reference/cards/), [record 0003](../decisions/0003-root-cards.md), rules 6 and 7).

A bundle is named by its directory (record 0006, rule 3).

:::note[Proposed]
What `acme/A` names when one letter labels the keys of several roots in one bundle is open ([issue #137](https://github.com/truvity/ritueel/issues/137)).

No file stores the bundle's name. `name` in `ritueel.yaml` is the name in the root keys' subjects, `CN=Example Root A`, and is not the bundle's name: the bundle `acme` may have `name: Acme Corp`. Two bundles may then issue the same subject, and whether `name` must differ between bundles is open ([issue #8](https://github.com/truvity/ritueel/issues/8)). Each bundle has its own unlock key and recovery key, which open its key files as [record 0002](../decisions/0002-where-a-key-lives.md), rule 28, says. With the passkey way, a card shared by two bundles holds one credential for each. How the slot 9d fallback works for two bundles is open, because the card has one 9d key ([issue #11](https://github.com/truvity/ritueel/issues/11)).
:::

## The layout

Every folder and file has one of five marks.

| Mark | Meaning | Who writes it |
|---|---|---|
| **WANTED** | A person says how it should be. | A person, on the workstation only ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11). `new` writes the starter files once ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 15). |
| **SEEN** | What a check read from the world. | A read-only check. The next check replaces the file whole ([record 0003](../decisions/0003-root-cards.md), rules 12 and 18). |
| **HISTORY** | What happened. | A ceremony, and only by adding files. Nothing is overwritten ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29). |
| **REQUEST** | A request in, an answer out. | The requester writes the request; a ceremony adds the answer beside it (rule 10). |
| **BUILT** | Found each time from the wanted files, the history, the date and the requests. | Nothing is stored. What is not applied yet is of this kind ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 29). |

The tree of a bundle `acme`, with root keys on cards and in a cloud key service:

```text
acme/
├── ritueel.yaml                       WANTED   settings
├── want/                              WANTED   one strict YAML file for each object
│   ├── cards/                         one for each card: root-a.yaml, root-b.yaml, day-ana.yaml, …
│   ├── roots/                         one for each root: acme-tls.yaml, acme-release.yaml, acme-ssh.yaml
│   ├── delegations/                   one for each delegation: acme-ca.yaml, acme-release.yaml, …
│   └── openpgp.yaml                   the user IDs of the OpenPGP root (one file, Proposed)
├── seen/                              SEEN     one slot map for each card
├── sealed/                            HISTORY  the sealed card secrets
├── roots/A/                           HISTORY  root.json and attestation/, written once
├── requests/acme-ca-2027/             REQUEST  the request, and once given the answer
├── history/20261120T100000Z-apply-3fa9c1d2/   HISTORY  one ceremony folder for each ceremony
│   ├── plan.json                      the plan
│   ├── wanted/                        exact copies of the wanted files the plan used
│   ├── attempt.json                   written before the first key is born
│   ├── births.jsonl                   the birth journal
│   ├── signatures.jsonl               the journal of signatures
│   ├── transcript.txt                 what ritueel printed
│   └── record.json                    the ceremony record, written last
├── trust/13-3fa9c1d2/                 HISTORY  one trust set; its name carries its number and its identity
└── drills/                            SEEN     the reports of the restore check, which the holder commits
```

:::note[Proposed]
The names `ritueel.yaml`, `history/`, `trust/` and `requests/` are decided ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 5, 10, 11 and 12). Every other folder name, the file names inside a ceremony folder and the spelling of the names that carry an identity await the maintainer's word and are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)).
:::

| Path | Mark | Written by | Holds |
|---|---|---|---|
| `ritueel.yaml` | WANTED | A person | The settings: name, release address, policy, the KMS account, keyring and keyservers ([below](/reference/bundle/#ritueelyaml)). |
| `want/…` | WANTED | A person; `want` writes only what the person saves | One file for each card, root and delegation, and the user IDs ([the wanted files](/reference/bundle/#the-wanted-files)). |
| `seen/…` | SEEN | The read-only card check | The map of one card: every slot of its PIV, OpenPGP and FIDO2 applications and its use ([cards](/reference/cards/)). |
| `sealed/…` | HISTORY | Adoption of a card, on the workstation only; it never runs on the stick ([record 0003](../decisions/0003-root-cards.md), rule 10; [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 14) | This bundle's own copy of a card's management key, PUK and, on a day-to-day card, Admin PIN, sealed to the recipients of the key files. The name of the file and which file is the current one are open ([issue #144](https://github.com/truvity/ritueel/issues/144)). |
| `roots/<label>/root.json` | HISTORY | The ceremony that makes the key, once | The facts of one root key ([below](/reference/bundle/#rootjson)). |
| `roots/<label>/attestation/` | HISTORY | The same ceremony | For a root key on a card or in KMS: the attestation, or the key's description and policy, as read at the first `apply` ([cards](/reference/cards/#files), [KMS](/reference/kms-root/#evidence-files)). |
| `roots/<label>/ssh-break-glass.pub` | HISTORY | The same ceremony, from M2 with the cloud store | The break-glass SSH CA key of the root key, one OpenSSH line ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 25; [the SSH CA key list](/reference/ssh-ca-key-list/#how-a-key-enters-the-list)). |
| `requests/<name>/` | REQUEST | The requester writes the request; a ceremony adds the answer (requests in, answers out: [record 0001](../decisions/0001-what-ritueel-is.md), rule 3) | One folder for each request; `<name>` is the stem of the [hand-off contract](/reference/hand-off-contract/#messages-and-files). It holds the request files and, once given, the answer beside them: `<name>.result.json`, and `<name>.cert.pem` or `<name>.bound.pgp` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 10). |
| `history/<ceremony>/` | HISTORY | A ceremony; `close` writes a closing record | One ceremony folder for each ceremony, with the [ceremony files](/reference/ceremony-record/): the plan, exact copies of the wanted files the plan used, the attempt, the [birth journal](/reference/ceremony-record/#the-birth-journal), the journal of signatures, the transcript and the ceremony record ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 5). Each ceremony record names the one before it (rule 6). |
| `trust/<number>-<identity>/` | HISTORY | A ceremony, built beside and renamed into place; also `revoke`, which writes the trust set without the key ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 8) | One trust set ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 12): `root-list.json`, `root-list.jws` and `ca-bundle.pem` ([the root list](/reference/root-list/#files)); from M4 `crl-<label>.pem` for each active root key ([the CRLs](/reference/crl/#files)); from M4 `ssh-ca-keys.json`, `ssh-ca-keys.jws` and `ssh-user-ca-keys.pub` ([the SSH CA key list](/reference/ssh-ca-key-list/#files)) and `revocations/`; from M5 `keyring/` ([the keyring package](/reference/keyring-package/#files)). |
| `drills/` | SEEN | The restore check; the holder commits the reports | Reports of the restore check. They are not ceremony records and stay out of the hash chain ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 25). |

An inert proposal of the page ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rule 11) is not a wanted file and has no mark here. It is built after the first build of the page. Where it waits and what it may hold are open ([issue #147](https://github.com/truvity/ritueel/issues/147)).

A personal bundle also holds the wrapped backup of the encryption subkey (record 0008, rule 8). Its path and format are fixed with the personal OpenPGP stage ([issue #18](https://github.com/truvity/ritueel/issues/18)).

- A ceremony only adds files. Nothing under `history/`, `trust/`, `sealed/` or `requests/` is ever overwritten ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29). `seen/` is the one place that is replaced: a check writes a new map whole over the old one.
- The bundle keeps no second copy of a root key's certificate or public key. They are in the newest trust set that holds them (rule 12), because a copy that a ceremony replaced would break rule 29.
- ritueel never changes a wanted file after `new`, and never changes a request. It adds the answer beside it (rules 10 and 11). A person edits no other path than the wanted files and the requests.
- ritueel refuses a request whose folder already has an answer (rule 10).
- The bundle is found by `--dir DIR`, or is the current directory when it holds `ritueel.yaml` ([Commands](/reference/cli/#flags-every-ceremony-shares)).
- Outside the bundle are the key files of a software root key ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 26) and the revocation material (rule 22).

## How a file is written

[Record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29, decides: a ceremony only adds files, each named by its identity (a digest or a time) and written whole or not at all, under a temporary name and then by one rename. These are the steps. The commands write in this order, so a stop leaves a file whole or leaves it unwritten.

| # | Step | Source |
|---|---|---|
| 1 | Write the whole content under a new name in the same folder (a temporary name). | [0006](../decisions/0006-bundle-history-and-trust-files.md) rule 29 |
| 2 | Flush the file, so that the data reaches the disk. | Proposed |
| 3 | Rename it to its final name. A name in `history/`, `trust/`, `sealed/` or `requests/` is never replaced, so the rename refuses to replace. Every name carries its identity, so two writers do not meet on one name. | 0006 rule 29 |
| 4 | Flush the folder. | Proposed |
| 5 | A set of files, such as a trust set, is built beside under one temporary name. Then the folder is renamed into place. Its final name carries its number and its identity. The flush of each file is Proposed. | 0006 rules 12 and 29 |
| 6 | The ceremony record is written last, after the transcript and the artifacts. It lists them by digest and ends the ceremony. A ceremony folder with no ceremony record has not ended. If it holds an attempt, `status` shows it as critical until a person closes it. | [0005](../decisions/0005-a-ceremony-and-where-it-runs.md) rules 7 and 9; 0006 rule 6 |
| 7 | The attempt is written before the first key is born. Each key goes into the birth journal as soon as it exists, and each signature into the journal of signatures. | 0005 rule 7 |
| 8 | A file that a ceremony record lists and that fails its digest is an error for every reader. It is never "absent". | 0006 rule 29 |

:::note[Proposed]
These parts of the steps are not decided and are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)).

- The data of a file and of its folder are flushed (steps 2, 4 and 5). The attempt is made by an exclusive create. A journal grows by one flushed line at a time. A half line does not parse and counts as not written. A torn file that no ceremony record lists counts as not written, and is written again under the same name.
- After a stop, ritueel does not delete a folder with a temporary name. `close` lists it with its digests. When the ceremony record is written and the rename has not happened, the next command finishes the rename first.
- After a write to the stick, ritueel prints "flushed; the join on the workstation checks every file", and not "safe to remove". A removable stick can report a flush it did not do.

The rename that refuses to replace is a Linux call (`renameat2` with the no-replace flag). Its manual page lists ext4, btrfs, xfs and vfat and does not list exFAT (read 2026-11-12). It is not tested on a stick. The steps rest on digests and not on the rename, so they hold on any file system. The file system of the stick, and the trial of the rename on it, are open ([issue #30](https://github.com/truvity/ritueel/issues/30)).
:::

### How a name carries its identity

| What | Its name | Source |
|---|---|---|
| A ceremony folder | The time in UTC, the command and the first eight characters of the plan's digest, for example `20261120T100000Z-apply-3fa9c1d2`. | 0006 rule 29. The spelling is Proposed. |
| A trust set | Its number and the first eight characters of a digest, for example `13-3fa9c1d2`. | 0006 rules 12 and 29. The spelling is Proposed. |
| An answer to a request | The stem of the request, in the folder of the request. | 0006 rule 10 |
| A copy of a wanted file | Its path under `wanted/` in the ceremony folder. | 0006 rule 5 |
| A sealed file | A digest. Which file is current is open ([issue #144](https://github.com/truvity/ritueel/issues/144)). | 0006 rule 29 |

A name that does not carry its identity is a road not taken: two copies of a bundle could then hold two contents under one name, and a join could no longer only add files ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), roads not taken).

## What join does

`ritueel join SOURCE` is the thirteenth command word ([Commands](/reference/cli/)). Coming back from the stick is a join ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 30).

- It adds the files that one copy of a bundle has and the other lacks. It never merges text.
- It stops when one name has two contents, and when one request has two answers (rule 30).
- Two ends of the history are a fork. A join adds both and shows the fork as a critical finding, in `status` and in `check history` (rules 6 and 30).
- A join writes no ceremony record and changes no file. It only adds.
- After every join ritueel prints the end of the history ([below](/reference/bundle/#the-end-of-the-history)) (rule 9).
- The refresh of the stick before a plan is run there ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 22) also only adds files, and skips the wanted files.
- Wanted files never go to the stick and never come back from it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 21; [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11). The copies of the wanted files in a ceremony folder are copies and not wanted files; they travel with the plan (rule 5).

:::note[Proposed]
These parts of a join are not decided and are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)): the exit code of a join that stops (3); a join in both directions as one command, and a join that also refreshes the stick; the list of paths a join considers (the slot maps in `seen/` are not joined; the read-only check builds them again); that the unit of a join is the file path, and that the answer says "older", "newer" or "fork".
:::

The repair of a fork is later ([issue #138](https://github.com/truvity/ritueel/issues/138)).

## The end of the history

- The end of the history is the ceremony record that no other ceremony record names ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 6).
- After every ceremony and every join ritueel prints it: the first eight characters of its digest, and the count of ceremony records (rule 9).
- The holder keeps that print apart from the repository. It is advice and is not enforced (rule 9). Ceremony records are not signed (rule 6), so the eight characters are a check for the holder's eye and not a defence against an attacker.
- The next signed root list carries the digest of the end of the history as `last_record_sha256`. It anchors the chain without another use of the root (rules 6 and 15; [the root list](/reference/root-list/)).
- Whether `revoke` leaves a ceremony record and prints the end of the history is open ([record 0007](../decisions/0007-changing-and-losing-a-root.md), Proposed; [issue #141](https://github.com/truvity/ritueel/issues/141)).

## On the stick

A key that can be copied, such as a key file, is used only in the offline system, which boots from a USB stick. A root key on a card may also run there. A cloud root key always runs on the workstation, because the offline system has no network ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 17, 18 and 20). The stick carries one extra partition, and ritueel defines its layout (rule 21). The picture is on [the bundle and the USB stick](/how-it-works/bundle-and-stick/#the-usb-stick).

**The stick carries:** the ritueel program, in several versions and architectures; the bundles; the encrypted key files, beside the bundles and never inside one (rule 21). The stick's copy of a bundle carries no wanted files (rule 21). A saved plan travels inside the bundle with the exact copies of the wanted files it used (rules 21 and 4).

**The stick does not carry:** wanted files, a plan made on the stick, or an adoption of a card (rule 14). The partitions of AirgapOS are not touched (rule 23).

**The run** is `ritueel apply PLAN`. It checks that the end of the history and the trust sequence still match those the plan was made against, and the person types the first eight characters of the plan's digest (rule 10). When a plan is prepared online and the stick is present, ritueel refreshes the partition first, and the plan records the digest of the program (rule 22).

:::note[Proposed]
The names below are the smallest layout that serves the decision. They await the maintainer's word.

```text
RITUEEL/                          the extra partition
├── ritueel/                      the program
│   ├── 0.1.0/
│   │   ├── linux-amd64/ritueel
│   │   └── linux-arm64/ritueel
│   └── 0.2.0/ …
├── bundles/                      several bundles, without their wanted files
│   ├── acme/                     roots/, requests/, history/<ceremony>/plan.json and wanted/, …
│   └── personal/
└── keys/                         the encrypted key files, one folder for each bundle
    └── personal/A.openpgp.key.age
```

- **`RITUEEL/`** is the extra partition. AirgapOS's own partitions are not touched.
- **`ritueel/<version>/<system>-<arch>/ritueel`** holds the program, and nothing else, because it is one static file. The version comes first, so that the run can use the exact version that made the plan (rule 25). The system and the architecture come second, so that several machines can use one stick.
- **`bundles/<name>/`** is a bundle copied without its wanted files, so the plan in its history and the bundle the plan was made from arrive together. It is the directory that your workstation uses with `--dir`, with no second format.
- **`keys/<bundle>/`** holds the key files of that bundle. Key files are never inside a bundle, so a copy of a bundle cannot carry a key by accident. The folder has the name of the bundle.
- **The plan records the copy that made it** in the member `ritueel`: `{ "version", "os_arch", "sha256" }` ([the ceremony files](/reference/ceremony-record/)). The run is then `<stick>/ritueel/<version>/<system>-<arch>/ritueel --dir <stick>/bundles/acme apply history/<ceremony>/plan.json`.

Not decided: the label and the file system of the partition, whether a checksum file sits beside each binary, and whether the `keys/` folder of a bundle may sit inside the parent of the bundle ([issue #30](https://github.com/truvity/ritueel/issues/30)).
:::

Not yet proven on hardware: that AirgapOS boots from a stick with such a partition and mounts it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).

## The wanted files

A person writes `ritueel.yaml` and one strict YAML file for each card, root and delegation. The user IDs of the OpenPGP root are a wanted file too; its shape is Proposed (below). A person writes them only on the workstation ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11). `new` writes the starter files ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 15). `want` opens one in `$EDITOR` and writes only what the person saves ([Commands](/reference/cli/)).

- **Strict YAML** (record 0006, rule 11). What strict means is Proposed (below).
- **The digest** of a wanted file is the SHA-256 of the bytes as stored, so `sha256sum` gives the same value. The plan lists the wanted files it used by digest ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 4). Two files with one meaning have two digests. This is accepted.
- **The name** of an object is the name of its file without `.yaml`. A card's file is named by a name the holder gives, not by its serial (record 0006, rule 11).
- **A deleted line or file** retires, revokes and removes nothing. The history wins over a wanted file (record 0005, rule 30). A wanted file that fails its check stops `apply` before anything is written (rule 14).

| File | One for each | Holds | Decided by |
|---|---|---|---|
| `ritueel.yaml` | bundle | The settings ([below](/reference/bundle/#ritueelyaml)). | [0006](../decisions/0006-bundle-history-and-trust-files.md) rule 11 |
| `want/cards/NAME.yaml` | card | The card's serial; its kind, which is `root`, `day-to-day`, `server` or `rehearsal` and never changes; the holder; and the rows of other bundles that the card declares. | [0003](../decisions/0003-root-cards.md) rules 8, 14, 18 |
| `want/roots/NAME.yaml` | root | The kind of the root (X.509, OpenPGP or SSH CA); its keys, each with a label and a place (a card named by its card file, or a cloud key); for a key, what it replaces and until when, and an optional retire date with a reason; the revocation reasons to keep ready; and whether it is a test root. The number of keys in the file is the number of root keys wanted. A key listed with no history is born by `apply`. | [0007](../decisions/0007-changing-and-losing-a-root.md) rules 3, 4, 5, 10, 20, 22; [0005](../decisions/0005-a-ceremony-and-where-it-runs.md) rules 15, 28, 29 |
| `want/delegations/NAME.yaml` | delegation | The type (`x509-intermediate`, `openpgp-subkey` or `ssh-ca-key`), the root it is under, and its limits ([below](/reference/bundle/#a-delegation-file)). A delegation is a declared name under a root for a key that does daily work. | [0006](../decisions/0006-bundle-history-and-trust-files.md) rule 23; [0008](../decisions/0008-a-persons-own-key.md) rule 7 |
| `want/openpgp.yaml` | bundle | The user IDs of the OpenPGP root. | [0008](../decisions/0008-a-persons-own-key.md) rule 17 (that a person edits the user IDs; the file and its members are Proposed, [#18](https://github.com/truvity/ritueel/issues/18)) |

:::note[Proposed]
These parts are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)): the members of the files in the table; what strict means (one document in a file, no anchors, no merge keys, no repeated keys, UTF-8 with LF, no byte order mark, no tags, no aliases, and an unknown key is an error); the form of an object name (lower-case letters, digits and hyphens, 1 to 63 characters).

The rules a request is checked against are split between `policy` in `ritueel.yaml` and each delegation's file ([issue #9](https://github.com/truvity/ritueel/issues/9)).

A card file never holds another bundle's name. A row of another bundle is declared as `use: other-bundle` with its row ([issue #11](https://github.com/truvity/ritueel/issues/11)).

Who owns a user ID of the OpenPGP root, whether the user IDs are one file for the root or one file for each object (the decision asks one file for each object), and how an old user ID is marked to retire, are open ([issue #18](https://github.com/truvity/ritueel/issues/18)). A test root is marked in its wanted root file at birth; the spelling is open ([issue #136](https://github.com/truvity/ritueel/issues/136)).

That `status` shows a deleted wanted line as a finding, and the name of the finding, is a Proposed line of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md).
:::

## `ritueel.yaml`

A person writes it; `new` makes the starter file. An unknown key is an error, as in the contract. It holds settings only. Each delegation has its own file ([above](/reference/bundle/#the-wanted-files)).

```yaml
version: 1
name: Example                    # in the root keys' subjects and user IDs
release_address: release@example.com
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.4
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
keyring:
  license: CC0-1.0
```

| Key | Meaning |
|---|---|
| `version` | `1`. |
| `name` | 1 to 64 characters: letters, digits, spaces and hyphens. It names the root keys and their primaries ([below](/reference/bundle/#the-root-certificate)). |
| `release_address` | The address in every primary's user ID: the project's release identity, never a person's ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)). |
| `policy` | The rules every request is checked against: `stores`, `min_firmware`, `pin_policy`, `require_name_constraints` and `validity_months`, with the meanings of the [reference policy](/reference/hand-off-contract/#what-the-certifier-checks). All five are required. |
| `kind` | Optional. `personal` for a person's own OpenPGP key; absent for a company bundle. A personal bundle has `person` instead of `name` and `release_address` ([personal OpenPGP](/reference/personal-openpgp/)). |
| `person` | Only with `kind: personal`: `name` (1 to 64 characters) and `address`. |
| `aws_kms` | Optional, from M2; required when a root key's store is `aws-kms`. The root account, the two Regions and the two roles, and, proposed for M7, the renewal policy ([the block](/reference/kms-root/#ritueelyaml), [the policy](/reference/kms-root/#the-policy-in-ritueelyaml)). |
| `keyring` | Proposed; no record has this member. `license` would be the SPDX identifier written into the `.rpm`, which the release pipeline builds ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rule 21): the operator's choice, which ritueel does not default ([the keyring package](/reference/keyring-package/)). |
| `keyservers` | Proposed in record 0011 (rule 4 decides a managed list; the block and its member names are proposed). The keyservers `ritueel publish` may send the public OpenPGP key to, one entry for each server (an address and the kind, the keys.openpgp.org interface or HKP). The holder lists them; `new` ships no default that sends, and keys.openpgp.org and keyserver.ubuntu.com are commented examples ([record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md)). It is not in the schema below until it is decided. |

The schema, in JSON Schema (draft 2020-12), which the code ships and checks the file against:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "policy"],
  "allOf": [
    { "if": { "required": ["kind"] },
      "then": { "required": ["person"], "not": { "anyOf": [{ "required": ["name"] }, { "required": ["release_address"] }] } },
      "else": { "required": ["name", "release_address"] } }
  ],
  "properties": {
    "version": { "const": 1 },
    "kind": { "const": "personal" },
    "person": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "address"],
      "properties": {
        "name": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 .'-]{0,63}$" },
        "address": { "type": "string", "format": "email" }
      }
    },
    "name": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 -]{0,63}$" },
    "release_address": { "type": "string", "format": "email" },
    "policy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["stores", "min_firmware", "pin_policy", "require_name_constraints", "validity_months"],
      "properties": {
        "stores": { "type": "array", "uniqueItems": true, "minItems": 1,
                    "items": { "enum": ["piv", "openpgp-card", "aws-kms", "software"] } },
        "min_firmware": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$" },
        "pin_policy": { "type": "array", "uniqueItems": true, "minItems": 1,
                        "items": { "enum": ["never", "once", "always"] } },
        "require_name_constraints": { "type": "boolean" },
        "validity_months": { "type": "integer", "minimum": 1 }
      }
    },
    "keyring": {
      "type": "object",
      "additionalProperties": false,
      "properties": { "license": { "type": "string", "minLength": 1 } }
    },
    "aws_kms": {
      "type": "object",
      "additionalProperties": false,
      "required": ["account", "region", "replica_region", "admin_role", "ceremony_role"],
      "properties": {
        "account": { "type": "string", "pattern": "^[0-9]{12}$" },
        "region": { "type": "string", "minLength": 1 },
        "replica_region": { "type": "string", "minLength": 1 },
        "admin_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
        "ceremony_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
        "renewal": {
          "type": "object",
          "additionalProperties": false,
          "required": ["role", "intermediates", "within_days"],
          "properties": {
            "role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
            "intermediates": { "type": "array", "uniqueItems": true, "items": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$" } },
            "within_days": { "type": "integer", "minimum": 14, "maximum": 90 }
          }
        }
      }
    }
  }
}
```

Two rules the schema cannot state: the two Regions of `aws_kms` differ, and both its roles are in `account`. ritueel checks both when it reads the file.

### A delegation file

`want/delegations/NAME.yaml` declares one delegation: a declared name under a root for a key that does daily work ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 23). A request under no declared delegation is refused with the code `policy` ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 14). `NAME` is the `NAME` of the commands: lower-case letters, digits and hyphens, 1 to 63 characters.

```yaml
version: 1
type: x509-intermediate
root: acme-tls
permitted_uri_hosts: [example.com]
```

```yaml
version: 1
type: openpgp-subkey
root: acme-release
capability: sign
kms_read_roles:
  "111122223333": arn:aws:iam::111122223333:role/example-certifier-read
```

```yaml
version: 1
type: ssh-ca-key
root: acme-ssh
use: user
```

| Key | Meaning |
|---|---|
| `version` | `1`. |
| `type` | `x509-intermediate`, `openpgp-subkey` or `ssh-ca-key`. |
| `root` | The name of the root the delegation is under: a file in `want/roots/`, of the kind the type needs. |
| `permitted_uri_hosts` | For `x509-intermediate`: the hosts a request's name constraints must stay inside. Required when `require_name_constraints` is true. Only URI hosts are expressible in version 1. **Planned:** permitted and excluded DNS subtrees and excluded IP ranges, for an intermediate that issues for DNS names and for per-environment limits; the schema will grow when a first installation needs it. |
| `capability` | For `openpgp-subkey`: `sign` or `authenticate`, required. A request for another capability is refused with `policy`; the subkey is bound with this one's key flag ([the contract](/reference/hand-off-contract/#openpgp-subkey)). |
| `use` | For `ssh-ca-key`: `user` or `host`, required. A request for another `use` is refused with `policy`; the key is listed with this use ([the contract](/reference/hand-off-contract/#ssh-ca-key)). |
| `kms_read_roles` | For a requester's KMS key in another account: the read-only role to assume, by account ([the contract](/reference/hand-off-contract/#aws-kms)). The role is never taken from a request. |

A test vector's configuration in `testdata/hand-off/v1/manifest.json` is the `policy` block together with the one delegation's members its requests are for: the `permitted_uri_hosts` and `kms_read_roles` there are that delegation's.

The members are proposed ([issue #8](https://github.com/truvity/ritueel/issues/8)), and so is the split of the rules between `policy` and the delegation file ([issue #9](https://github.com/truvity/ritueel/issues/9)): the contract says the policy lists the rules **for the requester**. The schema of the file:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "type", "root"],
  "properties": {
    "version": { "const": 1 },
    "type": { "enum": ["x509-intermediate", "openpgp-subkey", "ssh-ca-key"] },
    "root": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$" },
    "capability": { "enum": ["sign", "authenticate"] },
    "use": { "enum": ["user", "host"] },
    "permitted_uri_hosts": { "type": "array", "uniqueItems": true, "items": { "type": "string" } },
    "kms_read_roles": { "type": "object", "propertyNames": { "pattern": "^[0-9]{12}$" },
                        "additionalProperties": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" } }
  }
}
```

Five rules the schema cannot state: a delegation name is unique, which its file name guarantees; a name that begins with `break-glass-` is refused, because the SSH CA key list uses those for the break-glass keys; an `x509-intermediate` has `permitted_uri_hosts` when `require_name_constraints` is true; an `openpgp-subkey` has `capability`; an `ssh-ca-key` has `use` and no other key of the type. A delegation under no root is an error. ritueel checks all of them when it reads the file.

## `root.json`

`roots/<label>/root.json` is one canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)). The ceremony that makes the key writes it once, and nothing changes it after ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29).

Whether a key is active, retired or revoked is read from the ceremony records and the newest root list, not from this file ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 3). What a key replaces, and until when, is a wanted field (rules 3 and 4). Root state as files is later.

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `label` | The label of the root key: one upper-case letter, `A` and `B` for the two keys the first `apply` makes, then the next free letter for each key added, whatever its key store. It never names the store, is unique inside its bundle and is never reused. What a label names across roots is open ([issue #137](https://github.com/truvity/ritueel/issues/137)). |
| `store` | `software`, `piv` or `aws-kms`. |
| `test` | True for a test root key. Set at birth and never changed; a real root never becomes a test root ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 28). |
| `created_at` | When the key was made: the time of its ceremony. |
| `x509_spki_sha256` | The pin of the X.509 root key. |
| `openpgp_fingerprint` | The primary's fingerprint. |
| `openpgp_created` | The OpenPGP creation time of the primary, which fixes its fingerprint and is on no card ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 8). |
| `revocations` | An object from reason (`compromised`, `superseded`, and any the holder added) to the SHA-256 of that revocation signature packet, which is stored elsewhere ([revocation material](/reference/revocation-material/)). |
| `removal_sha256` | The SHA-256 of the key's removal authorisation, which is stored elsewhere with the revocation signatures ([revocation material](/reference/revocation-material/#the-removal-authorisation)). Absent in a personal bundle. |
| `adopted` | True for an OpenPGP primary adopted as it was ([record 0008](../decisions/0008-a-persons-own-key.md)) or for a cloud key that ritueel adopted instead of creating ([record 0004](../decisions/0004-the-cloud-root.md)). Absent otherwise. |
| `store_ref` | For a key in `piv` (from M6) or `aws-kms` (from M2); absent for `software`. For `piv`: `{ "serial", "row" }`, the card's serial and the key's row in the [slot map](../decisions/0003-root-cards.md); the slots follow from the built-in map. For `aws-kms`: `{ "x509_arn", "openpgp_arn", "ssh_arn" }`, the ARNs of the primary keys ([the cloud root](/reference/kms-root/#what-ritueel-creates)). |
| `vouched_by`, `vouches` | For a key added by a transition, from M4: the digests of the two vouch files as first made ([the transitions page](/reference/transitions/#in-rootjson)). |

:::note[Proposed]
Revocation material that is made again later (record 0007, rule 22) cannot change this file. Where its digest is kept besides the ceremony record of the ceremony that made it is open ([issue #8](https://github.com/truvity/ritueel/issues/8)).
:::

## The root certificate

Every X.509 root key's certificate has this profile. A relying party can check every row.

| Field | Value |
|---|---|
| Version, serial | 3. A positive number of at most 20 bytes from a cryptographic random source, with at least 64 random bits. |
| Signature | `ecdsa-with-SHA384`, self-signed with the root key's own P-384 key. |
| Issuer, subject | The same name: one common name, `<name> Root <label>`, from `ritueel.yaml`, for example `CN=Example Root A`. A test root key's name ends in ` (TEST ONLY)`: `CN=Example Root A (TEST ONLY)`. |
| Subject public key | The root key's X.509 key: ECDSA on P-384. |
| Validity | `notBefore` is the ceremony time; `notAfter` is 36 calendar months later (same day and time of the month, or the last day of the month if it has none), both UTC. |
| Basic constraints | Critical. `cA` true, no path length. |
| Key usage | Critical. `keyCertSign` and `cRLSign`. |
| Subject key identifier | Not critical. The leftmost 160 bits of the SHA-256 of the subject public key bits (RFC 7093, section 2, method 1), as in the [intermediate's profile](/reference/hand-off-contract/#what-is-issued). |
| Name constraints | Absent: constraints belong to the intermediates. |
| Anything else | Absent, the authority key identifier included (RFC 5280, section 4.2.1.1, allows it in a self-signed certificate). |

**Each use re-issues it.** Every ceremony that signs with a root key makes a new certificate over the same key and the same subject, with a new serial, starting at the ceremony time ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 13). The new certificate is a new file in the trust set ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 12 and 29); the earlier trust set keeps the earlier one. A root key that is used every year or two therefore never comes close to its end, and pins on its key never change.

## The OpenPGP primary

Every root key's OpenPGP primary has this profile, as [record 0009](../decisions/0009-release-keys-and-the-keyring.md) decides (rules 1, 2 and 4).

| Part | Value |
|---|---|
| Key | Version 4, ECDSA on P-384 (algorithm 19). The creation time is `openpgp_created`. |
| User ID | One: `<name> Release Root <label> <release_address>`, for example `Example Release Root A <release@example.com>`. A test root key's adds ` (TEST ONLY)` before the address. No person's name. |
| Self-signature | A positive certification (type `0x13`) of the user ID, SHA-384. Hashed: signature creation time (the ceremony time), key flags `0x01` (certify only), key expiration time, marked critical, so that the key expires 36 calendar months after the ceremony, and the issuer fingerprint. Unhashed: the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). |
| Subkeys | None of its own. It binds the subkeys of intermediates through the hand-off. |
| Revocation | A key revocation signature (type `0x20`), made when the key is born and stored apart from it. |

**Each use extends it,** with a new self-signature of the same shape at the ceremony time. The new public certificate is a new file in the trust set.

The test roots of the [hand-off vectors](/reference/hand-off-contract/#test-vectors) follow both profiles, with the name `Example Test`.

## The software root's key files

A software root key ([the `software` store](../decisions/0002-where-a-key-lives.md)) serves tests, drills and development, and never anchors a signed release ([record 0002](../decisions/0002-where-a-key-lives.md), rule 6; [record 0009](../decisions/0009-release-keys-and-the-keyring.md)). Its private key is in a file in a **key directory**, given by `--key-dir DIR`, which ritueel refuses when it is inside the bundle ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), roads not taken: key files inside the bundle). Every command that writes a key file, and every ceremony record of a ceremony that uses one, says that a software root key can be copied (record 0005, rule 27).

| File | Content |
|---|---|
| `<label>.x509.key.age` | The X.509 root key: a PKCS#8 `PrivateKeyInfo` (RFC 5958), PEM-armoured as `PRIVATE KEY`, encrypted with age to the recipients below. |
| `<label>.openpgp.key.age` | The primary: a transferable secret key, binary (RFC 9580, section 10.2), version 4, whose secret key material is not protected inside (S2K usage 0) because age encrypts the whole file. |
| `<label>.revocation.<reason>.pgp.age` | The primary's revocation signature for one reason, `compromised` or `superseded` (or one the holder added), encrypted the same way. One file for each reason; the SHA-256 of the signature packet before encryption is the reason's entry in `revocations`. |
| `<label>.removal.jws.age` | The key's removal authorisation, encrypted the same way; the SHA-256 of the JWS text before encryption is `removal_sha256`. |

- **Encryption.** The age format (`age-encryption.org/v1`). By default a key file is encrypted to two recipients: the public half of an age key (the unlock key) and a recovery recipient. A passkey on each card named as a way to open the file (the root cards) unwraps the private half of the unlock key; any one of those cards is enough, and a file may name more than two; the recovery key is an age identity in a passphrase-protected file kept apart from the cards ([record 0002](../decisions/0002-where-a-key-lives.md), rules 20 to 22). Encrypting needs no card. The members that hold the wrapped private half of the unlock key, and the recovery file, are fixed with the passkey proof (M1), and are not written here before it.
- **A passphrase instead,** for a holder without cards: the age passphrase recipient, which derives the key with scrypt (record 0002, rule 23). A passphrase file holds only that recipient, because the age v1 specification says "An scrypt stanza, if present, MUST be the only stanza in the header" (read 2026-11-11, [age v1](https://age-encryption.org/v1)). The passphrase is read from the terminal without echo, or from `--passphrase-fd N`; it is never a flag, an environment variable or a line of output. A test root key or a script uses it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 27).
- **A test root** is marked at birth and has no passphrase ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 28). Its key files are written with no encryption: `<label>.x509.key.pem` with the line `TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root.` before the armour, `<label>.openpgp.key.asc` and `<label>.revocation.<reason>.asc`, ASCII-armoured with the header `Comment: TEST ONLY`, and `<label>.removal.jws`. The names of its keys carry ` (TEST ONLY)` too, and `apply` refuses to put a test root and a real root in one trust set.
- The holder keeps the revocation files and the removal authorisation apart from the key files, as for a card ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 22).

## Follow-ups

- The code that writes the wanted files, the card maps, the sealed files, the `attestation/` files and the `aws_kms` block ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)); their formats are on [the cards page](/reference/cards/) and [the cloud root page](/reference/kms-root/).
- The steps of a write and the ceremony folder ([issue #9](https://github.com/truvity/ritueel/issues/9)).
- The CRLs, the SSH CA key list and the keyring files in a trust set come with their builders ([issue #30](https://github.com/truvity/ritueel/issues/30), [issue #55](https://github.com/truvity/ritueel/issues/55), [issue #15](https://github.com/truvity/ritueel/issues/15)), in M4 (the CRLs and the SSH CA key list) and M5 (the keyring).

## Later

These are named and are not rules. Nothing on this page depends on them.

- A store of every old text of a wanted file ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), roads not taken). Until then the copies in each ceremony folder, and git, keep the old texts.
- A change over several files, written as one step.
- A decided repair of a fork ([issue #138](https://github.com/truvity/ritueel/issues/138)).
- The sealed single-file form of the history, for backups that reveal nothing (record 0006, rule 5).
- Trust numbers that skip. Until then the number grows by one (record 0006, rule 14).
- The lock kept as a file, which keeps two writers from one bundle. The Proposed lock of [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md) is held by the running process; it is not this file.
- Root state as files: a key's state is read from the ceremony records, as in [`root.json`](/reference/bundle/#rootjson).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The root certificate profile. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The subject key identifier. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The primary, its self-signature and revocation, transferable secret keys. |
| [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958), [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PKCS#8 private keys and their PEM armour. |
| [age v1](https://github.com/C2SP/C2SP/blob/main/age.md) | Encryption of the software root's key files, and the passphrase recipient (scrypt). |
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) | The schema of `ritueel.yaml` and of a delegation file. |
