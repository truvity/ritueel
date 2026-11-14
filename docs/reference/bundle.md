---
title: The bundle, the wanted files, root profiles and key files
description: The layout of a ritueel bundle, who writes each part, how a file is written, what join does, and the wanted files and root profiles.
sidebar:
  order: 6
---

*Not built yet. This is the layout the M2 code writes ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9)); the rules it follows are in [record 0006](../decisions/0006-bundle-history-and-trust-files.md) and [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md).*

ritueel keeps everything it knows about one organisation or one person in one **bundle**, a directory of plain files with a fixed structure ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 1). A person writes only the **wanted files**. ritueel writes the rest, and it only adds files: it never rewrites a file of the history (record 0006, rule 31). [Learn](/learn/the-history/) advises on where to keep the bundle and how to back it up and restore it. ritueel needs no git (record 0006, rule 7), and the holder is still advised to keep the bundle in version control (record 0006, rule 11).

The bundle holds the wanted files, the history, the trust sets, the certificates, public keys and attestations of the root keys, the digests of the revocation signatures, the card files and card maps, the sealed secrets of cards ([record 0003](../decisions/0003-root-cards.md), rule 15) and, in a personal bundle, the wrapped backup of the person's encryption subkey ([record 0008](../decisions/0008-a-persons-own-key.md), rule 10). It never holds a private key in clear, a PIN the holder types, a passphrase or a revocation signature (record 0006, rule 1). Losing it loses the card files, the attestations and the OpenPGP creation times, so it is part of every key's identity (record 0006, rules 10 and 11). The private key of a software root key lives in a **key file outside it** ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 30).

## One bundle for one organisation or one person

A bundle has its own history, trust sequence and one root of each kind it uses (X.509, OpenPGP, SSH CA). A company bundle also has a root list; a personal bundle has none ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 2). The keys of a root are labelled `A` and `B`, then the next letter. A holder with a personal key and a company keeps two bundles, for example `personal/` and `acme/`. Across bundles a root key is written with the bundle's name, `acme/A` (record 0006, rule 3). Two bundles may share a pair of root cards. Each keeps its own card files, its own sealed copy of the card secrets and its own rows ([the cards page](/reference/cards/), [record 0003](../decisions/0003-root-cards.md), rules 8 and 9).

A **card** is a hardware token, such as a YubiKey. A **card file** is the wanted file of one card. A **row** is the four PIV slots that a card keeps for the keys of one bundle ([record 0003](../decisions/0003-root-cards.md), rules 3 and 5).

A bundle is named by its directory (record 0006, rule 3).

:::note[Proposed]
What `acme/A` names when one letter labels the keys of several roots in one bundle is open ([issue #137](https://github.com/truvity/ritueel/issues/137)).

No file stores the bundle's name. `name` in `ritueel.yaml` is the name in the root keys' subjects, `CN=Example Root A`, and is not the bundle's name: the bundle `acme` may have `name: Acme Corp`. Two bundles may then issue the same subject, and whether `name` must differ between bundles is open ([issue #8](https://github.com/truvity/ritueel/issues/8)). Each bundle has its own unlock key and recovery key, which open its key files as [record 0002](../decisions/0002-where-a-key-lives.md), rule 27, says. With the passkey way, a card shared by two bundles holds one credential for each. How the slot 9d fallback works for two bundles is open, because the card has one 9d key ([issue #11](https://github.com/truvity/ritueel/issues/11)).
:::

## The layout

Every folder and file has one of five marks.

| Mark | Meaning | Who writes it |
|---|---|---|
| **WANTED** | A person says how it should be. | A person, on the workstation only ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 5). `new` writes the starter files once ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 20). |
| **SEEN** | What a check read from the world. | A read-only check. The next check replaces the file whole ([record 0003](../decisions/0003-root-cards.md), rules 5 and 6). |
| **HISTORY** | What happened. | A ceremony, and only by adding files. Nothing is overwritten ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31). |
| **REQUEST** | A request in, an answer out. | The requester writes the request; a ceremony adds the answer beside it (record 0006, rule 6). |
| **BUILT** | Found each time from the wanted files, the history, the date and the requests. | Nothing is stored. What is not applied yet is of this kind ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 4). |

The tree of a bundle `acme`, with root keys on cards and in a cloud key service:

```text
acme/
├── ritueel.yaml                       WANTED   settings
├── want/                              WANTED   one strict YAML file for each object
│   ├── cards/                         one for each card: root-a.yaml, root-b.yaml, day-ana.yaml, …
│   ├── roots/                         one for each root: acme-tls.yaml, acme-release.yaml, acme-ssh.yaml
│   ├── delegations/                   one for each delegation: acme-ca.yaml, acme-release.yaml, …
│   └── openpgp.yaml                   the user IDs of the OpenPGP root (one file, Proposed)
├── seen/                              SEEN     one card map for each card
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

The names `ritueel.yaml`, the eight folders `want/`, `seen/`, `sealed/`, `roots/`, `requests/`, `history/`, `trust/` and `drills/`, and the six files of a ceremony folder are decided, in lower case with no spaces ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 5 and 37).

:::note[Proposed]
The folders inside `want/`, the file `want/openpgp.yaml`, the folder `wanted/` of a ceremony folder, the files under `roots/<label>/`, the names of the files in `seen/` and `sealed/`, and the spelling of the names that carry an identity are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)).
:::

| Path | Mark | Written by | Holds |
|---|---|---|---|
| `ritueel.yaml` | WANTED | A person | The settings: name, release address, policy, the KMS account, keyring and keyservers ([below](/reference/bundle/#ritueelyaml)). |
| `want/…` | WANTED | A person; `want` writes only what the person saves | One file for each card, root and delegation, and the user IDs ([the wanted files](/reference/bundle/#the-wanted-files)). |
| `seen/…` | SEEN | The read-only card check | The map of one card: every slot of its PIV, OpenPGP and FIDO2 applications and its use ([cards](/reference/cards/)). |
| `sealed/…` | HISTORY | Adoption of a card, on the workstation only; it never runs on the stick ([record 0003](../decisions/0003-root-cards.md), rule 15; [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 19) | This bundle's own copy of a card's management key, PUK and, on a day-to-day card, Admin PIN, sealed to the recipients of the key files. The name of the file and which file is the current one are open ([issue #144](https://github.com/truvity/ritueel/issues/144)). |
| `roots/<label>/root.json` | HISTORY | The ceremony that makes the key, once | The facts of one root key ([below](/reference/bundle/#rootjson)). |
| `roots/<label>/attestation/` | HISTORY | The same ceremony | For a root key on a card or in KMS: the attestation, or the key's description and policy, as read at the first `apply` ([cards](/reference/cards/#files), [KMS](/reference/kms-root/#evidence-files)). |
| `roots/<label>/ssh-break-glass.pub` | HISTORY | The same ceremony, from M2 with the cloud store | The break-glass SSH CA key of the root key, one OpenSSH line ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 29; [the SSH CA key list](/reference/ssh-ca-key-list/#how-a-key-enters-the-list)). |
| `requests/<name>/` | REQUEST | The requester writes the request; a ceremony adds the answer (requests in, answers out: [record 0001](../decisions/0001-what-ritueel-is.md), rules 3 to 7) | One folder for each request; `<name>` is the stem of the [hand-off contract](/reference/hand-off-contract/#messages-and-files). It holds the request files and, once given, the answer beside them: `<name>.result.json`, and `<name>.cert.pem` or `<name>.bound.pgp` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 6). |
| `history/<ceremony>/` | HISTORY | A ceremony; `close` writes a closing record | One ceremony folder for each ceremony, with the [ceremony files](/reference/ceremony-record/): the plan, exact copies of the wanted files the plan used, the attempt, the [birth journal](/reference/ceremony-record/#the-birth-journal), the journal of signatures, the transcript and the ceremony record ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 7). Each ceremony record names the one before it (record 0006, rule 8). |
| `trust/<number>-<identity>/` | HISTORY | A ceremony, built beside and renamed into place; also `revoke`, which writes the trust set without the key ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 11) | One trust set ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 12): `root-list.json`, `root-list.jws` and `ca-bundle.pem` ([the root list](/reference/root-list/#files)); from M4 `crl-<label>.pem` for each active root key ([the CRLs](/reference/crl/#files)); from M4 `ssh-ca-keys.json`, `ssh-ca-keys.jws` and `ssh-user-ca-keys.pub` ([the SSH CA key list](/reference/ssh-ca-key-list/#files)); from M5 `keyring/` ([the keyring package](/reference/keyring-package/#files)). |
| `drills/` | SEEN | The restore check; the holder commits the reports | Reports of the restore check. They are not ceremony records and stay out of the hash chain ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 26). |

An inert proposal of the page ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rule 12) is not a wanted file and has no mark here. It is built after the first build of the page. Where it waits and what it may hold are open ([issue #147](https://github.com/truvity/ritueel/issues/147)).

A personal bundle also holds the wrapped backup of the encryption subkey (record 0008, rule 10). Its path and format are fixed with the personal OpenPGP stage ([issue #18](https://github.com/truvity/ritueel/issues/18)).

- A ceremony only adds files. Nothing under `history/`, `trust/`, `sealed/` or `requests/` is ever overwritten ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31). `seen/` is the one place that is replaced: a check writes a new map whole over the old one.
- The bundle keeps no second copy of a root key's certificate or public key. They are in the newest trust set that holds them (record 0006, rule 12), because a copy that a ceremony replaced would break rule 31 of record 0006.
- ritueel never changes a wanted file on its own, and never changes a request. It adds the answer beside it (record 0006, rules 5 and 6). A person edits no other path than the wanted files and the requests.
- ritueel refuses a request whose folder already has an answer (record 0006, rule 6).
- The bundle is found by `--dir DIR`, or is the current directory when it holds `ritueel.yaml` ([Commands](/reference/cli/#flags-every-ceremony-shares)).
- Outside the bundle are the key files of a software root key ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 30) and the revocation material (record 0007, rule 23).

### Where the trust sequence is carried

The trust sequence is one integer for the bundle. It grows by one whenever any trust file changes, there is no second counter, and every trust file carries it ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 14):

| Trust file | Where it carries the sequence |
|---|---|
| The root list | The member `sequence` ([the root list](/reference/root-list/#the-list)). |
| The SSH CA key list | The member `sequence` ([the list](/reference/ssh-ca-key-list/#the-list)). |
| The CA bundle | The first line, `# trust-sequence: <sequence>` ([the CA bundle](/reference/root-list/#the-ca-bundle)). |
| A CRL | The CRL number ([the profile](/reference/crl/#the-profile)). |
| The keyring package | The version, `<year>.<sequence>` ([the package](/reference/keyring-package/#name-and-version)). |

## How a file is written

[Record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31, decides: a ceremony only adds files, each named by its identity (a digest or a time) and written whole or not at all. These are the steps: under a temporary name, then one rename. The commands write in this order, so a stop leaves a file whole or leaves it unwritten. The package `internal/fsx` does these steps; the commands that use it are not built yet. [The root folder of the writer](/reference/bundle/#the-root-folder-of-the-writer) and [Names](/reference/bundle/#names) say what else it promises.

| # | Step | Source |
|---|---|---|
| 1 | Write the whole content under a new name in the same folder (a temporary name: 15 characters, a fixed prefix and a random part, never the final name). The name is `.rt-` and 11 random lower-case letters and digits. | [0006](../decisions/0006-bundle-history-and-trust-files.md) rules 31, 32 and 39 |
| 2 | Flush the file, so that the data reaches the disk. | 0006 rule 40 |
| 3 | Rename it to its final name. A name in `history/`, `trust/`, `sealed/` or `requests/` is never replaced, so the rename refuses to replace. When the final name exists, the write fails and the file at that name is unchanged. Every name carries its identity, so two writers do not meet on one name. | 0006 rules 31 and 40 |
| 4 | Flush the folder. | 0006 rule 40 |
| 5 | A set of files, such as a trust set, is built in a folder beside its final name, under one temporary name (step 1). The folder is opened and must be empty, or the write stops. The files in it have their own names. Each file is flushed, then the folder is flushed, then the folder is renamed into place by a rename that refuses to replace, and its parent folder is flushed. Its final name carries its number and its identity. | 0006 rules 12, 31, 32 and 41 |
| 6 | The ceremony record is written last, after the transcript and the artifacts. It lists them by digest and ends the ceremony. A ceremony folder with no ceremony record has not ended. If it holds an attempt, `status` shows it as critical until a person closes it. | [0005](../decisions/0005-a-ceremony-and-where-it-runs.md) rules 10 and 12; 0006 rule 8 |
| 7 | The attempt is written before the first key is born. Each key goes into the birth journal as soon as it exists, and each signature into the journal of signatures. The attempt is written like every other file, so its name is taken once. A journal is the one kind of file that stands at its final name while it grows. It is made empty by a create that fails if the name exists. A line and its line break go in one write, then the file is flushed. A line that holds a line break is refused. A half last line counts as not written, and the reader returns it apart. The journals are files of the finished bundle. On the stick, while the ceremony runs, the attempt and the journals are trace records in the [trace area](/reference/trace-area/), and the files are made from it when the ceremony ends. | 0005 rules 10, 36 and 39; 0006 rule 43 |
| 8 | A file that a ceremony record lists and that fails its digest is an error for every reader. It is never "absent". | 0006 rule 31 |

- When a write or a flush returns an error, ritueel stops at once with an error. It does not retry, and it does not print the line that says the write was flushed ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 33). The first error stops the writer for good: every later call of it and of its journals returns that error and reaches nothing on the disk. An error because the name exists is such an error ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 44).
- An empty folder, such as a ceremony folder, is made at its final name by one call, and its parent folder is flushed. It needs no temporary name: it is whole when it is empty. It fails when anything has that name ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 42).
- The mode of a file must give its owner the read bit, and the mode of a folder the read, write and search bits. Another mode is refused ([0006](../decisions/0006-bundle-history-and-trust-files.md) rules 40 and 42).
- A name that ritueel refuses before it touches the file system ([Names](/reference/bundle/#names)) is not an error of the file system, and it does not stop the writer.
- A cut leaves what the step it fell in leaves. A cut before the rename (step 3) leaves the file under its temporary name and nothing at its final name. A cut after the rename leaves the whole file at its final name, as far as the data reached the disk before the rename. A cut while a set is built leaves a folder with a temporary name, and no trust set at the final name. Nothing is deleted, so these names stay ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 45).
- A leftover temporary name is never read as a record. A reader of a bundle skips every name that starts with `.rt-`, in any case, because a temporary folder holds whole files under ordinary names. `fsx.ReadDir` lists every name and leaves the skipping to its caller. A path that is only read may name a leftover, to look at it ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 45).

:::note[Proposed]
These parts of the steps are not decided and are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)).

- A file that was never renamed to its final name is not a file of the bundle, and a new write may take that name. What ritueel does with a file at its final name that fails its digest is open ([issue #181](https://github.com/truvity/ritueel/issues/181)).
- After a stop, `close` lists a file or a folder with a temporary name with its digests. When the ceremony record is written and the rename has not happened, the next command finishes the rename first.
- After a write to the stick, ritueel prints "flushed; the join on the workstation checks every file", and not "safe to remove". A removable stick can report a flush it did not do.
:::

Not yet proven on a real stick: a cut during a write can break a bundle there. A folder's list of names was lost, and one sector kept the content of the write before it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), [issue #181](https://github.com/truvity/ritueel/issues/181)). The order of the steps does not prevent that. A flush that returns without an error is only the report of the stick.

The rename that refuses to replace is a call of the system: `renameat2` with the no-replace flag on Linux, and `renameatx_np` with the exclusive flag on macOS. On a file system or a system that cannot refuse a rename over an existing file, ritueel stops with an error: it never replaces a file and has no second way to write one. Its manual page lists ext4, btrfs, xfs and vfat and does not list exFAT (read 2026-11-12). In a trial on 2026-11-12 in a virtual machine, the rename worked on exFAT with the kernel of the offline system. It is not tested on a real stick. The file system of the stick is exFAT ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 31).

### The root folder of the writer

The writer works from the bundle's root folder. `fsx.Open(root)` opens that folder once, and every path the writer is given is relative to it, with `/` as the separator. The writer walks each path from the root, one element at a time. It follows no symbolic link, in any element of a path and at the final name, for a write and for a read: a link, or an element that is not a folder, is an error that names the element. It replaces nothing: a file is made by an exclusive create, and the rename refuses an existing name. A read opens a file without following a link and without waiting, so a FIFO is not waited on, and it reads only a regular file of at most 8 MiB. Anything else is an error, and never a cut-off read. The writer cannot tell whether the root is the right folder, and it does not look at what the root is mounted on. All of this holds as long as no other process that can write into the root moves a folder that the writer has open. A `Writer` that is copied by value after its first use refuses every call (`ErrCopied`).

A read is bounded, so that a damaged or hostile stick cannot fill the memory. A file is read only if it is a regular file of at most 8 MiB (`MaxReadSize`). A folder is listed only if it holds at most 65,536 names (`MaxDirEntries`). A journal is read only if it has at most 65,536 lines (`MaxJournalLines`). Beyond a limit the read is an error that wraps `ErrTooMany`, and nothing is returned in part. A ceremony has a few dozen journal lines, so a limit is about a thousand times what a bundle needs. A name in a list is data from the stick, not a name that ritueel made. A reader checks it with `fsx.CheckName` ([0006](../decisions/0006-bundle-history-and-trust-files.md) rule 46) before it shows the name or uses it in a path, and shows it only as escapes.

### How a name carries its identity

| What | Its name | Source |
|---|---|---|
| A ceremony folder | The time in UTC, the command and the first eight characters of the plan's digest, for example `20261120T100000Z-apply-3fa9c1d2`. | 0006 rule 31. The spelling is Proposed. |
| A trust set | Its number and the first eight characters of a digest, for example `13-3fa9c1d2`. | 0006 rules 12 and 31. The spelling is Proposed. |
| An answer to a request | The stem of the request, in the folder of the request. | 0006 rule 6 |
| A copy of a wanted file | Its path under `wanted/` in the ceremony folder. | 0006 rule 7 |
| A sealed file | A digest. Which file is current is open ([issue #144](https://github.com/truvity/ritueel/issues/144)). | 0006 rule 31 |

A name that does not carry its identity is a road not taken: two copies of a bundle could then hold two contents under one name, and a join could no longer only add files ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), roads not taken).

## Names

A name of a file or a folder in a bundle holds only the ASCII letters `A` to `Z` and `a` to `z`, the digits `0` to `9`, the dot, the hyphen and the underscore ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 38). A name of only these characters has one spelling on every system. No letter looks like another, no accented letter has two forms, and no system folds the case of a letter in another way.

ritueel refuses any other name before it touches the file system, so a refused name leaves nothing behind. The writer checks every element of a path, and every name of a file in a set.

| Refused | Example | Reason |
|---|---|---|
| A byte that is not one of the characters above: a space, a control code, a separator, a character of another script, a byte that is not UTF-8. | `plan 1`, `plan:1`, `a\b`, `é` | A name stays plain ASCII, and the stick's file system cannot hold some of these characters. A drive name such as `C:x` is refused by the colon. |
| An empty name, `.` or `..`. A path with an empty element, with a leading or a trailing separator is refused too. | `..`, `a//b`, `dir/` | A workstation's file system gives these names another meaning. |
| A name longer than 255 bytes. | 256 times `a` | A workstation's file system and exFAT hold at most 255 characters in a name. |
| A device name of Windows: `CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`. The part before the first dot is compared, in any case. | `aux`, `Nul.json`, `com1.txt` | A Windows system cannot open a file with such a name. |
| A name that ends with a dot. | `notes.` | Windows removes the dot, and the Linux driver of exFAT removes it by default, so the name on the stick is not the name asked for. |
| A name to be written that starts with the prefix of a temporary name (`.rt-`, [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 39), in any case. This is any element of a path to be written, a folder on the way included, or the name of a file in a set. | `.RT-abc` | exFAT compares names without case, so the name could meet a temporary name that is in use. |
| Two names of one set that differ only by case. | `Plan.json` and `plan.JSON` | exFAT holds them as one name. |

A path to be read may name a temporary name, so that a reader can look at what a stop left behind. The other rules hold for a read as for a write.

The writer does not see the names that exist already, so a second name that differs only by case from an existing one, given in another call, is refused by the file system of the stick, and not by the writer. On a file system that tells the two names apart, both exist. The writer does not check the length of a whole path or the depth of the folders: the operating system refuses them, and the writer stops with that error.

A name that the holder chooses, a label, can be refused by these rules. The label must be checked when the holder types it, and the refusal must say why. It must not be left to the write. A label cannot hold a space or a letter of another script. The names of people and organisations live inside the files, not in the names of files.

## What join does

`ritueel join SOURCE` is the thirteenth command word ([Commands](/reference/cli/)). Coming back from the stick is a join ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 35).

- It adds the files that one copy of a bundle has and the other lacks. It never merges text.
- It stops when one name has two contents, and when one request has two answers (record 0006, rule 35).
- Two ends of the history are a fork. A join adds both and shows the fork as a critical finding, in `status` and in `check history` (record 0006, rules 8 and 35).
- A join writes no ceremony record and changes no file. It only adds (record 0006, rule 36).
- After every join ritueel prints the end of the history ([below](/reference/bundle/#the-end-of-the-history)) (record 0006, rule 11).
- The refresh of the stick before a plan is run there ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 32) also only adds files, and skips the wanted files.
- Wanted files never go to the stick and never come back from it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 30; [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 5). The copies of the wanted files in a ceremony folder are copies and not wanted files; they travel with the plan (record 0006, rule 7).

:::note[Proposed]
These parts of a join are not decided and are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)): the exit code of a join that stops (3); a join in both directions as one command, and a join that also refreshes the stick; the list of paths a join considers (the card maps in `seen/` are not joined; the read-only check builds them again); that the unit of a join is the file path, and that the answer says "older", "newer" or "fork".
:::

The repair of a fork is later ([issue #138](https://github.com/truvity/ritueel/issues/138)).

## The end of the history

- The end of the history is the ceremony record that no other ceremony record names ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 8).
- After every ceremony and every join ritueel prints it: the first eight characters of its digest, and the count of ceremony records (record 0006, rule 11).
- The holder keeps that print apart from the repository. It is advice and is not enforced (record 0006, rule 11). Ceremony records are not signed (record 0006, rule 8), so the eight characters are a check for the holder's eye and not a defence against an attacker.
- The rest of the advice of rule 11 of record 0006 is also not enforced: keep the bundle in a git repository of its own, and back it up to a second remote. [Learn](/learn/the-history/) adds signed commits and review.
- The next signed root list carries the digest of the end of the history as `last_record_sha256`. It anchors the chain without another use of the root (record 0006, rules 8 and 16; [the root list](/reference/root-list/)).
- Whether `revoke` leaves a ceremony record and prints the end of the history is open ([record 0007](../decisions/0007-changing-and-losing-a-root.md), Proposed; [issue #141](https://github.com/truvity/ritueel/issues/141)).

## On the stick

A key that can be copied, such as a key file, is used only in the offline system, which boots from a USB stick; a test root is the exception. A root key on a card may also run there. A cloud root key always runs on the workstation, because the offline system has no network ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 22 to 24 and 29). The stick carries two extra partitions, the files partition and the [trace area](/reference/trace-area/), inside one extended partition, and ritueel defines their layout (record 0005, rules 30 and 36). The picture is on [the bundle and the USB stick](/how-it-works/bundle-and-stick/#the-usb-stick).

**The stick carries:** the ritueel program, in several versions and architectures; the bundles; the encrypted key files, beside the bundles and never inside one (record 0005, rule 30). The stick's copy of a bundle carries no wanted files (record 0005, rule 30). A saved plan travels inside the bundle with the exact copies of the wanted files it used (record 0005, rules 7 and 30).

**The stick does not carry:** wanted files, a plan made on the stick, or an adoption of a card (record 0005, rule 19). The partitions of AirgapOS are not touched; sector 0 of the stick gains the table entry of the extended partition (record 0005, rule 33).

**The run** is `ritueel apply PLAN`. It checks that the end of the history and the trust sequence still match those the plan was made against, and the person types the first eight characters of the plan's digest (record 0005, rule 13). When a plan is prepared online and the stick is present, ritueel refreshes the files partition first, and the plan records the digest of the program (record 0005, rule 32).

:::note[Proposed]
The names below are the smallest layout that serves the decision. They await the maintainer's word.

```text
RITUEEL/                          the files partition
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

- **`RITUEEL/`** is the files partition. AirgapOS's own partitions are not touched.
- **`ritueel/<version>/<system>-<arch>/ritueel`** holds the program, and nothing else, because it is one static file. The version comes first, so that the run can use the exact version that made the plan (record 0005, rule 35). The system and the architecture come second, so that several machines can use one stick.
- **`bundles/<name>/`** is a bundle copied without its wanted files, so the plan in its history and the bundle the plan was made from arrive together. It is a bundle that your workstation uses with `--dir`, with no second format.
- **`keys/<bundle>/`** holds the key files of that bundle. Key files are never inside a bundle, so a copy of a bundle cannot carry a key by accident. The folder has the name of the bundle.
- **The plan records the copy that made it** in the member `ritueel`: `{ "version", "os_arch", "sha256" }` ([the ceremony files](/reference/ceremony-record/)). The run is then `<stick>/ritueel/<version>/<system>-<arch>/ritueel --dir <stick>/bundles/acme apply history/<ceremony>/plan.json`.

The file system of the partition is exFAT ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 31). Not decided: the label of the partition, whether a checksum file sits beside each binary, and whether the `keys/` folder of a bundle may sit inside the parent of the bundle ([issue #30](https://github.com/truvity/ritueel/issues/30)).
:::

Not yet proven on hardware ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md); [issue #181](https://github.com/truvity/ritueel/issues/181) for the last two):

- that AirgapOS boots from a stick with such partitions and mounts the files partition;
- that a session of the offline system on real hardware makes the device nodes of both partitions and lets ritueel open the trace area as root (a virtual machine showed it);
- what Windows, macOS and a Linux desktop show for an extended partition that holds a partition with no file system.

## The wanted files

A person writes `ritueel.yaml` and one strict YAML file for each card, root and delegation. The user IDs of the OpenPGP root are a wanted file too; its shape is Proposed (below). A person writes them only on the workstation ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 5). `new` writes the starter files ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 20). `want` opens one in `$EDITOR` and writes only what the person saves ([Commands](/reference/cli/)).

- **Strict YAML** (record 0006, rule 5). What strict means is Proposed (below).
- **The digest** of a wanted file is the SHA-256 of the bytes as stored, so `sha256sum` gives the same value. The plan lists the wanted files it used by digest ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 7). Two files with one meaning have two digests. This is accepted (record 0005, rule 6).
- **The name** of an object is the name of its file without `.yaml`. A card's file is named by a name the holder gives, not by its serial (record 0006, rule 5).
- **A deleted line or file** retires, revokes and removes nothing, and `status` shows it as a finding. The history wins over a wanted file (record 0005, rule 5). The name of the finding is fixed with the code. A wanted file that fails its check stops `apply` before anything is written (record 0005, rule 19).

| File | One for each | Holds | Decided by |
|---|---|---|---|
| `ritueel.yaml` | bundle | The settings ([below](/reference/bundle/#ritueelyaml)). | [0006](../decisions/0006-bundle-history-and-trust-files.md) rule 5 |
| `want/cards/NAME.yaml` | card | The card's serial; its kind, which is `root`, `day-to-day`, `server` or `rehearsal` and never changes; the holder; and the rows of other bundles that the card declares. | [0003](../decisions/0003-root-cards.md) rules 5, 10 and 11 |
| `want/roots/NAME.yaml` | root | The kind of the root (X.509, OpenPGP or SSH CA); its keys, each with a label and a place (a card named by its card file, or a cloud key); for a key, what it replaces and until when, and an optional retire date with a reason; the revocation reasons to keep ready; and whether it is a test root. The number of keys in the file is the number of root keys wanted. A key listed with no history is born by `apply`. | [0007](../decisions/0007-changing-and-losing-a-root.md) rules 3, 5, 6, 10, 21 and 23; [0005](../decisions/0005-a-ceremony-and-where-it-runs.md) rules 4, 20 and 26 |
| `want/delegations/NAME.yaml` | delegation | The type (`x509-intermediate`, `openpgp-subkey` or `ssh-ca-key`), the root it is under, and its limits ([below](/reference/bundle/#a-delegation-file)). A delegation is a declared name under a root for a key that does daily work. | [0006](../decisions/0006-bundle-history-and-trust-files.md) rule 27; [0008](../decisions/0008-a-persons-own-key.md) rule 9 |
| `want/openpgp.yaml` | bundle | The user IDs of the OpenPGP root. | [0008](../decisions/0008-a-persons-own-key.md) rule 16 (that a person edits the user IDs; the file and its members are Proposed, [#18](https://github.com/truvity/ritueel/issues/18)) |

:::note[Proposed]
These parts are fixed with the code ([issue #8](https://github.com/truvity/ritueel/issues/8)): the members of the files in the table; what strict means (one document in a file, no anchors, no merge keys, no repeated keys, UTF-8 with LF, no byte order mark, no tags, no aliases, and an unknown key is an error); the form of an object name (lower-case letters, digits and hyphens, 1 to 63 characters).

The rules a request is checked against are split between `policy` in `ritueel.yaml` and each delegation's file ([issue #9](https://github.com/truvity/ritueel/issues/9)).

A card file never holds another bundle's name. A row of another bundle is declared as `use: other-bundle` with its row ([issue #11](https://github.com/truvity/ritueel/issues/11)).

Who owns a user ID of the OpenPGP root, whether the user IDs are one file for the root or one file for each object (the decision asks one file for each object), and how an old user ID is marked to retire, are open ([issue #18](https://github.com/truvity/ritueel/issues/18)). Where a test root is marked, for example in its wanted root file, and how a test bundle starts, is open ([issue #136](https://github.com/truvity/ritueel/issues/136)).
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
| `name` | 1 to 45 characters: the ASCII letters `A` to `Z` and `a` to `z`, the digits, single spaces and hyphens, with no space at the start or the end. It names the root keys and their primaries ([below](/reference/bundle/#the-root-certificate)). The limit of 45 keeps the common name of a root key within the 64 characters that RFC 5280 allows: the name, ` Root ` and the label add 7 characters, and a test root key adds ` (TEST ONLY)`, 12 more, so one number holds for both and a name that is too long fails early, when `ritueel.yaml` is read, and not at the ceremony. The characters are limited so that no letter of another script and no invisible character can make two names look alike. |
| `release_address` | Required in a company bundle, with or without an OpenPGP root. The address in every primary's user ID: the project's release identity, never a person's ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)). |
| `policy` | The rules every request is checked against: `stores`, `min_firmware`, `pin_policy`, `require_name_constraints` and `validity_months`, with the meanings of the [reference policy](/reference/hand-off-contract/#what-the-certifier-checks). All five are required. |
| `kind` | Optional. `personal` for a person's own OpenPGP key; absent for a company bundle. A personal bundle has `person` instead of `name` and `release_address` ([personal OpenPGP](/reference/personal-openpgp/)). |
| `person` | Only with `kind: personal`: `name` (1 to 64 characters) and `address`. |
| `aws_kms` | Optional, from M2; required when a root key's key store is `aws-kms`. The root account, the two Regions and the two roles ([the block](/reference/kms-root/#ritueelyaml)). |
| `keyring` | Proposed; no record has this member. `license` would be the SPDX identifier written into the `.rpm`, which the release pipeline builds ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rule 22): the holder's choice, which ritueel does not default ([the keyring package](/reference/keyring-package/)). |
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
        "ceremony_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" }
      }
    }
  }
}
```

Two rules the schema cannot state: the two Regions of `aws_kms` differ, and both its roles are in `account`. ritueel checks both when it reads the file.

### A delegation file

`want/delegations/NAME.yaml` declares one delegation: a declared name under a root for a key that does daily work ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 27). A request under no declared delegation is refused with the code `policy` ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 19). `NAME` is the `NAME` of the commands: lower-case letters, digits and hyphens, 1 to 63 characters.

```yaml
version: 1
type: x509-intermediate
root: acme-tls
permitted_uri_hosts: [example.com]
permitted_dns_names: [example.com]
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
| `permitted_uri_hosts` | For `x509-intermediate`: the URI constraints a request's name constraints may hold, each a host or a period and a domain, in the form of [the contract](/reference/hand-off-contract/#the-request). A permitted URI constraint is inside the policy only when it equals an entry. |
| `permitted_dns_names` | For `x509-intermediate`: the DNS names a request's name constraints may hold, each in the form of the contract. A permitted DNS name is inside the policy only when it equals an entry. **Not decided:** excluded DNS subtrees and excluded IP ranges, except every IP address, which the [hand-off contract](/reference/hand-off-contract/#what-the-certifier-checks) accepts in a request ([issue #9](https://github.com/truvity/ritueel/issues/9)). |
| `capability` | For `openpgp-subkey`: `sign` or `authenticate`, required. A request for another capability is refused with `policy`; the subkey is bound with this one's key flag ([the contract](/reference/hand-off-contract/#openpgp-subkey)). |
| `use` | For `ssh-ca-key`: `user` or `host`, required. A request for another `use` is refused with `policy`; the key is listed with this use ([the contract](/reference/hand-off-contract/#ssh-ca-key)). |
| `kms_read_roles` | For a requester's KMS key in another account: the read-only role to assume, by account ([the contract](/reference/hand-off-contract/#aws-kms)). The role is never taken from a request. |

A test vector's configuration in `testdata/hand-off/v1/manifest.json` is the `policy` block together with the one delegation's members its requests are for: the `permitted_uri_hosts`, `permitted_dns_names` and `kms_read_roles` there are that delegation's.

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
    "permitted_dns_names": { "type": "array", "uniqueItems": true, "items": { "type": "string" } },
    "kms_read_roles": { "type": "object", "propertyNames": { "pattern": "^[0-9]{12}$" },
                        "additionalProperties": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" } }
  }
}
```

Five rules the schema cannot state: a delegation name is unique, which its file name guarantees; a name that begins with `break-glass-` is refused, because the SSH CA key list uses those for the break-glass keys; an `x509-intermediate` has an entry in `permitted_uri_hosts` or in `permitted_dns_names` (at least one of the two) when `require_name_constraints` is true; an `openpgp-subkey` has `capability`; an `ssh-ca-key` has `use` and no other key of the type. A delegation under no root is an error. ritueel checks all of them when it reads the file.

## `root.json`

`roots/<label>/root.json` is one canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)). The ceremony that makes the key writes it once, and nothing changes it after ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31).

A key is active, retired or revoked ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 3); which one is read from the ceremony records and the newest root list, not from this file. What a key replaces, and until when, is a wanted field (record 0007, rules 3 and 5). Root state as files is later.

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `label` | The label of the root key: one upper-case letter, `A` for the first key and `B` for the second key when the first `apply` makes two keys, then the next free letter for each key added, whatever its key store. It never names the key store, is unique inside its bundle and is never reused. What a label names across roots is open ([issue #137](https://github.com/truvity/ritueel/issues/137)). |
| `store` | `software`, `piv` or `aws-kms`. |
| `test` | True for a test root key. Set at birth and never changed; a real root never becomes a test root ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 26). |
| `created_at` | When the key was made: the time of its ceremony. |
| `x509_spki_sha256` | The pin of the X.509 root key. |
| `openpgp_fingerprint` | The primary's fingerprint. Present when the bundle has an OpenPGP root. |
| `openpgp_created` | The OpenPGP creation time of the primary, which fixes its fingerprint and is on no card ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 10). Present with the fingerprint. |
| `revocations` | An object from reason (`compromised`, `superseded`, and any the holder added) to the SHA-256 of that revocation signature packet, which is stored elsewhere ([revocation material](/reference/revocation-material/)). |
| `removal_sha256` | The SHA-256 of the key's removal authorisation, which is stored elsewhere with the revocation signatures ([revocation material](/reference/revocation-material/#the-removal-authorisation)). Absent in a personal bundle. |
| `adopted` | True for an OpenPGP primary adopted as it was ([record 0008](../decisions/0008-a-persons-own-key.md)) or for a cloud key that ritueel adopted instead of creating ([record 0004](../decisions/0004-the-cloud-root.md)). Absent otherwise. |
| `store_ref` | For a key in `piv` (from M6) or `aws-kms` (from M2); absent for `software`. For `piv`: `{ "serial", "row" }`, the card's serial and the key's row in the [slot map](../decisions/0003-root-cards.md); the slots follow from the built-in map. For `aws-kms`: `{ "x509_arn", "openpgp_arn", "ssh_arn" }`, the ARNs of the primary keys, one for each kind of root the bundle uses ([the cloud root](/reference/kms-root/#what-ritueel-creates)). |
| `vouched_by`, `vouches` | For a key added by a transition, from M4: the digests of the two vouch files as first made ([the transitions page](/reference/transitions/#in-rootjson)). |

:::note[Proposed]
Revocation material that is made again later (record 0007, rule 23) cannot change this file. Where its digest is kept besides the ceremony record of the ceremony that made it is open ([issue #8](https://github.com/truvity/ritueel/issues/8)).
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
| Subject key identifier | Not critical. The leftmost 160 bits of the SHA-256 of the subject public key bits (RFC 7093, section 2, method 1), as in the [intermediate's profile](/reference/hand-off-contract/#what-is-issued). |
| Key usage | Critical. `keyCertSign` and `cRLSign`. |
| Name constraints | Absent: constraints belong to the intermediates. |
| Anything else | Absent, the authority key identifier included (RFC 5280, section 4.2.1.1, allows it in a self-signed certificate). |

The extensions stand in the certificate in the order of the table: basic constraints, subject key identifier, key usage. The order changes the bytes of the certificate, and it is the order of the test vectors.

**Each use re-issues it.** Every ceremony that signs with a root key makes a new certificate over the same key and the same subject, with a new serial, starting at the ceremony time ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 15). The new certificate is a new file in the trust set ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 12 and 31); the earlier trust set keeps the earlier one. A root key that is used every year or two therefore never comes close to its end, and pins on its key never change.

## The OpenPGP primary

Every root key's OpenPGP primary has this profile, as [record 0009](../decisions/0009-release-keys-and-the-keyring.md), rules 1, 2 and 4, decide.

| Part | Value |
|---|---|
| Key | Version 4, ECDSA on P-384 (algorithm 19). The creation time is `openpgp_created`. |
| User ID | One: `<name> Release Root <label> <release_address>`, for example `Example Release Root A <release@example.com>`. A test root key's adds ` (TEST ONLY)` before the address. No person's name. |
| Self-signature | A positive certification (type `0x13`) of the user ID, SHA-384. Hashed: signature creation time (the ceremony time), key flags `0x01` (certify only), key expiration time, marked critical, so that the key expires 36 calendar months after the ceremony, and the issuer fingerprint. Unhashed: the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). |
| Subkeys | None of its own. It binds the subkeys that a requester asks for through the hand-off. |
| Revocation | A key revocation signature (type `0x20`), made when the key is born and stored apart from it. |

**Each use extends it,** with a new self-signature of the same shape at the ceremony time. The new public certificate is a new file in the trust set.

The test roots of the [hand-off vectors](/reference/hand-off-contract/#test-vectors) follow both profiles, with the name `Example Test`.

## The software root's key files

A software root key ([the `software` store](../decisions/0002-where-a-key-lives.md)) serves tests, drills and development, and never anchors a signed release ([record 0002](../decisions/0002-where-a-key-lives.md), rules 7 and 8; [record 0009](../decisions/0009-release-keys-and-the-keyring.md)). Its private key is in a file in a **key directory**, given by `--key-dir DIR`, which ritueel refuses when it is inside the bundle ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), roads not taken: key files inside the bundle). Every command that writes a key file, and every ceremony record of a ceremony that uses one, says that a software root key can be copied (record 0005, rule 27).

| File | Content |
|---|---|
| `<label>.x509.key.age` | The X.509 root key: a PKCS#8 `PrivateKeyInfo` (RFC 5958), PEM-armoured as `PRIVATE KEY`, encrypted with age to the recipients below. |
| `<label>.openpgp.key.age` | The primary: a transferable secret key, binary (RFC 9580, section 10.2), version 4, whose secret key material is not protected inside (S2K usage 0) because age encrypts the whole file. |
| `<label>.revocation.<reason>.pgp.age` | The primary's revocation signature for one reason, `compromised` or `superseded` (or one the holder added), encrypted the same way. One file for each reason; the SHA-256 of the signature packet before encryption is the reason's entry in `revocations`. |
| `<label>.removal.jws.age` | The key's removal authorisation, encrypted the same way; the SHA-256 of the JWS text before encryption is `removal_sha256`. |

- **Encryption.** The age format (`age-encryption.org/v1`). By default a key file is encrypted to two recipients: the public half of an age key (the unlock key) and a recovery recipient. A passkey on each card named as a way to open the file (the root cards) unwraps the private half of the unlock key; any one of those cards is enough, and a file may name more than two; the recovery key is an age identity in a passphrase-protected file kept apart from the cards ([record 0002](../decisions/0002-where-a-key-lives.md), rules 19 to 21). Encrypting needs no card. The members that hold the wrapped private half of the unlock key, and the recovery file, are fixed with the passkey proof (M1), and are not written here before it.
- **A passphrase instead,** for a holder without cards: the age passphrase recipient, which derives the key with scrypt (record 0002, rule 22). A passphrase file holds only that recipient, because the age v1 specification says "An scrypt stanza, if present, MUST be the only stanza in the header" (read 2026-11-11, [age v1](https://age-encryption.org/v1)). The passphrase is read from the terminal without echo, or from `--passphrase-fd N`; it is never a flag, an environment variable or a line of output. A script root that is not a test root uses it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 27).
- **A test root** is marked at birth and has no passphrase ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 26). What follows about its key files is Proposed ([issue #136](https://github.com/truvity/ritueel/issues/136)). Its key files are written with no encryption: `<label>.x509.key.pem` with the line `TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root.` before the armour, `<label>.openpgp.key.asc` and `<label>.revocation.<reason>.asc`, ASCII-armoured with the header `Comment: TEST ONLY`, and `<label>.removal.jws`. The names of its keys carry ` (TEST ONLY)` too, and `apply` refuses to put a test root and a real root in one trust set.
- The holder keeps the revocation files and the removal authorisation apart from the key files, as for a card ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 23).

## Follow-ups

- The code that writes the wanted files, the card maps, the sealed files, the `attestation/` files and the `aws_kms` block ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)); their formats are on [the cards page](/reference/cards/) and [the cloud root page](/reference/kms-root/).
- The ceremony folder, and the commands that use the steps of a write ([issue #9](https://github.com/truvity/ritueel/issues/9)).
- The CRLs, the SSH CA key list and the keyring files in a trust set come with their builders ([issue #30](https://github.com/truvity/ritueel/issues/30), [issue #55](https://github.com/truvity/ritueel/issues/55), [issue #15](https://github.com/truvity/ritueel/issues/15)), in M4 (the CRLs and the SSH CA key list) and M5 (the keyring).

## Later

These are named and are not rules. Nothing on this page depends on them.

- A store of every old text of a wanted file ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), roads not taken). Until then the copies in each ceremony folder, and git, keep the old texts.
- A change over several files, written as one step.
- A decided repair of a fork ([issue #138](https://github.com/truvity/ritueel/issues/138)).
- The sealed single-file form of the history, for backups that reveal nothing ([the roadmap](/roadmap/#after-the-first-version)).
- Trust numbers that skip. Until then the number grows by one (record 0006, rule 14).
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
