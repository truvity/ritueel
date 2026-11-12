---
title: "The ceremony folder: plan, attempt, journals, ceremony record and transcript, version 1"
description: The files of a ceremony folder: the plan, the attempt, the two journals, the ceremony record written last and the transcript, with their compatibility rule.
sidebar:
  order: 5
---

*Not built yet. This is version 1 of the files that the six steps of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md) write into a ceremony folder, under the rules of [record 0006](../decisions/0006-bundle-history-and-trust-files.md). Nothing reads them yet, so version 1 changes in place until the code does. The code is [issue #9](https://github.com/truvity/ritueel/issues/9), in M2; it follows this page.*

A cite such as (0005 rule 9) names the rule that decides the statement. A statement marked Proposed is not decided and names its open issue. What is later is listed at the end.

## The ceremony folder

Every ceremony leaves one **ceremony folder**, `history/<ceremony>/`, in the history of [the bundle](/reference/bundle/#the-layout) (0006 rule 5). The history is the write-once part of the bundle: a ceremony only adds files, and every name it writes carries its identity (0006 rule 29). The files hold public material only: never a private key, a PIN, a passphrase or a revocation signature (0006 rule 1).

| File | Written at | Holds | Decided by |
|---|---|---|---|
| `plan.json` | Step 1, plan | Every byte that will be signed, fixed in advance; what the plan applies and what it leaves out; the wanted files it used, by digest. | 0005 rule 4; 0006 rule 7 |
| `wanted/` | Step 1, plan | Exact copies of the wanted files the plan used. They are copies, not wanted files. | 0005 rules 4 and 21; 0006 rule 5 |
| `attempt.json` | Step 3, reserve | That keys or signatures may exist from this plan. | 0005 rule 7 |
| `births.jsonl` | Step 3, reserve | The birth journal. Only in a ceremony that makes keys. | 0005 rule 7 |
| `signatures.jsonl` | Step 3, reserve | The journal of signatures. | 0005 rule 7 |
| `transcript.txt` | Step 6, record | What ritueel printed. | 0006 rule 7 |
| `record.json` | Step 6, record, last | The ceremony record: what was checked, signed and written. | 0005 rule 9; 0006 rule 6 |

:::note[Proposed]
Of these names only the path `history/<ceremony>/plan.json` is decided (0006 rule 7). The other file names and the folder `wanted/` are fixed with the code ([#8](https://github.com/truvity/ritueel/issues/8)). The copies keep the paths they have in the bundle, under `wanted/`.
:::

`<ceremony>` is the name of the ceremony folder: its time as `YYYYMMDDThhmmssZ` in UTC, a hyphen, and the command, for example `20261120T100000Z-apply`. The time is the plan's `ceremony_time`, or for a closing record, which has no plan, the time it is written. The time is part of the identity of the name (0006 rule 29).

:::note[Proposed]
The name ends with a hyphen and the first eight characters of the plan digest, for example `20261120T100000Z-apply-3fa9c1d2`, so that two ceremonies of one second cannot meet on one name. A closing record has the first eight characters of the digest of the attempt it closes. Both are fixed with the code ([#8](https://github.com/truvity/ritueel/issues/8)).
:::

Two commands leave a ceremony folder: `apply`, with the plan, and `close`, with a closing record (0005 rules 7 and 10). `join` leaves none: it adds the ceremony folders of another copy as they are (0006 rules 30 and 31).

:::note[Proposed]
Whether `revoke` leaves a ceremony folder, a ceremony record and a printed end of the history is not decided ([#141](https://github.com/truvity/ritueel/issues/141)); it reads no plan. If it leaves no ceremony record, no ceremony record lists the trust set that it writes, and [the hash chain](/reference/ceremony-record/#the-hash-chain) check for such a trust set would report it. Whether an adoption of a card leaves a ceremony record of its own is not decided either ([#144](https://github.com/truvity/ritueel/issues/144)).
:::

## The order of writes

The steps of a write (whole or not at all, under a temporary name, then one rename) are on [the bundle page](/reference/bundle/#how-a-file-is-written) (0006 rule 29). A ceremony writes in this order:

| Step | Writes | Decided by |
|---|---|---|
| 1. Plan | The ceremony folder, `plan.json` and the copies in `wanted/`. With `--plan-only` ritueel stops here. | 0005 rules 4 and 10; 0006 rule 7 |
| 2. Confirm | Nothing. A wrong or missing confirmation writes nothing. | 0005 rule 6 |
| 3. Reserve | `attempt.json`, before the first key is born. The journals are created with it. | 0005 rule 7 |
| 4. Sign | One line in `births.jsonl` after each key exists and one line in `signatures.jsonl` after each signature is made. | 0005 rule 7 |
| 5. Verify | Nothing. Every artifact is checked against its request and the plan, with code that did not sign it, before it is written out. | 0005 rule 9 |
| 6. Record | `transcript.txt`, then the artifacts under names of their own (the trust set, the answers in `requests/`), and last `record.json`. | 0005 rule 9; 0006 rule 29 |

:::note[Proposed]
Rule 7 of record 0005 decides that an attempt is written before the first key and that each key and each signature is appended to a journal. That the attempt is made by an exclusive create, and that a journal grows by one flushed line at a time, is Proposed and is fixed with the code ([#8](https://github.com/truvity/ritueel/issues/8)).
:::

The ceremony record is the last file a ceremony writes, because it lists the others by digest. A ceremony folder with no ceremony record is a ceremony that has not ended.

## The states of a ceremony folder

A state is a fact on disk. The command `status ceremonies` and the History entry of [the local page](/reference/wizard/) show it.

| State | On disk | Fact decided by |
|---|---|---|
| planned | A plan and no attempt. Nothing was signed. | 0005 rule 7 |
| started | An attempt and no ceremony record. `status` reports it as critical (exit code 12) until a person closes it. | 0005 rule 7 |
| recorded | A ceremony record with the outcome `completed` or `declined`. | 0005 rule 9 |
| closed | A started ceremony that a closing record from `close` names. | 0005 rule 7 |

:::note[Proposed]
The facts are decided in the records of the last column. The names of the four states are Proposed ([#17](https://github.com/truvity/ritueel/issues/17)).
:::

## Common rules

The plan, the attempt and the ceremony record are JSON. They follow the JSON rules of the [hand-off contract](/reference/hand-off-contract/#messages-and-files): UTF-8 without a byte order mark, a member once, an unknown member is an error, integers only, times as `YYYY-MM-DDThh:mm:ssZ` in UTC, digests as SHA-256 in lower-case hexadecimal. ritueel writes them in the canonical form of RFC 8785, with no trailing newline, so a file's digest is the SHA-256 of its bytes and the same content gives the same digest on any machine. A reader verifies a digest over the bytes as stored and never re-serialises a file (0006 rule 11: everything the program writes is JSON or a standard format).

The copies in `wanted/` are strict YAML, as the person wrote them. Their digest is also over the stored bytes ([the wanted files](/reference/bundle/#the-wanted-files); 0005 rule 32).

A **key fingerprint** in these files is the SHA-256 of the DER `SubjectPublicKeyInfo` for an X.509 key, and the version 4 fingerprint (40 hexadecimal digits) for an OpenPGP key, as in the contract.

## The plan

The plan fixes every byte to be signed in advance: the root keys, each key's fingerprint and store, serials, times, the numbers of signatures and touches (0005 rule 4).

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony` | The ceremony's name. |
| `command` | `apply`. |
| `arguments` | An object with every argument that changes what is signed: the cards named with `--with` and, when a person names a card other than the card of the year, the reason given (0007 rule 14), and the names allowed by `--allow-missing` (0007 rule 17). What is wanted is in the wanted files, not in the arguments. Flags that change only how ritueel runs (`--plan-only`, `--confirm`, `--output`, `--passphrase-fd`) are not in it. The flag names are on [the commands page](/reference/cli/#commands). |
| `made_at` | When the plan was written. |
| `ritueel` | The copy of ritueel that made the plan: `{ "version", "os_arch", "sha256" }`. That the plan records the digest of the ritueel binary that made it, and that the run uses that version, is decided (0005 rules 22 and 25); the member name and its members are proposed. See the note below the table. |
| `ceremony_time` | The time every signature carries and every validity starts from. Drawn once, here (0005 rule 4). |
| `wanted` | A list of `{ "path", "sha256" }`: every wanted file the plan used, `ritueel.yaml` included, in path order. The digest is over the stored bytes (0005 rule 32). `wanted/` holds exact copies (0005 rule 4; 0006 rules 5 and 6). |
| `inputs` | A list of `{ "path", "sha256" }`: every other file the plan was made from, the request files among them, in path order. |
| `applies` | The changes the plan applies, each with its object. |
| `leaves_out` | The changes the plan leaves out, each with its object and the reason (0005 rule 4; 0007 rules 7 and 12). |
| `last_record_sha256` | The SHA-256 of the end of the history when the plan was made: the ceremony record that no other ceremony record names. Absent when there is none (0006 rule 6). The member name stays. |
| `root` | The root key that signs: `{ "label", "store", "x509", "openpgp", "test", "copyable" }`, with the two key fingerprints, `test` true for a test root (0005 rule 28) and `copyable` true for a key file (0005 rule 27). It is the key chosen to sign: the card of the year, or the card a person named. A signature by another key has its own `key`. The member name stays. |
| `root_reason` | Present only when a person named a card other than the card of the year: the reason given (0007 rule 14). |
| `requests` | A list, one for each request the ceremony answers: `{ "stem", "type", "request_sha256", "proof_sha256", "store", "key" }`, where `key` is the fingerprint of the requester's key. |
| `signatures` | The ordered list of every signature the ceremony makes, below. |
| `births` | Only in a ceremony that makes keys: the keys to be born, below. |
| `touches` | The number of touches the holder will give: one for each signature by a card, 0 for a key file or a cloud key (0005 rule 18). |
| `base_sequence` | The trust sequence of the newest trust set when the plan was made, the state it was made against. |
| `trust_sequence` | The trust sequence of the trust set the ceremony writes: `base_sequence` plus one (0006 rule 14). |

:::note[Proposed]
The member `ritueel` holds the version of the program that made the plan, its system and architecture as `os_arch`, and the SHA-256 of that copy. The run uses that version, and ritueel refuses to run the plan with another one. This is what lets the offline system keep several versions on the [USB stick](/reference/bundle/#on-the-stick). The names are a proposal, awaiting the maintainer's word.
:::

The members `wanted`, `applies` and `leaves_out` are new. That the plan lists the wanted files it used by digest, what it applies and what it leaves out with the reason is decided (0005 rule 4). The names of the three members, and of the members inside `applies` and `leaves_out` (an object and a change; a reason as text), are Proposed ([#8](https://github.com/truvity/ritueel/issues/8)).

Each member of `signatures`:

| Member | Meaning |
|---|---|
| `n` | Its place in the order, from 1. |
| `kind` | `intermediate-certificate`, `subkey-binding`, `root-certificate`, `primary-self-signature`, `primary-revocation` (at the birth of an OpenPGP primary, and again by `apply` for the reasons in the wanted root file; one for each reason, with a `reason` member: 0007 rules 20 and 22), `root-removal` (the removal authorisation, at the birth of a root key: 0007 rule 21), `cross-certificate` and `openpgp-vouch` (when a key is added: 0007 rule 6), `root-list`, and from M4 `crl` and `ssh-ca-key-list`. |
| `key` | The fingerprint of the signing key: the root key's X.509 key or its OpenPGP primary. |
| `subject` | What is signed for: the request's stem, or the root key's label for its own certificate, self-signature, revocation, CRL, root list and SSH CA key list. |
| `reason` | For `primary-revocation`: `compromised`, `superseded`, `retired` or `no-reason` (0007 rules 20 and 22). |
| `serial` | For a certificate: the serial number, in lower-case hexadecimal, drawn here. |
| `not_before`, `not_after` | For a certificate or a binding: the validity it gives. |
| `tbs_sha256` | The SHA-256 of the exact bytes the key signs: the DER `TBSCertificate`, the OpenPGP data hashed for the signature (RFC 9580, section 5.2.4), the JWS signing input of the root list (one for each root key that signs it) or of the SSH CA key list, or the DER `TBSCertList` of a CRL. |
| `derived` | True for a signature that covers a key born in this ceremony; it has no `tbs_sha256`, and no `key` when the new key signs itself ([below](/reference/ceremony-record/#the-plan)). Absent otherwise. |

`tbs_sha256` is what makes the plan exact: two machines that build the same plan from the same bundle compute the same bytes to sign, and the verify step compares each artifact with it.

**A key that is born in the ceremony is the exception** (0005 rule 5). The first `apply` and each added root key make keys, and a signature that covers a new key (its root certificate, its primary's self-signature and revocation signatures, a vouching signature, a cross-certificate) cannot have its bytes fixed before the key exists. The plan lists such a signature with `derived` set to true and without `tbs_sha256` (and without `key` when the new key signs itself), and lists the keys to be born in `births`: for each, `{ "label", "purpose", "store", "place", "creation_time" }`, where `place` is the card's serial and slot, or the Region, and `creation_time` is the OpenPGP creation time drawn here. The verify step checks every derived artifact against the profile and the key that was born, with code that did not sign it, and the ceremony record carries the digests that the plan could not. For such a key the plan fixes everything else (0005 rule 5): the store, the serial and slot or the Region, the algorithm, the OpenPGP creation time, the serials, the validity and the touches.

### The plan digest and the confirmation

The **plan digest** is the SHA-256 of the bytes of the plan file, shown as 64 lower-case hexadecimal digits.

- **A person** sees the plan in words and its digest, and types **the first eight characters** of the digest, and nothing more. ritueel compares them with the digest's first eight, without regard to case. A key press is not accepted (0005 rule 6).
- **A script** passes `--confirm DIGEST` with all 64 digits, which it can only have by reading the plan ritueel wrote (`--plan-only --output json` prints it, see [Commands](/reference/cli/#machine-readable-output)).
- **A wrong or missing confirmation is refused before the attempt is written** (exit code 5). Nothing is signed and nothing is reserved.

`ritueel apply PLAN` executes a plan made earlier (it asks for the first eight characters of the digest; `--confirm DIGEST` is the flag for scripts: 0005 rule 10). **A plan is bound to the state it was made against:** ritueel refuses it with the reason code `plan-stale` (exit code 3) when the newest trust sequence is no longer `base_sequence`, the end of the history is no longer `last_record_sha256`, or any file of `inputs` has another digest. The stick carries no wanted files (0005 rule 21), so on a stick only the end of the history and the trust sequence can be compared. A confirmation never replaces a touch.

:::note[Proposed]
What `apply PLAN` does when a wanted file changed after the plan was made, and an age limit of a plan, are not decided ([#142](https://github.com/truvity/ritueel/issues/142)). A flag `--only` that a script must pass to confirm is not decided either ([#143](https://github.com/truvity/ritueel/issues/143)). None of the three is a rule.
:::

### Declining

A person who has read the plan may **decline** a request instead of confirming: by typing `decline` at the confirmation prompt, then a reason, or with `--decline REASON` and `apply PLAN` from a script (the flag name is proposed on [the commands page](/reference/cli/#commands)). Declining is a deliberate act and is recorded: ritueel writes the answer `<stem>.result.json` beside the request in `requests/<stem>/` with `outcome` `refused` and the code `declined` ([the contract's check 10](/reference/hand-off-contract/#what-the-certifier-checks)), and a ceremony record with `outcome` `declined` that holds the reason. No attempt is written and nothing is signed; the exit code is 3. A wrong or missing confirmation is not a decline: it writes nothing and exits 5.

## The attempt

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony` | The ceremony's name. |
| `plan_sha256` | The plan digest. |
| `root` | The label of the root key that signs. |
| `started_at` | When the attempt was written. |

ritueel writes the file first, and only then makes the first birth or signature (0005 rule 7). An existing attempt for a plan means its serials may be used: ritueel refuses to run that plan again. An attempt is **resolved** when a ceremony record names its ceremony: the ceremony's own record, or a closing record from `close`. `status` reports every unresolved attempt as **critical** (exit code 12): a reserved but unrecorded attempt may mean a signature that was made and never recorded.

:::note[Proposed]
Whether `apply` refuses to make a new plan while an attempt is open, or only refuses to run the plan that has the attempt, is not decided ([#140](https://github.com/truvity/ritueel/issues/140)). This page says the second.
:::

### The birth journal

A ceremony that makes keys also creates `births.jsonl`, with the attempt and before the first birth (0005 rule 7). After each key exists, and before the next birth begins, ritueel appends one line (0005 rule 7): `{ "at", "label", "purpose", "store", "place", "public_key_sha256" }`, where `place` is as in the plan with the key's ARN for KMS. The journal holds no secret. If the run stops, `close` prints it, so that the holder can delete the slot of the half-born key (that deleting one slot works on firmware 5.7.4 is tried on a rehearsal card in M1; a card that holds roots is never reset: [record 0003](../decisions/0003-root-cards.md), rule 11) or schedule the key for deletion; ritueel does neither ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 7; [record 0004](../decisions/0004-the-cloud-root.md), rule 11). An attempt is resolved by a ceremony record, as before; the journal is not a second record.

### The journal of signatures

A ceremony that signs also creates `signatures.jsonl`, with the attempt and before the first signature (0005 rule 7). After each signature is made, and before the next begins, ritueel appends one line (0005 rule 7). The journal holds no secret. `close` prints it with the birth journal.

:::note[Proposed]
The name `signatures.jsonl` and the members of a line are fixed with the code ([#8](https://github.com/truvity/ritueel/issues/8)). The proposal: `{ "at", "n", "kind", "key", "signature_sha256" }`, where `n` is the place in the plan's `signatures`. Whether a line holds the signature itself is open. A line is whole when it ends with a newline. A last line without its newline does not parse and counts as not written, but it may mean that a key or a signature exists; so may a missing line, when the run stopped between making it and writing the line.
:::

## The record

The ceremony record is the file `record.json`, written last in its ceremony folder (0006 rule 6). It holds no secret. It says what was done, with which keys, on which store, what outsiders see and where it ran (0005 rule 2). Its members are the time in UTC, the command, the plan digest, the wanted files and the artifacts with their digests, the keys and stores, the evidence checked, the policy applied, the slot map version and the confirmation (0006 rule 6). The table gives each.

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony`, `command`, `arguments` | As in the plan. `command` is `apply`, or `close` for a closing record. |
| `outcome` | `completed`; `declined` when the person declined the request ([Declining](/reference/ceremony-record/#declining)); or `closed` for a closing record. |
| `plan_sha256` | The plan digest. Absent in a closing record, which has no plan of its own. |
| `prev_record_sha256` | The SHA-256 of the ceremony record before it in the chain. Absent in the first ceremony record of the bundle, and only there (0006 rule 6). |
| `started_at`, `finished_at` | When the attempt was written, and when the ceremony record was. |
| `root`, `root_reason` | As in the plan. Absent in a closing record. |
| `slot_map_version` | For a root key on a card: the version of the slot map ([record 0003](../decisions/0003-root-cards.md), rule 4). Absent for a key file or a cloud key. |
| `confirmation` | `{ "by", "at" }`: `typed` or `flag`, and when (0005 rule 6). |
| `ran_on` | Proposed. Where the ceremony ran: `workstation` or `offline-system`. Every ceremony record says it (0005 rule 2); the name and the two values are proposed. Whether a second-device check was declared, and what was compared, is open ([#30](https://github.com/truvity/ritueel/issues/30)). |
| `limit_shown` | The first `apply` only: true, because it prints the [accepted limit](../decisions/0005-a-ceremony-and-where-it-runs.md) (0005 rule 15). |
| `requests` | One for each request, below. |
| `wanted` | The plan's list of wanted files, by digest (0006 rule 6). |
| `applied` | The changes the ceremony applied, as `applies` in the plan. |
| `left_out` | The changes the ceremony left out, each with the reason, as `leaves_out` in the plan. |
| `signatures` | The plan's list, each with `signature_sha256`: the SHA-256 of the signature made. |
| `artifacts` | A list of `{ "path", "sha256" }`: every file the ceremony wrote other than the plan, the copies of the wanted files, the attempt, the two journals, the transcript and the ceremony record itself, in path order. The trust set is among them. |
| `trust_sequence` | As in the plan. |
| `transcript_sha256` | The SHA-256 of the transcript. |
| `advisory_review` | An `apply` that renews: `{ "at", "note" }`, the holder's answer that they reviewed the advisories for the cards, services and algorithms in use, and a short note of what they read. ritueel asks and records; it does not judge the answer ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 18). |
| `declined` | A declining record only: `{ "stem", "reason" }`, the request declined and the reason the person gave. Such a ceremony record has no `signatures`, and its `artifacts` are the refused answer. |
| `closes` | A closing record only: `{ "ceremony", "attempt_sha256", "reason" }`, the attempt it resolves, its digest, and the reason the person gave. |
| `revocations` | A ceremony that made revocation material: a list of `{ "label", "reason", "sha256" }`, the digest of each signature packet, and of each removal authorisation with the reason `root-removal`. The material itself is never in the ceremony record (0007 rule 22; [revocation material](/reference/revocation-material/)). |

The members `wanted`, `applied` and `left_out` are new. That the ceremony record lists the wanted files and the artifacts by digest is decided (0006 rule 6; 0005 rule 4). The names of the three members are Proposed ([#8](https://github.com/truvity/ritueel/issues/8)). A key's state (active, retired or revoked: 0007 rule 3) is read from the ceremony records and the newest root list; no member holds it. The member `roots_target` is not in version 1: the number of keys wanted is the number in the wanted root file (0007 rule 5).

Each member of `requests` holds what the [hand-off contract records](/reference/hand-off-contract/#what-the-certifier-records): `stem`, `type`, `request_sha256`, `proof_sha256`, `store`, `key`, `evidence`, `policy`, `outcome` and `artifacts`.

- `evidence` holds what was read from the proof and checked. For a key file it is `{ "unprotected": true }`: the key proves nothing about where it lives. The members for `piv` (serial, firmware, PIN and touch policy, form factor, slot), `aws-kms` (the ARN, the key's description and the digest of its policy) and `openpgp-card` are fixed with those stores: `aws-kms` in M2, `openpgp-card` in M3 and `piv` in M6.
- `policy` is a copy of the policy applied to the request: the `policy` block of `ritueel.yaml` and the wanted file of the delegation ([the bundle](/reference/bundle/#ritueelyaml)).
- `outcome` is `issued`, and `artifacts` the answer's files with their digests, as in `result.json`; in a declining record, `outcome` is `refused` with the code `declined`.

### The hash chain

Ceremony records form one chain (0006 rule 6). The first ceremony record of a bundle has no `prev_record_sha256`; every other names the one before it, so each ceremony folder names the one before it. `check history` walks the chain from the first ceremony record and reports:

- a ceremony record's `prev_record_sha256` that is not the digest of a ceremony record;
- two ceremony records that name the same one. That is a fork, a critical finding (0006 rule 30). Its repair is not decided ([#138](https://github.com/truvity/ritueel/issues/138));
- a `record.json` in a ceremony folder of `history/` that is not on the chain;
- a ceremony record that is not in canonical form, or whose version is unknown;
- a transcript whose digest is not the `transcript_sha256` of its ceremony record;
- a trust set in `trust/` that is not an artifact of a ceremony record, which shows that the newest ceremony record was removed;
- the `last_record_sha256` of a root list in `trust/` that is not on the chain;
- **a file that a ceremony record lists and that fails its digest.** It is an error, never "absent" (0006 rule 29). The files checked are the copies in `wanted/` and the artifacts. A wanted file in `want/` may have changed since, because a person writes it.

The ceremony records are not signed by a root. The digest of the end of the history goes into the next signed root list ([the root list](/reference/root-list/#the-list)), which anchors the chain up to that ceremony without another use of the root (0006 rule 6). After every ceremony and every join, ritueel prints the first eight characters of that digest and the count of ceremony records (0006 rule 9; [the end of the history](/reference/bundle/#the-end-of-the-history)).

## The transcript

`history/<ceremony>/transcript.txt` is UTF-8 text with LF line endings: every line ritueel printed during the ceremony, on either stream, in order, without terminal control sequences. ritueel writes it itself; it is never a capture of the terminal, so it holds nothing the holder typed (0006 rule 7). It ends with the last line printed before the ceremony record is written; its SHA-256 is in the ceremony record.

## What other records put in a ceremony record

A record that decides a field of the ceremony record is named here. A list of fields that a record leaves to a reference page lands in this table, with the rule that decides it.

| Record and rule | What the ceremony record carries | Member |
|---|---|---|
| 0002 rule 6; 0005 rule 27; 0008 rule 6 | That a key file can be copied. | `root.copyable` |
| 0003 rule 4 | The version of the slot map. | `slot_map_version` |
| 0003 rule 7 | The serial of a card, never the name of another bundle. | `evidence`, fixed with the stores |
| 0004 rule 8 | The key ARN and the digest of the key policy of a cloud key. The role session of the ceremony role is also in the ceremony record. | `evidence`; the member for the role session is fixed with the cloud store ([#12](https://github.com/truvity/ritueel/issues/12)) |
| 0005 rule 2 | Where the ceremony ran. | `ran_on` (proposed) |
| 0005 rule 15 | That the accepted limit was shown. | `limit_shown` |
| 0005 rule 28 | That a root is a test root (TEST ONLY). | `root.test` |
| 0007 rule 18 | That the holder reviewed the advisories. | `advisory_review` |
| 0007 rule 22 | The digest and the reason of each revocation signature, never the signature. | `revocations` |
| 0002 rule 10 | A warning that the OS keyring backend can be insecure and has no copy. | Not fixed; with the keyring store ([#60](https://github.com/truvity/ritueel/issues/60)) |

## Versions and compatibility

- The plan, the attempt and the ceremony record each carry `version`. This page is version `1` of all three. The journals and the copies of the wanted files carry none.
- A change to a member or a rule of any of the three is a new version of that file. Adding a member is a change too, because a reader refuses an unknown member.
- **Ceremony records are never rewritten**, because a rewritten ceremony record breaks the chain. So a release of ritueel reads every ceremony record version that any earlier release wrote, and a reader that meets a version it does not know refuses it and names it, rather than skipping it.
- A plan or an attempt is read only by the release that wrote it, or a later one; a release refuses a plan of a version it does not write.

## Later

These are later. They are not rules, and this page does not write them.

- A store of every old text of a wanted file. Until then the copies in each ceremony folder and git keep the old texts.
- Change sets over several files.
- A decided repair of a fork ([#138](https://github.com/truvity/ritueel/issues/138)).
- The sealed single-file export of a bundle, for backups.
- Trust numbers that skip.
- The state of a root key as files. Until then it is read from the ceremony records and the newest root list.

## Follow-ups

- The code that writes and checks these files, with the tests of issue #9's done-when ([issue #9](https://github.com/truvity/ritueel/issues/9)): the steps of a write, the plan, the two journals and `check history`.
- The `evidence` members of the `piv` and `aws-kms` stores ([issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)), and of `openpgp-card` ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) | The canonical form of the plan, the attempt and the ceremony record. |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | `TBSCertificate`. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The data an OpenPGP signature hashes. |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | The JWS signing input of the root list. |
| [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) | Times. |
