---
title: Ceremony plan, attempt, record and transcript, version 1
description: The files a ritueel ceremony writes, the plan and its digest, the attempt, the hash-chained record and the transcript, with their compatibility rule.
sidebar:
  order: 5
---

*Not built yet. This is version 1 of the files that the six steps of [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) write. The code is [issue #9](https://github.com/truvity/ritueel/issues/9), in M1; it follows this page.*

Every ceremony writes four kinds of file into [the directory](/reference/directory/#the-layout): a **plan** before anything is signed, an **attempt** just before the first signature, then a **record** and a **transcript** when it ends. They hold public material only: never a private key, a PIN, a passphrase or a revocation signature.

| File | Written at | Holds |
|---|---|---|
| `plans/<ceremony>.json` | Step 1, plan | Every byte that will be signed, fixed in advance. |
| `attempts/<ceremony>.json` | Step 3, reserve | That signatures may exist from this plan. |
| `records/<ceremony>.json` | Step 6, record | What was checked, signed and written. |
| `transcripts/<ceremony>.txt` | Step 6, record | What ritueel printed. |

`<ceremony>` is the ceremony's name: its time as `YYYYMMDDThhmmssZ` in UTC, a hyphen, and the command with its words joined by hyphens, for example `20261115T120000Z-intermediate-add`. The time is the plan's `ceremony_time`, or for a closing record of `records close`, which has no plan, the time it is written.

## Common rules

The three JSON files follow the JSON rules of the [hand-off contract](/reference/hand-off-contract/#messages-and-files): UTF-8 without a byte order mark, a member once, an unknown member is an error, integers only, times as `YYYY-MM-DDThh:mm:ssZ` in UTC, digests as SHA-256 in lower-case hexadecimal. ritueel writes them in the canonical form of RFC 8785, with no trailing newline, so a file's digest is the SHA-256 of its bytes and the same content gives the same digest on any machine. A reader verifies a digest over the bytes as stored and never re-serialises a file.

A **key fingerprint** in these files is the SHA-256 of the DER `SubjectPublicKeyInfo` for an X.509 key, and the version 4 fingerprint (40 hexadecimal digits) for an OpenPGP key, as in the contract.

## The plan

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony` | The ceremony's name. |
| `command` | The command, as typed: `init`, `intermediate add` and so on. |
| `arguments` | An object with every argument that changes what is signed: the intermediate's name, the request's stem, `--root` and its reason, `--allow-missing` names. Flags that change only how ritueel runs (`--output`, `--passphrase-fd`) are not in it. |
| `made_at` | When the plan was written. |
| `ceremony_time` | The time every signature carries and every validity starts from. Drawn once, here. |
| `inputs` | A list of `{ "path", "sha256" }`: every file of the directory the plan was made from, `ritueel.yaml` and the request files included, in path order. |
| `last_record_sha256` | The SHA-256 of the newest record in the directory, or absent when there is none. |
| `root` | The root that signs: `{ "label", "store", "x509", "openpgp", "test", "copyable" }`, with the two key fingerprints, `test` true for a test root, and `copyable` true for a software root. |
| `root_reason` | Present only when `--root` chose another root than the root of the year: the reason given. |
| `requests` | A list, one for each request the ceremony answers: `{ "stem", "type", "request_sha256", "proof_sha256", "store", "key" }`, where `key` is the fingerprint of the requester's key. |
| `signatures` | The ordered list of every signature the ceremony makes, below. |
| `births` | Only in a ceremony that makes keys: the keys to be born, below. |
| `touches` | The number of touches the holder will give: one for each signature by a card, 0 for a software root. |
| `base_sequence` | The trust sequence of the newest trust products when the plan was made, the state it was made against. |
| `trust_sequence` | The trust sequence of the trust products the ceremony writes: `base_sequence` plus one. |

Each member of `signatures`:

| Member | Meaning |
|---|---|
| `n` | Its place in the order, from 1. |
| `kind` | `intermediate-certificate`, `subkey-binding`, `root-certificate`, `primary-self-signature`, `primary-revocation` (at `init` and `root add`, and by `revocation make`; one for each reason, with a `reason` member), `cross-certificate` and `openpgp-vouch` (at `root add`), `root-list`, and from M2 and M3 `crl` and `ssh-ca-key-list`. |
| `key` | The fingerprint of the signing key: the root's X.509 key or its OpenPGP primary. |
| `subject` | What is signed for: the request's stem, or the root's label for the root's own certificate, self-signature, revocation, CRL, root list and SSH CA key list. |
| `reason` | For `primary-revocation`: `compromised`, `superseded`, `retired` or `no-reason`. |
| `serial` | For a certificate: the serial number, in lower-case hexadecimal, drawn here. |
| `not_before`, `not_after` | For a certificate or a binding: the validity it gives. |
| `tbs_sha256` | The SHA-256 of the exact bytes the key signs: the DER `TBSCertificate`, the OpenPGP data hashed for the signature (RFC 9580, section 5.2.4), the JWS signing input of the root list or of the SSH CA key list, or the DER `TBSCertList` of a CRL. |
| `derived` | True for a signature that covers a key born in this ceremony; it has no `tbs_sha256`, and no `key` when the new key signs itself ([below](/reference/ceremony-record/#the-plan)). Absent otherwise. |

`tbs_sha256` is what makes the plan exact: two machines that build the same plan from the same directory compute the same bytes to sign, and the verify step compares each artifact with it.

**A key that is born in the ceremony is the exception.** `init`, `root add` and `ssh-ca break-glass` make keys, and a signature that covers a new key (its root certificate, its primary's self-signature and revocation signatures, a vouching signature, a cross-certificate) cannot have its bytes fixed before the key exists. The plan lists such a signature with `derived` set to true and without `tbs_sha256` (and without `key` when the new key signs itself), and lists the keys to be born in `births`: for each, `{ "label", "purpose", "store", "place", "creation_time" }`, where `place` is the card's serial and slot, or the Region, and `creation_time` is the OpenPGP creation time drawn here. The verify step checks every derived artifact against the profile and the key that was born, with code that did not sign it, and the record carries the digests that the plan could not ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)).

### The plan digest and the confirmation

The **plan digest** is the SHA-256 of the bytes of the plan file, shown as 64 lower-case hexadecimal digits.

- **A person** sees the plan in words and its digest, and types **the first eight characters** of the digest. ritueel compares them with the digest's first eight, without regard to case. A key press is not accepted.
- **A script** passes `--confirm DIGEST` with all 64 digits, which it can only have by reading the plan ritueel wrote (`--plan-only --output json` prints it, see [Commands](/reference/cli/#machine-readable-output)).
- **A wrong or missing confirmation is refused before the attempt is written** (exit code 5). Nothing is signed and nothing is reserved.

`--plan FILE` runs from a plan made earlier. **A plan is bound to the state it was made against, not to a clock:** ritueel refuses it with the reason code `plan-stale` (exit code 3) when the newest trust sequence is no longer `base_sequence`, the newest record is no longer `last_record_sha256`, or any file of `inputs` has another digest. A plan that still matches runs however old it is, with its own `ceremony_time`. A confirmation never replaces a touch.

### Declining

A person who has read the plan may **decline** a request instead of confirming: by typing `decline` at the confirmation prompt, then a reason, or with `--decline REASON` and `--plan FILE` from a script. Declining is a deliberate act and is recorded: ritueel writes the answer `answers/<stem>.result.json` with `outcome` `refused` and the code `declined` ([the contract's check 10](/reference/hand-off-contract/#what-the-certifier-checks)), and a record with `outcome` `declined` that holds the reason. No attempt is written and nothing is signed; the exit code is 3. A wrong or missing confirmation is not a decline: it writes nothing and exits 5.

## The attempt

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony` | The ceremony's name. |
| `plan_sha256` | The plan digest. |
| `root` | The label of the root that signs. |
| `started_at` | When the attempt was written. |

ritueel creates the file only if it does not exist (exclusive create), writes it to disk, and only then makes the first birth or signature. An existing attempt for a plan means its serials may be used: ritueel refuses to run that plan again. An attempt is **resolved** when a record names its ceremony: the ceremony's own record, or a closing record from `records close`. `status` reports every unresolved attempt as **critical** (exit code 12): a reserved but unrecorded attempt may mean a signature that was made and never recorded.

### The birth journal

A ceremony that makes keys also creates `attempts/<ceremony>.births.jsonl`, with the attempt and before the first birth. After each key exists, and before the next birth begins, ritueel appends one line and syncs the file: `{ "at", "label", "purpose", "store", "place", "public_key_sha256" }`, where `place` is as in the plan with the key's ARN for KMS. The journal holds no secret. If the run stops, `records close` prints it, so that the holder can reset the card or the operator can schedule the key for deletion; ritueel does neither ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)). An attempt is resolved by a record, as before; the journal is not a second record.

## The record

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `ceremony`, `command`, `arguments` | As in the plan. |
| `outcome` | `completed`; `declined` when the person declined the request ([Declining](/reference/ceremony-record/#declining)); or `closed` for a closing record. |
| `plan_sha256` | The plan digest. Absent in a closing record, which has no plan of its own. |
| `prev_record_sha256` | The SHA-256 of the record before it in the chain. Absent in the first record of the directory, and only there. |
| `started_at`, `finished_at` | When the attempt was written, and when the record was. |
| `root`, `root_reason` | As in the plan. Absent in a closing record. |
| `slot_map_version` | For a root on a card: the version of the slot map ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards)). Absent for a software root. |
| `confirmation` | `{ "by", "at" }`: `typed` or `flag`, and when. |
| `limit_shown` | `init` only: true, because `init` prints the [accepted limit](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit). |
| `requests` | One for each request, below. |
| `signatures` | The plan's list, each with `signature_sha256`: the SHA-256 of the signature made. |
| `artifacts` | A list of `{ "path", "sha256" }`: every file the ceremony wrote other than the plan, the attempt, the record and the transcript, in path order. The trust products are among them. |
| `trust_sequence` | As in the plan. |
| `transcript_sha256` | The SHA-256 of the transcript. |
| `declined` | A declining record only: `{ "stem", "reason" }`, the request declined and the reason the person gave. Such a record has no `signatures`, and its `artifacts` are the refused answer. |
| `closes` | A closing record only: `{ "ceremony", "attempt_sha256", "reason" }`, the attempt it resolves, its digest, and the reason the person gave. |
| `revocations` | A ceremony that made revocation signatures: a list of `{ "label", "reason", "sha256" }`, the digest of each signature packet. The signatures themselves are never in the record ([revocation material](/reference/revocation-material/)). |
| `roots_target` | `init`, `root add`, `root retire` and `root revoke`: the number of active roots the holder intends after the ceremony ([root transitions](/reference/transitions/#the-target)). |

Each member of `requests` holds what the [hand-off contract records](/reference/hand-off-contract/#what-the-certifier-records): `stem`, `type`, `request_sha256`, `proof_sha256`, `store`, `key`, `evidence`, `policy`, `outcome` and `artifacts`.

- `evidence` holds what was read from the proof and checked. For a software key it is `{ "unprotected": true }`: the key proves nothing about where it lives. The members for `piv` (serial, firmware, PIN and touch policy, form factor, slot), `aws-kms` (the ARN, the key's description and the digest of its policy) and `openpgp-card` are fixed with those stores, in M2 and M4.
- `policy` is a copy of the policy applied to the request: the `policy` block of `ritueel.yaml` and the intermediate's entry ([the directory](/reference/directory/#ritueelyaml)).
- `outcome` is `issued`, and `artifacts` the answer's files with their digests, as in `result.json`; in a declining record, `outcome` is `refused` with the code `declined`.

### The hash chain

Records form one chain. The first record of a directory has no `prev_record_sha256`; every other names the record before it. `records verify` walks the chain from the first record and fails when:

- a record's `prev_record_sha256` is not the digest of a record, or two records name the same one;
- a file in `records/` is not on the chain;
- a record is not in canonical form, or its version is unknown;
- a transcript's digest is not the record's `transcript_sha256`;
- a trust product in `products/` is not an artifact of a record, which shows that the newest record was removed;
- the `last_record_sha256` of a root list in `products/` is not on the chain.

The records are not signed by a root. The digest of the newest record goes into the next signed root list ([the root list](/reference/root-list/#the-list)), which anchors the chain up to that ceremony without another use of the root.

## The transcript

`transcripts/<ceremony>.txt` is UTF-8 text with LF line endings: every line ritueel printed during the ceremony, on either stream, in order, without terminal control sequences. ritueel writes it itself; it is never a capture of the terminal, so it holds nothing the holder typed. It ends with the last line printed before the record is written; its SHA-256 is in the record.

## Versions and compatibility

- The plan, the attempt and the record each carry `version`. This page is version `1` of all three.
- A change to a member or a rule of any of them is a new version of that file. Adding a member is a change too, because a reader refuses an unknown member.
- **Records are never rewritten**, because a rewritten record breaks the chain. So a release of ritueel reads every record version that any earlier release wrote, and a reader that meets a version it does not know refuses it and names it, rather than skipping it.
- A plan or an attempt is read only by the release that wrote it, or a later one; a release refuses a plan of a version it does not write.

## Follow-ups

- The code that writes and checks these files, with the tests of issue #9's done-when ([issue #9](https://github.com/truvity/ritueel/issues/9)).
- The `evidence` members of the `piv` and `aws-kms` stores ([issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)), and of `openpgp-card` ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) | The canonical form of the plan, the attempt and the record. |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | `TBSCertificate`. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The data an OpenPGP signature hashes. |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | The JWS signing input of the root list. |
| [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) | Times. |
