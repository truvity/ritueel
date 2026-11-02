---
title: Revocation material for OpenPGP master keys
description: The revocation signatures made when a master key is born, where they are written and refused, how to make and check one later, and what the ledger keeps.
sidebar:
  order: 12
---

*Not built yet. This is the page that [ADR 0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/#revocation-material) leaves for the format and the commands; the code is [issue #69](https://github.com/truvity/ritueel/issues/69), in M3, with the roots of [issue #48](https://github.com/truvity/ritueel/issues/48). The ideas are taught in [Revoke](/learn/revoke/).*

A revocation made after a master key is lost cannot be made at all. So ritueel makes the revocation signatures when the key is born, for every OpenPGP master key it creates: the primary of each root, and a person's own primary when personal OpenPGP is built (M4, [issue #18](https://github.com/truvity/ritueel/issues/18)).

## What is made

For each master key, one **key revocation signature** (RFC 9580, section 5.2.1.11, type `0x20`) for each reason:

| Reason | Code | Made by default | What verifiers do with old signatures |
|---|---|---|---|
| Compromised | 2 | Yes | Distrust everything the key signed. |
| Superseded | 1 | Yes | Believe what was signed before the revocation. |
| Retired | 3 | `--reasons` | The same as superseded. |
| No reason | 0 | `--reasons` | Left to the verifier. |

`--reasons compromised,superseded,retired` chooses the set. The default set is two reasons because the event cannot be known at birth: a card that is lost and may be locked is not the same as a card that is stolen with its PIN, and a soft reason on a stolen key tells verifiers to believe a thief's backdated signatures ([Revoke](/learn/revoke/#reasons-matter)).

Each signature is version 4, SHA-384, over the primary's public key packet alone. Its hashed area holds the signature creation time (the ceremony time), the reason for revocation (the code and the word of the table), and the issuer fingerprint; its unhashed area holds the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). It is signed through the store that holds the primary, so a card key takes a touch: one for each reason, counted in the plan.

There is no designated revoker: RFC 9580 deprecates the mechanism ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#revocation-readiness)).

## Where it is written

| Root's store | Where | Form |
|---|---|---|
| `piv`, `aws-kms`, and the `software` backends `onepassword` and `keyring` | The directory named by `--revocation-dir DIR`, required by every command that makes one. | One file for each reason, `<fingerprint>.<reason>.asc`: the signature packet, ASCII-armoured (RFC 9580, section 6.2), so it can be printed. Mode `0600`. |
| `software`, backend `file` | The key directory, with the key files ([the directory](/reference/directory/#the-software-roots-key-files)). | `<label>.revocation.<reason>.pgp.age`, encrypted like the key files; a test root writes `<label>.revocation.<reason>.asc`. |

ritueel refuses, with the code `revocation-dir`, a directory that:

- is inside the ledger directory (`--dir`), or inside the work tree of the repository that holds it;
- does not exist, or cannot be written;
- already holds a file of the same name (`revocation-exists`): a revocation signature is never overwritten.

It never prints a revocation signature to the terminal, the transcript, a log or the record, and it does not record the path, which means nothing on another machine. The holder stores the files apart from the cards, in at least two places ([The ledger](/learn/the-ledger/#what-else-must-be-backed-up-and-where)).

## What the ledger keeps

The **digest** of each signature: the SHA-256 of the binary signature packet, so that the armoured file, the encrypted file and the binary packet all check against it. At birth the digests are in `root.json` as `revocations`, an object from reason to digest, and in the record of the ceremony as a list of `{ "label", "reason", "sha256" }`. A signature made later by `revocation make` adds its entry to the record of that ceremony, and `status` and the drill read the full set from `root.json` and the records together.

`revocation_sha256` of the first version of [`root.json`](/reference/directory/#rootjson) is replaced by `revocations`.

## Making one later, and checking one

| Command | Does | Needs a person |
|---|---|---|
| `ritueel revocation make --root LABEL --reason REASON --revocation-dir DIR` | A ceremony, with the plan, the confirmation and the record: signs one more revocation signature while the primary and its PIN still exist, and writes it as above. | Yes |
| `ritueel revocation check FILE [--root LABEL]` | Reads a stored file, armoured or binary, and prints only the verdict: well formed, type `0x20`, the reason, the issuer, and whether its digest is the ledger's. It signs and writes nothing. | No |

`revocation check` exits 0 when the file is a revocation signature of a primary in the directory with the digest the ledger holds, and 3 with the code otherwise: `revocation-invalid` (not a revocation signature, or one that does not verify over the primary), `revocation-mismatch` (a different digest), `reason-unknown`. A missing file is a refusal of the caller's, not a pass.

## Using one

`root revoke` is the one command that uses a stored signature: it checks the file as `revocation check` does, then publishes it ([root transitions](/reference/transitions/#root-revoke)). For a person's primary the guide is [Revoke a key](/guides/revoke-a-key/).

## Follow-ups

- The signing, the files, the refusals and `revocation make` and `check` ([issue #69](https://github.com/truvity/ritueel/issues/69)).
- The two reasons for the root primaries at `init` ([issue #48](https://github.com/truvity/ritueel/issues/48)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The key revocation signature (sections 5.2.1.11 and 5.2.3.31), the escrowed revocation (section 13.9) and the armour (section 6.2). |
