---
title: Revocation material
description: The revocation signatures and removal authorisation made when a root is born, where they are written and refused, how to make and check one later.
sidebar:
  order: 12
---

*Not built yet. This is the page that [record 0007](../decisions/0007-changing-and-losing-a-root.md) leaves for the format and the commands; the code is [issue #69](https://github.com/truvity/ritueel/issues/69), in M2, with the roots of [issue #48](https://github.com/truvity/ritueel/issues/48). The ideas are taught in [Revoke](/learn/revoke/). The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

A revocation made after a primary key is lost cannot be made at all. So ritueel makes the revocation signatures when the key is born, for every OpenPGP primary key it creates: the primary of each root, and a person's own primary when personal OpenPGP is built (M3, [issue #18](https://github.com/truvity/ritueel/issues/18)). For the same reason every root also makes its **removal authorisation** at birth, which lets it leave the root set without signing ([below](/reference/revocation-material/#the-removal-authorisation)).

Revocation is covered with OpenPGP revocation signatures made in advance and kept apart, and with CRLs and root lists for X.509 ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 27).

## What is made

For each primary key, one **key revocation signature** (RFC 9580, section 5.2.1.11, type `0x20`) for each reason:

| Reason | Code | Made by default | What verifiers do with old signatures |
|---|---|---|---|
| Compromised | 2 | Yes | Distrust everything the key signed. |
| Superseded | 1 | Yes | Believe what was signed before the revocation. |
| Retired | 3 | `--reasons` | The same as superseded. |
| No reason | 0 | `--reasons` | Left to the verifier. |

`--reasons compromised,superseded,retired` chooses the set. The default set is two reasons because the event cannot be known at birth: a card that is lost and may be locked is not the same as a card that is stolen with its PIN, and a soft reason on a stolen key tells verifiers to believe a thief's backdated signatures ([Revoke](/learn/revoke/#reasons-matter)).

Each signature is version 4, SHA-384, over the primary's public key packet alone. Its hashed area holds the signature creation time (the ceremony time), the reason for revocation (the code and the word of the table), and the issuer fingerprint; its unhashed area holds the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). It is signed through the store that holds the primary, so a card key takes a touch: one for each reason, counted in the plan.

There is no designated revoker ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 20). RFC 9580 deprecates the mechanism.

## Where it is written

| Root's store | Where | Form |
|---|---|---|
| `piv`, `aws-kms`, and the `software` backends `onepassword` and `keyring` | The directory named by `--revocation-dir DIR`, required by every command that makes one. | One file for each reason, `<fingerprint>.<reason>.asc`: the signature packet, ASCII-armoured (RFC 9580, section 6.2), so it can be printed. Mode `0600`. |
| `software`, backend `file` | The key directory, with the key files ([the bundle](/reference/bundle/#the-software-roots-key-files)). | `<label>.revocation.<reason>.pgp.age`, encrypted like the key files; a test root writes `<label>.revocation.<reason>.asc`. |

ritueel refuses, with the code `revocation-dir`, a directory that:

- is inside the bundle (`--dir`), or inside the work tree of the repository that holds it;
- does not exist, or cannot be written;
- already holds a file of the same name (`revocation-exists`): a revocation signature is never overwritten.

It never prints a revocation signature to the terminal, the transcript, a log or the record, and it does not record the path, which means nothing on another machine. The holder stores the files apart from the cards, in at least two places ([The history](/learn/the-history/#what-else-must-be-backed-up-and-where)).

## What the bundle keeps

The **digest** of each signature: the SHA-256 of the binary signature packet, so that the armoured file, the encrypted file and the binary packet all check against it. At birth the digests are in `root.json` as `revocations`, an object from reason to digest, and in the record of the ceremony as a list of `{ "label", "reason", "sha256" }`. A signature made later by `revocation make` adds its entry to the record of that ceremony, and `status` and the drill read the full set from `root.json` and the records together.

`revocation_sha256` of the first version of [`root.json`](/reference/bundle/#rootjson) is replaced by `revocations`.

## The removal authorisation

Changing the root set requires every current root, or a root's stored removal authorisation ([the root list](/reference/root-list/#who-signs)). A root that is lost or destroyed cannot sign the list that removes it, so it signs its consent in advance: when it is born, at `init` or `root add`, its X.509 root key signs a statement over its own pin, in [the format of the root list page](/reference/root-list/#the-removal-authorisation). It has no reason, no sequence and no expiry. A personal bundle, which has no X.509 key and no root list, makes none.

It is revocation material, and is handled like a revocation signature:

| Root's store | Where | Form |
|---|---|---|
| `piv`, `aws-kms`, and the `software` backends `onepassword` and `keyring` | `--revocation-dir DIR`, with the revocation signatures. | `<x509_spki_sha256>.removal.jws`, the compact JWS as text. Mode `0600`. |
| `software`, backend `file` | The key directory. | `<label>.removal.jws.age`, encrypted like the key files; a test root writes `<label>.removal.jws`. |

The same refusals apply (`revocation-dir`, `revocation-exists`), it is never printed, and the holder stores it apart from the cards with the revocation signatures. The bundle keeps its digest, the SHA-256 of the JWS text, in `root.json` as `removal_sha256`, and the record of the ceremony lists it in `revocations` as `{ "label", "reason": "root-removal", "sha256" }`. Its signature is one of the plan's, of kind `root-removal`, and on a card it takes a touch.

`root revoke` attaches it to the list that removes the root, when the root does not sign that list itself ([root transitions](/reference/transitions/#root-revoke)). Anyone who holds it and the other roots can remove that root from the set, so it is kept with the same care as the revocation signatures.

## Making one later, and checking one

| Command | Does | Needs a person |
|---|---|---|
| `ritueel revocation make --root LABEL (--reason REASON \| --removal) --revocation-dir DIR` | A ceremony, with the plan, the confirmation and the record: signs one more revocation signature, or the removal authorisation again, while the root's key and its PIN still exist, and writes it as above. | Yes |
| `ritueel revocation check FILE [--root LABEL]` | Reads a stored file, armoured or binary, and prints only the verdict: well formed, type `0x20` and the reason, or a removal authorisation and its pin; the issuer; and whether its digest is the bundle's. It signs and writes nothing. | No |

`revocation check` exits 0 when the file is a revocation signature of a primary, or a removal authorisation of a root, in the bundle with the digest the bundle holds, and 3 with the code otherwise: `revocation-invalid` (not a revocation signature or removal authorisation, or one that does not verify), `revocation-mismatch` (a different digest), `reason-unknown`. A missing file is a refusal of the caller's, not a pass. The restore check runs it on every stored file ([drills](/reference/drill/#the-restore-check)).

## Using one

`root revoke` is the one command that uses stored material: it checks the revocation signature, and the removal authorisation when the root does not sign, as `revocation check` does, then publishes the signature and attaches the authorisation to the new root list ([root transitions](/reference/transitions/#root-revoke)). For a person's primary the guide is [Revoke a key](/guides/revoke-a-key/).

## Follow-ups

- The signing, the files, the refusals and `revocation make` and `check` ([issue #69](https://github.com/truvity/ritueel/issues/69)).
- The two reasons for the root primaries at `init` ([issue #48](https://github.com/truvity/ritueel/issues/48)).
- The removal authorisation at `init` and `root add`, with the root list that reads it ([issue #14](https://github.com/truvity/ritueel/issues/14), [issue #13](https://github.com/truvity/ritueel/issues/13)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The key revocation signature (sections 5.2.1.11 and 5.2.3.31), the escrowed revocation (section 13.9) and the armour (section 6.2). |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | The removal authorisation, a compact JWS. |
