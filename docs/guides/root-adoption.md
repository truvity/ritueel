---
title: Adopting the roots
description: The first ceremony that makes the roots, on two root cards or in a cloud account, and the adoption drill that must pass before a release is signed.
sidebar:
  order: 1
---

*Design phase: not built yet. This page is the plan that the first `ritueel apply` will follow, and the adoption drill that will rehearse it (M4, [issue #48](https://github.com/truvity/ritueel/issues/48)). No release is signed until the project's root has been adopted and the adoption drill has passed ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)). The adoption on a cloud root comes first (M4) and card roots follow the first signed release (M6); the [roadmap](/roadmap/) has the order.*

Adoption makes the real roots: on two dedicated root cards, or in one cloud root account. It runs once, and everything signed afterwards hangs from it, so it is rehearsed first.

## What you start with

- Two root cards that hold only root keys, each prepared as in [Prepare a root card](/guides/prepare-a-root-card/): its PIN set, and the card adopted by ritueel, which replaces the PUK and the management key and seals them in the bundle. The PINs are in your password manager, one entry per card.
- A machine to run ritueel on ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)): your workstation for a root on cards, under four conditions (a touch for every signature, the number of signatures stated in the plan, no retry of a failed touch, a check of the result on a second device); your workstation for a cloud root, under the last three, since a cloud key has no touch (the typed digest and the role session stand, and the audit trail records every signature); or the offline system, booted from a read-only system, which you may choose for a root on cards and must use for a key file; a cloud root always uses the workstation. The plan can be made anywhere and saved. A test root may use the workstation or a rehearsal card. A new bundle, made by `ritueel new`, that you keep in version control.
- Two places to keep the cards apart, and at least two places, apart from the cards, for the revocation signatures.

## Steps

1. **Run the adoption drill first, on software roots.** `ritueel new --test-root` (the spelling of `--test-root` is proposed) and the first `ritueel apply` in a scratch bundle, then the walk-through of [A lost root card](/guides/lost-root-card/), which is the adoption drill, on it. Result: you have seen every prompt, and the ceremony record says what a ceremony writes.
2. **Run the adoption drill on rehearsal cards.** The same, on two cards that will never hold a real root. Result: the card handling, the attestation check and the touch are known before they count.
3. **Create the roots.** The first `ritueel apply`, with both root cards present. Each card generates its X.509 root key, its OpenPGP primary and its break-glass SSH CA key in the PIV slots of the bundle's row. ritueel checks the attestation of each root key against the maker's root and stores it, with the public keys, in the bundle and the ceremony record, and each root key signs its first, empty [CRL](/reference/crl/). Result: keys A and B of each root, each provably born on its card.
4. **Store the revocation signatures.** The first `apply` writes two revocation signatures for each primary, one for *compromised* and one for *superseded*, and one removal authorisation for each root key, into the directory you named with `--revocation-dir`. Store each file apart from its card, in at least two places, and not in the bundle. Result: either primary can be revoked, for the right reason, and either root key can leave the root list without signing, even if its card and PIN are lost.
5. **Publish the first trust files.** The CA bundle, the signed root list, the SSH CA key list with the two break-glass keys, the CRLs and the keyring file, which ritueel makes from the bundle. Your pipeline packages the keyring and publishes everything. Result: outsiders can install the certificate of each root key.
6. **Put the cards in their two places,** and commit the bundle.

## How you know it worked

- `ritueel check history` passes, and the ceremony record of the first `apply` holds both attestations and the digests of both revocation signatures.
- `ritueel status` lists keys A and B of each root, each valid for about three years, and no unresolved attempt.
- The report of the adoption drill says how long each step took.

A company on a cloud key service prepares its account as in [Prepare the cloud root](/guides/prepare-the-cloud-root/), then runs the same steps against that account: one key for each kind of root the bundle uses (an X.509 root key, an OpenPGP primary, a break-glass SSH CA key), each a multi-Region key with a replica, made by ritueel or an existing key that ritueel adopts ([record 0004](../decisions/0004-the-cloud-root.md)), and the key's description and policy in place of an attestation.
