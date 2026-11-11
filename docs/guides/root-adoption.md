---
title: Adopting the roots
description: The first ceremony that makes the roots, on two root cards or in a cloud account, and the drill that must pass before a release is signed.
sidebar:
  order: 1
---

*Design phase: not built yet. This page is the plan that `ritueel init` will follow, and the drill that will rehearse it ([issue #48](https://github.com/truvity/ritueel/issues/48)). No release is signed until the project's root has been adopted and the drill has passed ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)). The adoption on a cloud root comes first (M4) and card roots follow the first signed release (M6); the [roadmap](/roadmap/) has the order.*

Adoption makes the real roots: on two dedicated root cards, or in one cloud root account. It runs once, and everything signed afterwards hangs from it, so it is rehearsed first.

## What you start with

- Two root cards that hold only roots, each prepared as in [Prepare a root card](/guides/prepare-a-root-card/): its PIN set, and the card adopted by ritueel, which replaces the PUK and the management key and seals them in the directory. The PINs are in your password manager, one entry per card.
- A machine booted from the read-only offline system, with ritueel ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-plan-runs)); the plan can be made anywhere and saved. For a cloud root, a workstation is enough, and a test root may use the workstation or a rehearsal card. An empty directory, advised to be kept in version control.
- Two places to keep the cards apart, and a third for the revocation signatures.

## Steps

1. **Run the drill first, on software roots.** `ritueel init --test-root` in a scratch directory, then the [lost-card drill](/guides/lost-root-card/) on it. Result: you have seen every prompt, and the record says what a ceremony writes.
2. **Run the drill on rehearsal cards.** The same, on two cards that will never hold a real root. Result: the card handling, the attestation check and the touch are known before they count.
3. **Create the roots.** `ritueel init` with both root cards present. Each card generates its X.509 root, its OpenPGP primary and its break-glass SSH CA key in the PIV slots of the root's row. ritueel checks the attestation of each root key against the maker's root and stores it, with the public keys, in the directory and the record, and each root signs its first, empty [CRL](/reference/crl/). Result: two roots, each provably born on its card.
4. **Store the revocation signatures.** `init` writes two revocation signatures for each primary, one for *compromised* and one for *superseded*, into the directory you named with `--revocation-dir`. Store each file apart from its card, in at least two places, and not in the directory. Result: either primary can be revoked, for the right reason, even if its card and PIN are lost.
5. **Publish the first trust products.** The CA bundle, the signed root list, the SSH CA key list with the two break-glass keys, the CRLs and the keyring package, built from the directory. Your pipeline publishes them. Result: outsiders can install the two final roots.
6. **Put the cards in their two places,** and commit the directory.

## How you know it worked

- `ritueel records verify` passes, and the record of `init` holds both attestations and the digests of both revocation signatures.
- `ritueel status` lists two roots, each valid for about three years, and no unresolved attempt.
- The drill's record says how long each step of the lost-card walk-through took.

A company on a cloud key service prepares its account as in [Prepare the cloud root](/guides/prepare-the-cloud-root/), then runs the same steps against its dedicated root account: one X.509 root and one OpenPGP primary, each a multi-Region key with a replica, made by ritueel or an existing key that ritueel adopts ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/)), and the key's description and policy in place of an attestation.
