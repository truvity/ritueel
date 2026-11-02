---
title: Adopting the roots
description: The first ceremony on the two root cards, with attestation and stored revocation signatures, and the drill that must pass before a release is signed.
sidebar:
  order: 1
---

*Design phase: not built yet. This page is the plan that `ritueel init` will follow, and the drill that will rehearse it ([issue #48](https://github.com/truvity/ritueel/issues/48)). No release is signed until both have run ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)). Adoption is the last item of M3, because it publishes the root list, the CA bundle and the keyring, and its drill walks through `root revoke` and `root add`; the [roadmap](/roadmap/) has the order.*

Adoption makes the real roots: on two dedicated root cards, or in one cloud root account. It runs once, and everything signed afterwards hangs from it, so it is rehearsed first.

## What you start with

- Two root cards that are used for nothing else, each prepared as in [Prepare a root card](/guides/prepare-a-root-card/): its PIN, PUK and management key changed from the defaults. The PINs are in your password manager, one entry per card.
- A workstation with ritueel, and an empty directory kept in version control.
- Two places to keep the cards apart, and a third for the revocation signatures.

## Steps

1. **Run the drill first, on software roots.** `ritueel init --test-root` in a scratch directory, then the [lost-card drill](/guides/lost-root-card/) on it. Result: you have seen every prompt, and the record says what a ceremony writes.
2. **Run the drill on test cards.** The same, on two cards that will never hold a real root. Result: the card handling, the attestation check and the touch are known before they count.
3. **Create the roots.** `ritueel init` with both root cards present. Each card generates its X.509 root, its OpenPGP primary and its break-glass SSH CA key in their PIV slots. ritueel checks the attestation of each root key against the maker's root and stores it, with the public keys, in the directory and the record, and each root signs its first, empty [CRL](/reference/crl/). Result: two roots, each provably born on its card.
4. **Store the revocation signatures.** `init` writes a revocation signature for each primary. Store each one apart from its card, and not in the directory. Result: either primary can be revoked even if its card and PIN are lost.
5. **Publish the first trust products.** The CA bundle, the signed root list, the SSH CA key list with the two break-glass keys, the CRLs and the keyring package, built from the directory. Your pipeline publishes them. Result: outsiders can install the two final roots.
6. **Put the cards in their two places,** and commit the directory.

## How you know it worked

- `ritueel records verify` passes, and the record of `init` holds both attestations and the digests of both revocation signatures.
- `ritueel status` lists two roots, each valid for about three years, and no unresolved attempt.
- The drill's record says how long each step of the lost-card walk-through took.

A company on a cloud key service prepares its account as in [Prepare the cloud root](/guides/prepare-the-cloud-root/), then runs the same steps against its dedicated root account: one X.509 root and one OpenPGP primary, each a multi-Region key with a replica, and the key's description and policy in place of an attestation.
