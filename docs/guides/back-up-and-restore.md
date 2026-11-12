---
title: Back up and restore
description: Back up the bundle, the revocation certificates and the PINs, then prove it by restoring on a clean machine and comparing the result with the cards.
sidebar:
  order: 6
---

*Design phase: not built yet. The restore check is planned as the command `ritueel check restore`. Read [The history](/learn/the-history/) first for what is kept, where, and why.*

## What you start with

- The bundle in its repository, with two remotes. Its history is the write-once part.
- The revocation certificates in their two places.
- The PINs you type in the password manager.
- The recovery key, apart from the cards and apart from its passphrase ([record 0002](../decisions/0002-where-a-key-lives.md)). The sealed secrets of the cards are in the bundle; the PUK and the management key are not kept by hand ([record 0003](../decisions/0003-root-cards.md)).
- A clean machine, or a freshly made user account.

## Back up

1. **Push the bundle** to both remotes, and check each shows the latest commit.
2. **Note the end of the history** that ritueel printed, apart from the repository.
3. **Check the revocation certificates:** both places hold them, and each digest equals the one in the bundle.
4. **Check the second card** is where you think it is.
5. **Check the PINs** are in the password manager, one entry per card, and that the recovery key and its passphrase are in two different places.

## Restore, as a drill

0. **Run the check.** `ritueel check restore --expect-last DIGEST --allowed-signers FILE --revocation-dir DIR` does steps 1 to 4 below, compares the stored revocation signatures with their digests, and writes a report ([the check](/reference/drill/#the-restore-check)). The steps say what it does, so you can do each by hand once.
1. **Clone the bundle** on the clean machine from the remote, and verify the signed commits.
2. **Verify the chain.** `ritueel check history`, then compare the end of the history with the note. Result: the history is whole.
3. **List the state.** `ritueel status`. Result: the roots, the intermediates and what expires when.
4. **Compare with the keys.** For each root key, read the serial and fingerprint from the card or the cloud key and compare with the bundle. Result: the bundle describes the keys you hold.
5. **Walk through a loss.** Take one rehearsal card out of use and follow [A lost root card](/guides/lost-root-card/) with the stored revocation certificate.

## How you know it worked

Every comparison matches, and the walk-through ends with the checks of the lost-card guide. The drill's report says how long each step took.

Run this on test keys first, then once on the real ones, and then once a year.
