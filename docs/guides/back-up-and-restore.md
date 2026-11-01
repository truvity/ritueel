---
title: Back up and restore
description: Back up the ledger, the revocation certificates and the PINs, then prove it by restoring on a clean machine and comparing the result with the cards.
sidebar:
  order: 6
---

*Design phase: not built yet. The restore drill is planned as its own command. Read [The ledger](/learn/the-ledger/) first for what is kept, where, and why.*

## What you start with

- The ledger in its repository, with two remotes.
- The revocation certificates in their two places.
- The PINs in the password manager.
- A clean machine, or a freshly made user account.

## Back up

1. **Push the ledger** to both remotes, and check each shows the latest commit.
2. **Note the last digest** of the record chain apart from the repository.
3. **Check the revocation certificates:** both places hold them, and each digest equals the one in the ledger.
4. **Check the second card** is where you think it is.
5. **Check the PINs** are in the password manager, one entry per card.

## Restore, as a drill

1. **Clone the ledger** on the clean machine from the remote, and verify the signed commits.
2. **Verify the chain.** `ritueel records verify`, then compare the last digest with the note. Result: the history is whole.
3. **List the state.** `ritueel status`. Result: the roots, the intermediates and what expires when.
4. **Compare with the keys.** For each root, read the serial and fingerprint from the card or the cloud key and compare with the ledger. Result: the ledger describes the keys you hold.
5. **Walk through a loss.** Take one test card out of use and follow [A lost root card](/guides/lost-root-card/) with the stored revocation certificate.

## How you know it worked

Every comparison matches, and the walk-through ends with the checks of the lost-card guide. The drill's record says how long each step took.

Run this on test keys first, then once on the real ones, and then once a year.
