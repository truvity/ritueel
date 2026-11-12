---
title: Recover
description: Recovering is what you do after a loss, a lost card, a forgotten PIN, a lost bundle or a locked account. What each loss costs and what each answer needs.
sidebar:
  order: 18
---

**Recovering is putting the chain right after a loss.** The loss may be a card, a PIN, the bundle, or access to a cloud account. The answer depends on what was lost and what you prepared.

## What was lost

| Lost | What it means | The answer | Needs |
|---|---|---|---|
| **One of two root cards** | The key on it can no longer sign. If the card was stolen with its PIN, it can sign for someone else. A pair shared by two bundles is lost for both: each bundle needs its own transition. | [Revoke](/learn/revoke/) it, publish trust files without it, add a replacement key, re-sign what chained only to it. | The other card; the stored revocation certificate. |
| **A card whose PIN is forgotten** | After three wrong tries it blocks; the PUK, which ritueel made and sealed in the bundle, unblocks it, and a full reset destroys the keys. | Treat it as a lost card. | The same. |
| **Both root cards** | No key can sign. | Start again with a new root, and persuade every client to trust it. A disaster you prepared for by keeping the cards in two places. | The backup of the bundle; a plan for the clients. |
| **The bundle** | The card files, attestations and the OpenPGP creation times, and the sealed secrets of the cards. | Restore it from its backup. | The [backup](/learn/the-history/). Without one, rebuild what the published certificates carry and accept the rest as lost. |
| **A revocation certificate** | The only way to revoke a primary key whose card is gone. | Make a new one now, while the card is still there. | The card and its PIN. |
| **A cloud root account** | The key is a permission, and the permission is gone. | Restore access through the provider; otherwise it is a lost root. | A replica in another Region covers a lost Region, not a lost account. |
| **A software key** | Depends on the store. | Restore from the store's own replication, if it has any. | See [where a key lives](/learn/key-stores/). |

## The same chain, whole again

Every recovery has the same shape:

1. **Contain.** If the key can be used by someone else, revoke it first.
2. **Rebuild redundancy.** Add a replacement key so there are two again.
3. **Re-sign.** What chained only to the lost key gets a certificate from the surviving key, over the same keys.
4. **Publish.** New trust files, after an overlap that your slowest client needs.
5. **Record.** What was done, with which keys.
6. **Practise.** Run the drill so the next recovery is not the first.

## Replacement, not copy

A card is never replaced by a copy of its key, because a card cannot be copied. A lost key is replaced by a new key, made on a new card, that the surviving key vouches for. That is the same transition as any other ([moving from one root to another](/learn/transitions/)), done in a hurry.

## In ritueel

The [guide for a lost root card](/guides/lost-root-card/) walks through it, and the [backup and restore guide](/guides/back-up-and-restore/) covers the bundle.
