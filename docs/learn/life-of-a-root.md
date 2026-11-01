---
title: The life of a root
description: A root from birth to recovery in order. Create, sign intermediates or subkeys, record, back up, re-sign, rotate, revoke and recover, and when each step happens.
sidebar:
  order: 9
---

A root lives for years, and most of what happens to it is waiting. This page follows one root through every ritual it will meet, in the order it meets them, and says when each is done. The steps are the same for an X.509 root and an OpenPGP master key; where they differ, the page says so.

| Ritual | When | What changes |
|---|---|---|
| [Create](#create) | Once | A new key exists in its store. |
| [Sign intermediates or subkeys](#sign-intermediates-or-subkeys) | When one is needed, then every year | A key below the root gets authority. |
| [Record](#record) | After every ceremony | The ledger says what was done. |
| [Back up](#back-up) | Right after creating, and after every change | Loss becomes survivable. |
| [Re-sign](#re-sign) | Every year | The same key gets a new validity. |
| [Rotate](#rotate) | On an event, or after at most three years | A new key replaces the old one. |
| [Revoke](#revoke) | On compromise or loss | A key is declared untrustworthy. |
| [Recover](#recover) | When a card or a key is lost | The chain is made whole again. |

## Create

A root is created at a ceremony, in the store where it will live: on a card, or in a cloud key service. It is born there and never leaves. Before anything else you decide the store ([where a key lives](/learn/key-stores/)), the name, the algorithm and the lifetime.

Three things are made at the same time as the root, because they cannot be made later:

- the **evidence of where it was born**: a card's attestation, or a cloud key's description and policy;
- for an OpenPGP master key, a **revocation certificate**, kept apart from the card;
- the **second root**, on a second card, if you use cards: an independent key, never a copy.

Because a first ceremony is the one you have practised least, practise on test keys first. That is the point of a [drill](/guides/root-adoption/).

## Sign intermediates or subkeys

A root with nothing below it is useless. At a ceremony the root authorises each intermediate CA, or binds each OpenPGP subkey, after checking the request and the proof of where the key lives. The result goes to the system or the person that holds the key.

For a person's OpenPGP key the same step puts subkeys onto a card: the card makes the key, and the master key binds it. The signing, encryption and authentication subkeys can each live on the card, and only the binding signatures come from the offline master.

## Record

A ceremony without a record is a ceremony you cannot audit. The [ledger](/learn/the-ledger/) gets one record per ceremony: what was signed, by which key, in which store, and what outsiders now see. The record holds no secret and is chained to the one before.

## Back up

After the first ceremony, and after every change:

- push the [ledger](/learn/the-ledger/) to its remotes and write the last digest apart;
- put the revocation certificates in their two places;
- check that the second card exists, in a second place;
- make sure the PINs are in the password manager.

Then practise getting it back. A restore drill on a clean machine is the proof.

## Re-sign

Re-signing is the ordinary yearly ritual. The **same key** gets a **new validity**. A certificate for an intermediate is issued again over the same public key, or a binding is signed again with a later expiry. The root itself is extended at the same time, because each use of the root extends it by about three years.

Re-signing is cheap, and it changes nothing for anyone who already trusts the key. It keeps validity short, so a lost or forgotten key ages out, and it keeps the ceremony practised. The rule: **re-sign every year.**

## Rotate

Rotating is different: a **new key** replaces the old one. It is a larger event, because everything that trusted the old key must learn the new one, so it is done only when there is a reason:

- **On an event.** A suspected compromise, a change of store, a change of algorithm, a change of custody.
- **After at most three years,** whatever else happened. Three years is the top of the usual lifetime for a private signing key, and a forced rotation keeps the rotate path exercised.

The rule: **re-sign yearly; rotate on an event or after at most three years.**

## Revoke

Revoking declares a key untrustworthy now. It is the emergency exit, and its material is made in advance: an OpenPGP revocation certificate made when the key was born, and for X.509 a signed list that leaves the root out (for an intermediate, a CRL signed by the root). A revocation reaches different verifiers differently; see [what a revocation reaches](/learn/openpgp-release-keys/#revocation).

## Recover

Recovering is what you do after a loss: a card broken, stolen or forgotten in a taxi. It is a revocation, a replacement root, and a re-signing of whatever chained only to the lost one. See [moving from one root to another](/learn/transitions/).

Next: [moving from one root to another](/learn/transitions/).
