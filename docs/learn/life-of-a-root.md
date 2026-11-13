---
title: The life of a root
description: A root from birth to recovery in order. Create, sign intermediates or subkeys, record, back up, re-sign, rotate, revoke and recover, and when each step happens.
sidebar:
  order: 14
---

A root lives for years, and most of what happens to it is waiting. This page follows one root through every ritual, in order, and says when each is done. The steps are the same for an X.509 root and an OpenPGP primary key; where they differ, the page says so.

| Ritual | When | What changes |
|---|---|---|
| [Create](#create) | Once | A new key exists in its key store. |
| [Sign intermediates or subkeys](#sign-intermediates-or-subkeys) | When one is needed, then every year | A key below the root gets authority. |
| [Record](#record) | After every ceremony | The history says what was done. |
| [Back up](#back-up) | Right after creating, and after every change | Loss becomes survivable. |
| [Re-sign](#re-sign) | Every year | The same key gets a new validity. |
| [Rotate](#rotate) | On an event; a key in software also after at most three years | A new key replaces the old one. |
| [Revoke](#revoke) | On compromise or loss | A key is declared untrustworthy. |
| [Recover](#recover) | When a card or a key is lost | The chain is made whole again. |

## Create

A root key is created at a ceremony, in the key store where it will live: a card, a cloud key service or a key file. On a card or in a cloud service the key never leaves. First you decide the key store ([where a key lives](/learn/key-stores/)), the name, the algorithm and the lifetime.

Three things are made at birth:

- the **evidence of where it was born**: a card's attestation, or a cloud key's description and policy;
- for an OpenPGP primary key, a **revocation signature**, kept apart from the card;
- the **second key**, on a second card, if you use cards: an independent key, never a copy.

Because a first ceremony is the one you have practised least, practise on test keys first. That is the point of a [drill](/guides/root-adoption/).

## Sign intermediates or subkeys

A root with nothing below it is useless. At a ceremony the root authorises each intermediate CA, or binds each OpenPGP subkey, after checking the request and the proof of where the key lives. The result goes to the system or the person that holds the key.

For a person's OpenPGP key the same step puts subkeys onto a card: the card makes the key, and the primary key binds it. The signing and authentication subkeys are born on the card, an encryption subkey is made in software and loaded onto it with a backup, and only the binding signatures come from the offline primary.

## Record

A ceremony without a ceremony record cannot be audited. The [history](/learn/the-history/) gets one ceremony record for each ceremony: what was signed, by which key, in which key store, and what outsiders now see. It holds no secret and is chained to the one before.

## Back up

After the first ceremony, and after every change:

- push the bundle, with its [history](/learn/the-history/), to its remotes and keep the [end of the history](/glossary/) elsewhere;
- put the revocation signatures in their two places;
- check that the second card exists, in a second place;
- make sure the PINs are in the password manager.

Then practise getting it back. A restore drill on a clean machine is the proof.

## Re-sign

Re-signing is the ordinary yearly ritual. The **same key** gets a **new validity**. A certificate for an intermediate is issued again over the same public key, or a binding is signed again with a later expiry. The key that signs is extended at the same time, because each use extends it by about three years.

Re-signing is cheap, and it changes nothing for anyone who already trusts the key. It keeps validity short, so a lost or forgotten key ages out, and it keeps the ceremony practised. The rule: **re-sign every year.** See [re-sign](/learn/re-sign/) for the reasons.

## Rotate

Rotating is different: a **new key** replaces the old one. It is a larger event, because everything that trusted the old key must learn the new one, so it is done only when there is a reason:

- **On an event.** An advisory that affects the card, its firmware or the service; the deprecation of the algorithm; a lost card or one at its end of life; a suspected compromise; a change of key store or of place. The yearly ceremony includes a review of the advisories, so that this kind of event is not missed.
- **For a key in software, also after at most three years,** whatever else happened, because a file can be copied without a trace. Three years is the top of the usual lifetime for a private signing key, and a forced rotation keeps the rotate path exercised. A key on a card or in a cloud key service cannot be copied, and has no such limit.

The rule: **re-sign yearly; rotate on an event, and a key in software after at most three years.** See [rotate](/learn/rotate/).

## Revoke

Revoking declares a key untrustworthy now. It is the emergency exit, and its material is made in advance: an OpenPGP revocation signature made when the key was born, and for X.509 a signed list that leaves the key out (for an intermediate, a CRL from its root key). A revocation reaches different verifiers differently; see [what a revocation reaches](/learn/openpgp-release-keys/#revocation). See [revoke](/learn/revoke/).

## Recover

Recovering is what you do after a loss: a card broken, stolen or forgotten in a taxi. It is a revocation, a replacement key, and a re-signing of whatever chained only to the lost one. See [recover](/learn/recover/) and [moving from one root to another](/learn/transitions/).

Next: [revoke](/learn/revoke/).
