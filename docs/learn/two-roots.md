---
title: Two roots in practice
description: Why a chain of trust runs two roots at once, what public CAs do, how clients behave with two certificates, how the cards alternate, and how keys move.
sidebar:
  order: 11
---

*Design phase: this page teaches the model of [record 0003](../decisions/0003-root-cards.md). Checks of other projects were made on 2026-10-29; check again before you rely on one.*

This page assumes the [basics](/learn/what-is-a-root/#keys-from-zero), [the custody chain](/learn/custody-chain/), and a first look at where a key lives: [a card](/learn/how-a-yubikey-holds-keys/) and [a cloud key](/learn/how-a-kms-key-works/).

Two keys are redundancy, not control. One holder operates both cards, which are stored in two locations, and the cards alternate by year. This page shows that the practice is ordinary, and what to expect from clients. It is about cards, which cannot be copied, and one pair of cards may serve more than one bundle of one holder, each bundle in its own row ([record 0003](../decisions/0003-root-cards.md)). A cloud root has one key for each kind of root the bundle uses, each with a replica ([record 0004](../decisions/0004-the-cloud-root.md)).

## What others do

- **Public CAs run several roots at once.** [Let's Encrypt](https://letsencrypt.org/certificates/) operates ISRG Root X1 (RSA 4096) and ISRG Root X2 (ECDSA P-384), and X2 also has a certificate cross-signed by X1.
- **One intermediate can have two certificates.** Several Let's Encrypt intermediates had one certificate from ISRG Root X1 and a second, cross-signed one from an older root, so clients that trusted either root could build a chain.
- **Roots are replaced with old and new trusted together.** [RFC 4210, section 4.4](https://datatracker.ietf.org/doc/html/rfc4210) describes a root key update in which the old key stays in use until relying parties have the new one.
- **Purposes are kept apart.** The [Chrome Root Program policy](https://googlechrome.github.io/chromerootprogram/crp/policy), section 1.3.2, wants TLS server hierarchies dedicated to that one purpose. That rule is for the web PKI, but it is a good reason for roots that certify only the intermediates of one system.

What is less common is two keys that are **both permanently active and back each other up**. The conventional design keeps one root key and copies it between hardware security modules, with the wrapping key split among several custodians (an M-of-N scheme). The [YubiHSM 2 backup](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-backup-restore.html), for example, exports a key under a wrap key and imports it into a second device. That design has one root key to publish, but the copy is a key that has left the device it was born in, so the second device cannot attest where the key came from.

ritueel takes the other branch for two reasons: no key is ever copied, so each card keeps its attestation, and losing a card is survivable because the other key already exists. The price is two root keys to publish, document and watch.

## How the cards alternate

An intermediate's certificate is signed by the card of the year and lasts about 13 months. At the yearly ceremony the other card signs a new certificate over the same intermediate key, so years overlap by about a month. The key is not made again each year; it is replaced on an event, and a key in software also at most every three years. Between ceremonies the root signs nothing, and ritueel holds no online key.

| Year | Card at the ceremony | Certified that year | Still valid from the year before |
|---|---|---|---|
| 1 | A | Certificates 1 | none |
| 2 | B | Certificates 2 | Certificates 1, for about a month |
| 3 | A | Certificates 3 | Certificates 2, for about a month |

If card B is lost in year 2, certificates 2 are never issued by it. Card A signs them over the same intermediate keys, outsiders get a CA bundle and a keyring without B, and a replacement key is added. See [a lost root card](/guides/lost-root-card/).

## What to expect from clients

The effects below appear during an overlap and whenever a cross-certificate exists, when one intermediate key has two certificates.

- **A server presents one chain.** The chain holds the leaf and one certificate of the intermediate, issued by one root. Do not put both certificates of the intermediate in the same chain.
- **Path building differs between libraries.** The OpenSSL command line takes the first intermediate whose name matches and does not try the other one if that path fails; Go backtracks and tries both. The same family of bug is why OpenSSL 1.0.x broke when [a cross-signed root expired in 2021](https://openssl-library.org/post/2021-09-13-letsencryptrootcertexpire/): it preferred the chain it was sent over a valid path through its own trust store. A verifier that uses the OpenSSL command line should pass the chain it wants explicitly, or the root that matches it.
- **A revocation list is per issuer.** A client may build the path through either key, so it may ask for either list. A key that has no revocations still publishes an empty, current list. Each key signs its [CRL](/reference/crl/) only when it signs, about every second year, so a CRL is valid for 25 months and the other key's is carried unchanged.

## Moving and mixing

A root is built from one or more keys, in any key store ([record 0001](../decisions/0001-what-ritueel-is.md), rule 29). Cards and a cloud key may belong to one root, so that a failure of one kind does not take out the other ([record 0004](../decisions/0004-the-cloud-root.md), rule 2). The keys of one root change by steps, which [moving from one root to another](/learn/transitions/) teaches in full.

**From one kind of key store to another.** A transition never moves a key. It makes a new key in the new key store, and an old key vouches for it ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 10). The new key store must give evidence for a root, so a key file cannot be the new home of a root that others rely on ([record 0002](../decisions/0002-where-a-key-lives.md), rules 7 and 8).

| From | To | What changes |
|---|---|---|
| Key file | Card | The key stops being copyable. |
| Key file | Cloud key | The key moves under cloud access control and audit. |
| Card | Cloud key | A physical key becomes a permission. |
| Cloud key | Card | A permission becomes a physical key. A second card exists in another place before the first is relied on. |

**Adding a key.** An active root key vouches for the new one: for X.509 with a cross-certificate, for OpenPGP with a certification of the new primary. Adding a root key is a two-card ceremony, and a change of the root keys runs alone ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 7 and 9).

**An overlap.** Old and new key are both active. The holder says how long it lasts, as a wanted end date, and ritueel invents no default ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 3 and 5).

**Retiring a key.** ritueel leaves the retirement out of the plan until every declared delegation has a certificate or binding from another active key, valid for 30 more days ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 8).

**Revoking a key.** `revoke` is an act of its own, for an emergency. A root key leaves by a new root list without it, signed by the surviving keys and carrying its removal authorisation ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 11 and 12).

**The revocation is prepared at birth.** When a key is born, ritueel makes its revocation material: for every OpenPGP primary, a revocation signature for each of two reasons, compromised and superseded, and for every root key, a removal authorisation. The holder keeps them apart from the cards, in at least two places. Each costs one more touch at a card ceremony ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rules 21 to 23). Each key has its own: no key is the revoker of another, and the key of a lost card leaves with the material made for it. [Revoke](/learn/revoke/) says what a revocation reaches.

:::caution[Open]
How the card of the year is found when one root has a key on a card and a key in the cloud is not decided ([record 0007](../decisions/0007-changing-and-losing-a-root.md), "Proposed"; [issue #137](https://github.com/truvity/ritueel/issues/137)).
:::

## The limit you accept

Whoever holds one root card and its PIN can sign things that outsiders trust, until that key is revoked and the update reaches them ([the accepted limit](../decisions/0002-where-a-key-lives.md)). Standard tools cannot require two keys to agree. Do not describe the second card as a spare, and do not describe the custody as two-person control.

ritueel's own signed root list is the one place where keys agree. Renewing the list with the same keys needs one key, as every yearly ceremony does. Changing the root keys requires every current key, or a key's stored removal authorisation: each key signs consent to its own removal when it is born, and that file is kept with its revocation signature, so a lost card can still leave the set ([the root list](/reference/root-list/#who-signs)).
