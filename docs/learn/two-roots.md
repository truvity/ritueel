---
title: Two roots in practice
description: Why a chain of trust runs two roots at once, what public CAs do, how clients behave when an intermediate has two certificates, and how the cards alternate.
sidebar:
  order: 20
---

*Design phase: this page teaches the model of [record 0003](../decisions/0003-root-cards.md). Checks of other projects were made on 2026-10-29; check again before you rely on one.*

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

## The limit you accept

Whoever holds one root card and its PIN can sign things that outsiders trust, until that key is revoked and the update reaches them ([the accepted limit](../decisions/0002-where-a-key-lives.md)). Standard tools cannot require two keys to agree. Do not describe the second card as a spare, and do not describe the custody as two-person control.

ritueel's own signed root list is the one place where keys agree. Renewing the list with the same keys needs one key, as every yearly ceremony does. Changing the root keys requires every current key, or a key's stored removal authorisation: each key signs consent to its own removal when it is born, and that file is kept with its revocation signature, so a lost card can still leave the set ([the root list](/reference/root-list/#who-signs)).
