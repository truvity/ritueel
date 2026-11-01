---
title: Root and intermediate
description: The two kinds of key in a chain of trust, in X.509 and in OpenPGP, how they live different lives, and why the split exists.
sidebar:
  order: 2
---

A chain of trust has two kinds of key, and they live different lives. The root is trusted by outsiders directly. An *intermediate* is a key the root has authorised to act for it.

## In X.509

| | Root | Intermediate |
|---|---|---|
| What it is | A CA root certificate, installed in trust stores. | An intermediate CA certificate, signed by the root. |
| Used | Rarely: when an intermediate is created or renewed, or when the roots themselves change. Often once a year. | Every day, by software, to issue the certificates that people and machines present. |
| Held by | A person's care: a card in a drawer, a cloud key behind a confirmation. | A running system, close to the work. |
| Lifetime | Years, extended at each use. | Months, so that losing one is a small event. |
| Cost of a mistake | Every client that trusts it must learn the change. | Replace one intermediate. The root stays. |

## In OpenPGP

OpenPGP has no certificate chains, but it has the same split. The **primary key**, or master key, is the root of an identity. **Subkeys** are the intermediates: the primary key binds each one with a signature, and says what it may do.

| | Master (primary) key | Subkey |
|---|---|---|
| What it does | Certifies: it signs identities, binds subkeys, and revokes. It signs nothing else. | Signs data, encrypts, or authenticates (for example to an SSH server), one purpose per subkey. |
| Used | When a subkey is added, renewed or revoked. | Every day, by `gpg`, `git` or a release script. |
| Held by | Offline, in a store only a ceremony reaches. | On a card or in a key service, close to the work. |
| Lifetime | Years. | A year or two, renewed by re-signing the binding. |
| Cost of a mistake | Everyone who has your fingerprint must learn the change. | Revoke one subkey and bind another. The fingerprint stays. |

The master key is rarely needed, and that is why a person with a card for daily use can keep the master key somewhere else entirely.

## Why the split exists

The key that is expensive to lose is used rarely, and the key that is used all the time is cheap to replace. If one key did both jobs, every daily signature would put the most valuable key at risk. With the split, a thief who takes a laptop, a server or a card of subkeys gets a key that the root can disown.

A system that holds intermediates, such as [sluis](https://sluis.id), lives in the right-hand column. ritueel is about the left-hand column: the root, and the ceremony where the root authorises the next key.

## How an intermediate gets its authority

1. The holder of the intermediate makes the key where it will live, so the key never travels, and sends a request. For X.509 the request is a PKCS#10 certificate request. For OpenPGP it is the public subkey with a *back-signature*, a signature the subkey makes over the primary and itself to prove it agreed to be bound.
2. The request carries proof of where the key lives, if the store can give one: a YubiKey attestation certificate, or the description of a cloud key.
3. At a [ceremony](/learn/ceremonies/) the root's holder checks the request, sees what is about to be signed, and confirms.
4. The root signs. For X.509 the result is an intermediate CA certificate; for OpenPGP, a binding signature on the subkey. It goes back to the holder, who installs it.

The files that travel, and the checks on each side, are in the [hand-off contract](/reference/hand-off-contract/).

Next: [why the root stays offline](/learn/why-the-root-stays-offline/).
