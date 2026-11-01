---
title: Layered trust
description: Why trust is built in layers of keys with different jobs, what each layer is for, and why redundancy answers loss while revocation answers compromise.
sidebar:
  order: 5
---

Trust in a well-run PKI is not one key. It is layers, each with a different job, a different lifetime and a different level of care.

## The layers

| Layer | Job | Lifetime | How it is kept |
|---|---|---|---|
| **Root** | Authorises the layer below. Trusted by outsiders directly. | Years, extended at each use. | Offline, in a store only a ceremony reaches. |
| **Intermediate** | Does the daily signing: issues certificates, or signs releases. | Months to a year, renewed by re-signing. | In a system, born where it lives. |
| **Leaf** | The certificate or signature that a person or machine presents. | Days to a year. | On the machine that uses it. |

Each layer is cheap to replace compared with the one above it, and the more valuable key is touched less often. A leaf is replaced on a schedule. An intermediate is replaced on an event. A root is replaced almost never, and then with great care.

## Why not fewer layers

One layer, a root that signs leaves directly, would be simple, but every issuance would use the root. The root would have to be online, and it would be exposed every day. Two layers, root and intermediates, is the usual minimum. More layers are for large organisations that want to separate environments, products or teams, each with its own intermediate and its own limits, so that a break in one is contained.

## Limits narrow as you go down

A layer should be able to do less than the one above it. In X.509 this is done with *name constraints* on an intermediate: it can issue only for the names it is meant for. In OpenPGP, a subkey's flags say whether it can sign, encrypt or authenticate, and nothing more. A narrow intermediate that is stolen does less damage. The [private PKI](/learn/chain-private-pki/) page returns to this.

## Redundancy and compromise are different problems

There are two ways a root fails, and they need different answers.

- **Loss.** The key is gone: a card breaks, an account is locked. The answer is *redundancy*: another key that can take over. A card cannot be copied, so redundancy means a second, independent card. A cloud key service can replicate its own key, so redundancy means a replica.
- **Compromise.** Someone else has the key. A second copy makes it worse. The answer is *revocation*: declare the key untrustworthy and move to a new one.

So ritueel never offers to export a key from a card or a cloud key to make a backup. For cards, backup means two cards. For a cloud key, it means a replica. For a key in a software store, the store's own replication is the backup, and the next page on [key stores](/learn/key-stores/) says what that costs.

Redundancy is not control either. Any one root a client trusts can sign anything that client accepts. Two roots do not mean that two people must agree. Protect each root as if it were the only one.

## What outsiders see

Outsiders do not see your layers. They see what they installed: a root list, a CA bundle, a keyring, a fingerprint. The chain a verifier follows from that to a leaf is the [custody chain](/learn/custody-chain/), and a break anywhere in it breaks everything below.

Next: [the custody chain](/learn/custody-chain/).
