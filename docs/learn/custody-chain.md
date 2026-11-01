---
title: The custody chain
description: Who or what holds each key from root to leaf, who can use it and under which ceremony, why a break breaks all below it, and how ritueel records it.
sidebar:
  order: 6
---

A **custody chain** is the answer to a plain question: for every key between the root and the thing a person actually uses, **who or what holds it, who can make it sign, and under which ceremony did it get its authority?**

A *signature chain* tells a verifier which key signed which. A custody chain adds the human and physical side: where each key lives and who has power over it. The two have the same links, and you need both.

## An example

A small organisation runs a private certificate hierarchy. Its custody chain, written as a table:

| Link | Key | Held by | Lives in | Can be made to sign by | Authority came from |
|---|---|---|---|---|---|
| 1 | Root, card A | The holder | A YubiKey in a drawer | The holder, with the PIN and a touch | Self-signed at the first ceremony; extended at each yearly ceremony |
| 1 | Root, card B | The holder | A YubiKey in another place | The same | The same, independently |
| 2 | Intermediate for production | The production platform | A cloud key service | The platform's issuing service and the roles allowed to call it | A certificate signed by the root of the year at a yearly ceremony |
| 3 | Leaf certificate of a workload | The workload | The workload's memory | The workload | Issued automatically by the intermediate, valid for days |

For OpenPGP, the same idea:

| Link | Key | Held by | Lives in | Can be made to sign by | Authority came from |
|---|---|---|---|---|---|
| 1 | Master key (certify only) | The holder | Offline, in a store only a ceremony reaches | The holder, at a ceremony | Self-certified when created |
| 2 | Signing subkey | The holder | A card used every day | The holder, with PIN and touch | Bound by the master key; the binding is re-signed each year |
| 2 | Authentication subkey | The holder | The same card | The SSH agent, for the holder's logins | Bound by the master key |

Reading across a row tells you what an attacker would need: the card and its PIN, a role in a cloud account, or a hold on a workload.

## Why it matters

**It is what a verifier actually trusts.** A client does not trust a certificate or a signature in the abstract. It trusts a chain that ends at a root it already holds. Every link of that chain is a key somebody holds, in a place, under rules. If you cannot say who holds a link, you do not know what you are asking people to trust.

**A break anywhere breaks everything below it.** If the key at link 2 is stolen, everything the thief signs with it looks genuine to every client that trusts the root. If the root is stolen, everything under it is suspect. The strength of the chain is the strength of its weakest link, and the weakest link is rarely the root: it is the intermediate that sits on a busy server, or the subkey on a laptop without a PIN.

**It tells you what to do when something goes wrong.** With the table in front of you, "a card was lost" reads as "link 1, card A: revoke it, publish a root list without it, re-sign what chained only to it". Without the table, it reads as a bad day.

Four questions for every link, written down before you need them:

1. **Where does the key live?** Which store, and what proves it?
2. **Who or what can make it sign?** And what must they have: a card, a PIN, a touch, a role, a vault?
3. **Under which ceremony did it get its authority, and when does that run out?**
4. **How is it replaced or revoked?** And who is told?

## How ritueel records it

ritueel keeps the chain in the [ledger](/learn/the-ledger/), a directory of plain files that holds public information only:

- **The links it makes or signs.** For each root: its certificate or public key, where it lives, and the evidence of where it was born (the attestation of a card, or the description and policy of a cloud key). For each intermediate it certifies: the request it received, the proof that came with it, and the certificate or binding it returned.
- **The ceremonies that made each link.** One record per ceremony, chained by hash to the one before it, saying what was signed, with which key, in which store, and what outsiders see as a result.
- **When each link runs out.** Expiry dates of roots and certificates, with a warning well before they come.
- **What it does not hold.** Private keys, PINs, passphrases and the revocation certificates themselves are never in the ledger. The ledger holds only a digest of each revocation certificate, so you can tell later that the right one is the one you kept.

The ledger covers the links down to the intermediates that ritueel certifies. Below that, the system that holds the intermediate keeps its own record of the leaves it issues. The two meet at the [hand-off contract](/reference/hand-off-contract/).

## Different chains

The same four questions apply to every kind of chain, and the answers differ. [Custody chains compared](/learn/custody-chains/) puts public PKI, private PKI, OpenPGP and SSH side by side, with a page for each.

Next: [custody chains compared](/learn/custody-chains/).
