---
title: The custody chain
description: Who or what holds each key from root to leaf, who can use it and under which ceremony, why a break breaks all below it, and how ritueel records it.
sidebar:
  order: 2
---

This page assumes the [basics](/learn/what-is-a-root/#keys-from-zero): a key pair, a signature and a certificate.

A **custody chain** is the answer to a plain question: for every key between the root and the thing a person actually uses, **who or what holds it, who can make it sign, and under which ceremony did it get its authority?**

A *signature chain* tells a verifier which key signed which. A custody chain adds the human and physical side: where each key lives and who has power over it. The two have the same links, and you need both.

## An example

A small organisation runs a private certificate hierarchy. Its custody chain, written as a table:

| Link | Key | Held by | Lives in | Can be made to sign by | Authority came from |
|---|---|---|---|---|---|
| 1 | Root key A | The holder | A YubiKey in a drawer | The holder, with the PIN and a touch | Self-signed at the first ceremony; extended each time it signs |
| 1 | Root key B | The holder | A YubiKey in another place | The same | The same, independently |
| 2 | Intermediate for production | The production platform | A cloud key service | The platform's issuing service and the roles allowed to call it | A certificate signed with the card of the year at a yearly ceremony |
| 3 | Leaf certificate of a workload | The workload | The workload's memory | The workload | Issued automatically by the intermediate, valid for days |

For OpenPGP, the same idea:

| Link | Key | Held by | Lives in | Can be made to sign by | Authority came from |
|---|---|---|---|---|---|
| 1 | Primary key (certify only) | The holder | Offline, in a key store only a ceremony reaches | The holder, at a ceremony | Self-certified when created |
| 2 | Signing subkey | The holder | A card used every day | The holder, with PIN and touch | Bound by the primary key; the binding is re-signed each year |
| 2 | Authentication subkey | The holder | The same card | The SSH agent, for the holder's logins | Bound by the primary key |

Reading across a row tells you what an attacker would need: the card and its PIN, a role in a cloud account, or a hold on a workload.

## Why it matters

**It is what a verifier actually trusts.** A client trusts no certificate or signature by itself. It trusts a chain that ends at a root it already holds. Every link of that chain is a key somebody holds, in a place, under rules. If you cannot say who holds a link, you do not know what you are asking people to trust.

**A break anywhere breaks everything below it.** If the key at link 2 is stolen, everything the thief signs with it looks genuine to every client that trusts the root. If the root is stolen, everything under it is suspect. The strength of the chain is the strength of its weakest link, and the weakest link is rarely the root: it is the intermediate that sits on a busy server, or the subkey on a laptop without a PIN.

**It tells you what to do when something goes wrong.** With the table in front of you, "a card was lost" reads as "link 1, key A: revoke it, publish a root list without it, re-sign what chained only to it". Without the table, it reads as a bad day.

Four questions for every link, written down before you need them:

1. **Where does the key live?** Which key store, and what proves it?
2. **Who or what can make it sign?** And what must they have: a card, a PIN, a touch, a role, a vault?
3. **Under which ceremony did it get its authority, and when does that run out?**
4. **How is it replaced or revoked?** And who is told?

## How ritueel records it

ritueel keeps the chain in the bundle, a directory of plain files with a fixed structure that holds public material and, sealed, the secrets of cards. Its write-once part is the [history](/learn/the-history/):

- **The links it makes or signs.** For each root key: its certificate or public key, where it lives, and the evidence of its birth (the attestation of a card, or the description and policy of a cloud key). For each intermediate it certifies: the request it received, the proof that came with it, and the certificate or binding it returned.
- **The ceremonies that made each link.** One ceremony record per ceremony, chained by hash to the one before it, saying what was signed, with which key, in which key store, and what outsiders see as a result.
- **When each link runs out.** Expiry dates of root keys and certificates, with a warning before they come.
- **What it does not hold.** Private keys, PINs, passphrases and the revocation signatures themselves are never in the bundle in clear. The bundle holds only a digest of each revocation signature, so you can tell later that the right one is the one you kept.

The history covers the links down to the intermediates that ritueel certifies. Below that, the system that holds the intermediate keeps its own record of the leaves it issues. The two meet at the [hand-off contract](/reference/hand-off-contract/).

## Different chains

The same four questions apply to every kind of chain, and the answers differ. The table puts public PKI, private PKI, OpenPGP and SSH side by side, with a page for each.

| | [Public PKI](/learn/chain-public-pki/) | [Private PKI](/learn/chain-private-pki/) | [OpenPGP](/learn/chain-openpgp/) | [SSH](/learn/chain-ssh/) |
|---|---|---|---|---|
| **Root** | A public CA's root, in browser and system trust stores. | Your own root. | A primary key that only certifies. | An SSH CA key. |
| **Held by** | The CA, in audited hardware. | You: cards, a cloud key. | You: in a key store only a ceremony reaches (a root card or the cloud root; a person's own primary in an encrypted file kept offline). | You, or a system you run. |
| **Middle** | The CA's intermediates, online at the CA. | Per-environment intermediates, with name constraints. | Subkeys for signing, encryption and authentication, on a card. | Usually none, or one CA per environment. |
| **End** | TLS certificates for your sites. | Certificates for workloads and hosts. | Signatures, encrypted messages, logins. | User and host certificates. |
| **How a verifier gets the root** | It ships with the operating system or browser. | You distribute it to every trust store. | A fingerprint over a channel it trusts, a keyring package, or a key directory. | The host is configured with the CA's public key. |
| **Typical lifetime of the end** | Days to a year. The maximum is set by the CA/Browser Forum. | Days to a year; your choice. | A signature lasts as long as the key does; a subkey a year or two. | Minutes to days; your choice. |
| **Revocation** | The CA's lists and responders; browsers also push their own. | A CRL signed by the root, or short lifetimes. | A revocation certificate, published, and a keyring without the key. | A revoked-keys list on each host, or short lifetimes. |
| **What you do not control** | The rules, the root programs, Certificate Transparency, the CA. | The distribution: every client you forgot to update. | How a verifier learns your fingerprint. | Which hosts trust the CA key, and for how long. |
| **Where ritueel helps** | It does not hold a public CA's keys. It teaches what you depend on. | The root, the intermediates' ceremonies, the CA bundle and the root list. | The primary key, the subkeys onto cards, the revocation signature, the keyring file. | The break-glass SSH CA and the SSH CA key list. |

Next: [Private PKI](/learn/chain-private-pki/).
