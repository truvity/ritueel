---
title: Custody chains compared
description: Four custody chains side by side, public PKI, private PKI, OpenPGP and SSH. Who holds each key, what you control, how revocation works, where ritueel fits.
sidebar:
  order: 7
---

[The custody chain](/learn/custody-chain/) asks four questions of every key: where it lives, who can make it sign, under which ceremony it got its authority, and how it is replaced or revoked. The answers depend on the kind of chain. The four below are the ones most teams meet.

| | [Public PKI](/learn/chain-public-pki/) | [Private PKI](/learn/chain-private-pki/) | [OpenPGP](/learn/chain-openpgp/) | [SSH](/learn/chain-ssh/) |
|---|---|---|---|---|
| **Root** | A public CA's root, in browser and system trust stores. | Your own root. | A master key that only certifies. | An SSH CA key. |
| **Held by** | The CA, in audited hardware. | You: cards, a cloud key. | You: offline, in a store only a ceremony reaches. | You, or a system you run. |
| **Middle** | The CA's intermediates, online at the CA. | Per-environment intermediates, with name constraints. | Subkeys for signing, encryption and authentication, on a card. | Usually none, or one CA per environment. |
| **End** | TLS certificates for your sites. | Certificates for workloads and hosts. | Signatures, encrypted messages, logins. | User and host certificates. |
| **How a verifier gets the root** | It ships with the operating system or browser. | You distribute it to every trust store. | A fingerprint over a channel it trusts, a keyring package, or a key directory. | The host is configured with the CA's public key. |
| **Typical lifetime of the end** | Days to a year. The maximum is set by the CA/Browser Forum. | Days to a year; your choice. | A signature lasts as long as the key does; a subkey a year or two. | Minutes to days; your choice. |
| **Revocation** | The CA's lists and responders; browsers also push their own. | A CRL signed by the root, or short lifetimes. | A revocation certificate, published, and a keyring without the key. | A revoked-keys list on each host, or short lifetimes. |
| **What you do not control** | The rules, the root programs, Certificate Transparency, the CA. | The distribution: every client you forgot to update. | How a verifier learns your fingerprint. | Which hosts trust the CA key, and for how long. |
| **Where ritueel helps** | It does not hold a public CA's keys. It teaches what you depend on. | The root, the intermediates' ceremonies, the CA bundle and the root list. | The master key, the subkeys onto cards, the revocation certificate, the keyring package. | The break-glass SSH CA and the SSH CA key list. |

## What stays the same

Whatever the chain, the work is the same shape:

1. **One key is trusted directly,** and it is the one that needs the most care.
2. **The key that does the daily work is a different key,** cheaper to replace.
3. **Authority passes down by a signature made at a ceremony,** and runs out unless it is renewed.
4. **Revocation is prepared before it is needed,** and it reaches different verifiers in different ways.

That is why one set of rituals, [re-sign](/learn/re-sign/), [rotate](/learn/rotate/), [revoke](/learn/revoke/) and [recover](/learn/recover/), serves all four.
