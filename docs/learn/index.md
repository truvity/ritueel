---
title: Learn
description: The general logic of keeping root keys and intermediates safe, in the order to learn it, from what a root is to the whole life of a root.
sidebar:
  label: Overview
  order: 0
---

ritueel teaches first. These pages explain how roots and intermediates are handled securely, whatever tool you use; the tools exist to make the rituals simpler, and they come after. Read the pages in order. Each one assumes the page before it.

| Page | What you learn |
|---|---|
| [What is a root?](/learn/what-is-a-root/) | The key that everything else hangs from, and what goes wrong when it is lost or stolen. |
| [Root and intermediate](/learn/root-and-intermediate/) | The two kinds of key in a chain of trust, and the same split in OpenPGP: the master key and its subkeys. |
| [Why the root stays offline](/learn/why-the-root-stays-offline/) | What "offline" protects against, and how much of it you can have without a vault and a live CD. |
| [What a ceremony is](/learn/ceremonies/) | The rare, manual use of a root, why it is manual, and why that is a feature. |
| [Layered trust](/learn/layered-trust/) | Why trust comes in layers, what each layer is for, and where redundancy helps and where it does not. |
| [The custody chain](/learn/custody-chain/) | Who or what holds each key from the root to the leaf, and what a verifier really trusts. |
| [Where a key lives](/learn/key-stores/) | Software and its backends, YubiKey PIV and OpenPGP card, AWS KMS and the planned stores, compared in the open. |
| [The ledger](/learn/the-ledger/) | The record of what you did: where it lives, how it is backed up, and how it is restored. |
| [The life of a root](/learn/life-of-a-root/) | Create, sign, record, back up, re-sign, rotate, revoke, recover: the whole story in order. |
| [Moving from one root to another](/learn/transitions/) | How a new root takes over from an old one without breaking anyone, and what outsiders install. |
| [Two roots in practice](/learn/two-roots/) | What public CAs do, how clients behave when an intermediate has two certificates, and how two cards alternate. |
| [OpenPGP release keys and the keyring](/learn/openpgp-release-keys/) | The primaries, an intermediate's subkey, the back-signature, the keyring package, and what a revocation reaches. |

When you are ready to act, the [guides](/guides/) give the steps. The [principles](/principles/) are the rules ritueel's design follows, and the [decision records](/decisions/) hold the reasons.

:::note[Design phase]
ritueel has no release yet. These pages teach the model the tools will follow. Where a page says what a tool does, the tool is planned unless the page says it is built; the [roadmap](/roadmap/) has the order.
:::
