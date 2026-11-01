---
title: Concepts
description: The ideas behind ritueel, in the order to learn them. Roots and intermediates, where a key lives, two roots, OpenPGP release keys and the ceremony.
sidebar:
  order: 0
---

ritueel is a teaching product, so the ideas come first. Read these pages in order; each one assumes the page before it.

| Page | What you learn |
|---|---|
| [Roots, intermediates and transitions](/concepts/roots-and-transitions/) | What a root is, why you want more than one, how a new root takes over from an old one, and what outsiders have to install. |
| [Where a key lives](/concepts/key-stores/) | Software, a YubiKey, or AWS KMS: what each protects against, what it costs, and how to choose. |
| [Two roots in practice](/concepts/two-roots/) | What public CAs do, how clients behave when an intermediate has two certificates, and how the two cards alternate by year. |
| [OpenPGP release keys and the keyring](/concepts/openpgp-release-keys/) | The primaries, the board subkey, the back-signature, the keyring package, and what gpg, sqv, apt and rpm were tested to accept. |
| [The ceremony](/concepts/ceremonies/) | What a person does at a ceremony, what the tool checks before each touch, and the open question of the card tool. |

:::note[Design phase]
ritueel has no release yet. These pages describe the model that the tools will follow ([ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)). Where a page says what a tool does, the tool is planned unless the page says it is built; the [roadmap](/roadmap/) has the order.
:::
