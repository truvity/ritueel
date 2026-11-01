---
title: Concepts
description: The ideas behind ritueel, in the order to learn them. Principles, roots, where a key lives, two roots, OpenPGP release keys and the ceremony.
sidebar:
  order: 0
---

ritueel is a teaching product, so the ideas come first. Read these pages in order; each one assumes the page before it.

| Page | What you learn |
|---|---|
| [Design principles](/concepts/principles/) | What ritueel is and is not, and the rules the design follows, each linked to the record that decides it. |
| [Roots, intermediates and transitions](/concepts/roots-and-transitions/) | What a root is, why you want more than one, how a new root takes over from an old one, and what outsiders install. |
| [Where a key lives](/concepts/key-stores/) | Software, a PIV card, an OpenPGP card or AWS KMS: what each protects against, what it costs, and how to choose. |
| [Two roots in practice](/concepts/two-roots/) | What public CAs do, how clients behave when an intermediate has two certificates, and how the two cards alternate by year. |
| [OpenPGP release keys and the keyring](/concepts/openpgp-release-keys/) | The primaries, an intermediate's subkey, the back-signature, the keyring package, and what a revocation reaches. |
| [The ceremony](/concepts/ceremonies/) | What a person does at a ceremony, what the tool checks before each touch, and how roots and intermediates are renewed. |

:::note[Design phase]
ritueel has no release yet. These pages describe the model that the tools will follow; the [decision records](/decisions/) hold the reasons. Where a page says what a tool does, the tool is planned unless the page says it is built; the [roadmap](/roadmap/) has the order.
:::
