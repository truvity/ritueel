---
title: Pages
description: Where a page of the ritueel site lives, how it says whether a thing is built or only designed, what kinds of page there are, and how to draw a diagram.
sidebar:
  order: 6
---

The pages on this site teach the model of roots and transitions first, and then say what the tools do. A page is not a promise that a tool exists, so it says how far it has got. How to write the prose itself is in [Writing style](/contributing/writing/).

## Where a page lives

Docs live in `docs/`, next to the thing they describe: the format of the decision records is in `docs/decisions/`, and a page about a part of ritueel sits in that part's section of the site. When the thing changes, its docs change in the same pull request.

| Kind | Where | For |
|---|---|---|
| Concepts | `docs/concepts/` | The model: what a root is, why there are several, what outsiders install. Written before any tool exists, and kept true after. |
| Guides | `docs/guides/` | One guide per transition, such as software to YubiKey or YubiKey to AWS KMS. Step by step. |
| Drills | `docs/drills/` | Practice runs on test keys: a lost card, an expiring root, a revocation. |
| Reference | `docs/reference/` | Commands, file formats and the hand-off contract. |
| Decisions | `docs/decisions/` | The decision records. |

## What is built

Say it in the first paragraph of a page about a tool: "Not built yet", "Partly built: X works, Y does not", or nothing when it is built and released. Change it in the same pull request that builds the thing. A guide never describes a command that does not exist as if it did.

## Diagrams

Mermaid diagrams (a ```` ```mermaid ```` fence) may arrive with the site. Until then, use a table or a short numbered list. A diagram that needs scrolling to be read is too big: keep it to a size a reader takes in at a glance, with short labels and a few boxes per row.

## Asides

How settled a point is shows in how it is written. Plain prose is agreed. `:::note[Proposed]` is the design as proposed, awaiting the maintainer. `:::caution[Open]` is undecided and links to the decision issue.
