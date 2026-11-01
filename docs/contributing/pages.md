---
title: Pages and writing
description: Where a page of the ritueel site lives, how it says what is built, and how pages, records and reports are written for an engineer reader.
sidebar:
  order: 6
---

The pages on this site teach the model of roots and transitions first, and then say what the tools do. Everything in this repository is written for an engineer who has not followed the discussion: pages, decision records, research, pull requests and commit messages.

## Where a page lives

Docs live in `docs/`, next to the thing they describe. When the thing changes, its docs change in the same pull request.

| Kind | Where | For |
|---|---|---|
| Concepts | `docs/concepts/` | The model: what a root is, why there are several, what outsiders install. Written before any tool exists, and kept true after. |
| Guides | `docs/guides/` | One guide per ceremony or transition, step by step, with its drill on test keys. |
| Reference | `docs/reference/` | Commands, file formats and the hand-off contract. Exact, versioned, no reasoning. |
| Research | `docs/research/` | Dated results of spikes and research, verdict first ([Spikes and research](/contributing/research/)). The name ends in the date. |
| Decisions | `docs/decisions/` | The decision records. They cite research and reference pages and do not repeat them. |

Say a thing once, in the page that owns it, and link to it from the others: a measurement in its research page, a rule in its record, a format in its reference page.

## What is built

Say it in the first paragraph of a page about a tool: "Not built yet", "Partly built: X works, Y does not", or nothing when it is built and released. Change it in the same pull request that builds the thing. A guide never describes a command that does not exist as if it did.

## Asides and diagrams

How settled a point is shows in how it is written. Plain prose is agreed. `:::note[Proposed]` is the design as proposed, awaiting the maintainer. `:::caution[Open]` is undecided and links to the decision issue.

Use a table or a short numbered list rather than a diagram. A Mermaid diagram (a ```` ```mermaid ```` fence) may arrive with the site; one that needs scrolling to be read is too big.

## Links

A link to another page uses its site path with a trailing slash, `/concepts/key-stores/`. A link to a heading, on the same page or another, uses the full form `/concepts/key-stores/#the-four-stores`: the link check is strict and resolves both.

## Plain and short

- Say the verdict first, then the reasons.
- Use plain words and short sentences. Prefer the active voice: "the holder confirms the touch", not "the touch is confirmed".
- Use a table to compare options, versions or numbers, not a paragraph.
- One idea per paragraph. Cut a word that adds nothing.

## Teaching

- Name the key store or the format before you use its short name. Say what goes wrong in the real world before you give the rule.
- Show a transition as numbered steps with the result of each step: what exists now, what an outsider sees.
- A drill states what the learner starts with, what they do, and how they know it worked.

## Dated and checkable

- Date every claim that can rot: a measurement, a version, a firmware behaviour, a price, the state of an upstream project. "Measured 2026-10-31" lets the next reader judge it.
- Name the version of a tool or a standard when the claim depends on it.
- Cite the principle or the record for a decision, not the day it was made.

## Instructions

- In guidance for people and agents, prefer soft wording ("prefer", "avoid") and say why. Keep "never" and "must" for the rules that have no exception, such as secrets and the public-content rules.
- Write steps as numbered lists in the imperative.

## Files

- Use the `.yaml` extension for YAML files, not `.yml`. The exceptions are the file names a tool requires: `.github/ISSUE_TEMPLATE/config.yml` and `.yarnrc.yml`. `just check-yaml-ext` checks it.
- After an edit, reflow the paragraph you changed so it keeps the wrapping the file already uses.
- Text files use LF line endings; `.gitattributes` enforces it.
