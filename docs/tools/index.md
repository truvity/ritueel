---
title: Tools
description: "The ritueel tools that simplify the ceremonies: a command line, a guided mode and a read-only page on localhost. All are planned, and all drive one engine."
sidebar:
  label: Overview
  order: 0
---

The tools exist to simplify the rituals you learn about in [Learn](/learn/). They are not a reason to skip learning: a tool that signs the wrong thing signs it quickly.

:::caution[Not built yet]
ritueel is in the design phase and has no release. Every tool on this page is planned. The [roadmap](/roadmap/) has the order; each page says what is built.
:::

| Tool | What it is | Status |
|---|---|---|
| [The command line](/tools/cli/) | One to three commands for each ceremony, with a plan, a confirmation, a record and the checks before every touch. | Planned (M2 to M7) |
| [The wizard](/tools/wizard/) | A guided mode in the terminal, and a read-only page served on your own computer only. | Planned (page M2, guided mode after the first signed release) |
| [Command reference](/reference/cli/) | The commands, flags, files and exit codes. | Specified |

## One engine, three faces

The command line, the guided mode and the local page are three faces of the **same** ceremony engine: plan, confirm, reserve, sign, verify, record ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). The guided mode fills in flags and the page shows the plan; neither implements a ceremony of its own, and the page never confirms one. What the command line refuses, they refuse.

## What the tools never do

- Hold a private key outside the store that made it (a person's own key has one stated exception: [ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/)), or keep a PIN or a passphrase that a person types.
- Confirm an irreversible step for you.
- Sign online, or issue the certificates of servers and people. That belongs to a system that holds intermediates.
