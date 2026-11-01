---
title: Tools
description: The ritueel tools that simplify the ceremonies, a command line and a wizard on localhost, and what is built today. Both are planned, and both drive one engine.
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
| [The command line](/tools/cli/) | One to three commands for each ceremony, with a plan, a confirmation, a record and the checks before every touch. | Planned (M1 to M3) |
| [The wizard](/tools/wizard/) | A guided front end in the terminal, and a web page served on your own computer only. | Planned (M4) |
| [Command reference](/reference/cli/) | The commands, flags, files and exit codes. | Specified |

## One engine, two faces

The command line and the wizard are two faces of the **same** ceremony engine: plan, confirm, reserve, sign, verify, record ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). The wizard fills in flags and shows the plan; it does not implement a ceremony of its own. What the command line refuses, the wizard refuses.

## What the tools never do

- Hold a private key outside the store that made it, or keep a PIN or a passphrase.
- Confirm an irreversible step for you.
- Sign online, or issue the certificates of servers and people. That belongs to a system that holds intermediates.
