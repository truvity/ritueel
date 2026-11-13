---
title: Tools
description: "The ritueel tools: a command line, a guided mode and a read-only page on localhost. Only `version` is built; the page exists as code. All drive one engine."
sidebar:
  label: Overview
  order: 0
---

The tools exist to simplify the rituals you learn about in [Learn](/learn/). They are not a reason to skip learning: a tool that signs the wrong thing signs it quickly.

:::caution[Not built yet]
ritueel is in the design phase and has no release. Only the command `version` is built; every other command is planned. The local page exists as code and a demo (`ui/`, `proto/`), as a design to look at and click through; the program that serves it does not. The [roadmap](/roadmap/) has the order; each page says what is built.
:::

| Tool | What it is | Status |
|---|---|---|
| [The command line](/tools/cli/) | One or two commands for each ceremony, with a plan, a confirmation, a record and the checks before every touch. | Planned (M2 to M7) |
| [The wizard](/tools/wizard/) | The guided mode in the terminal. It asks line by line and shows the plan with its digest. | Planned (page M2, guided mode after the first signed release) |
| [The local page](/tools/local-page/) | The browser view of your own bundle, served on your computer and read-only. A [demo](/demo/) shows the real page over made-up data. | Partly built: the page and its demo exist; the program that serves the page is planned (M2) |
| [Command reference](/reference/cli/) | The commands, flags, files and exit codes. | Specified |

## One engine, three faces

The command line, the guided mode and the local page are three faces of the **same** ceremony engine ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)). The guided mode fills in flags and the page shows the plan; neither implements a ceremony of its own, and the page never confirms one. The command line and the page also call the same API of one ritueel process. What the command line refuses, they refuse.

## What the tools never do

- Hold a private key outside the store that made it (a person's own key has two stated exceptions, an adopted primary and an encryption subkey: [record 0008](../decisions/0008-a-persons-own-key.md) and rule 2 of [record 0002](../decisions/0002-where-a-key-lives.md)), or keep a PIN or a passphrase that a person types.
- Confirm an irreversible step for you.
- Sign online, or issue the certificates of servers and people. That belongs to a system that holds intermediates.
- Send anything out except a public OpenPGP key, to the keyservers you list. For everything else they print what to do ([record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md)).
