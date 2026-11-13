---
title: The local page and its demo
description: The local page is ritueel's view of your own bundle, in your browser. The demo on this site is that page over made-up data. The program behind it is not built.
sidebar:
  order: 3
---

:::caution[Partly built]
The page itself and its [demo](/demo/) exist, as a design to look at and click through. **Planned, not built:** the program that serves the page from your own computer, and every call it makes. It comes with milestone M2 of the [roadmap](/roadmap/). Nothing on the demo reads a real bundle or a real card. ritueel is in its design phase.
:::

The local page is the third face of the program, beside the command line and the guided mode in the terminal ([The wizard](/tools/wizard/)). It is served by the one ritueel process on your own computer, to your own browser, only while you use it, and it is a **view**: it shows what is not applied yet, what is wrong, where every key is and what it is for, what happened, and what outsiders install. Its first build writes nothing; the one write it may get later is an inert proposal that nothing acts on. It never confirms anything, and it never asks for or receives a PIN, a passphrase or any secret. You write the wanted files in an editor, you run `ritueel apply` in the terminal, and you type the first eight characters of the plan's digest there.

## The four entries

- **To do.** What is not applied yet, each change on its object, with what it needs and whether it is ready or waits, and the command to apply it. A second tab, Findings, lists what is wrong.
- **Inventory.** Where every key is and what it is for: by card, by root, or by date, with one panel for the object you choose.
- **History.** The ceremonies, newest first, each planned, started, recorded or closed. A plan that was never run is folded into one line.
- **Trust set.** The newest trust set, the check of each file and the command that verifies it.

Every command is shown as text with a Copy control. The page reads when you open a screen and when its window gets the focus, never on a timer, and every screen shows the time of its read.

## The demo

[Open the demo](/demo/). It is the real page, built in a demo mode, shown with made-up data. A [bundle](/reference/bundle/) is the directory with a fixed structure that holds everything ritueel knows about one organisation or one person. The example bundles are:

- `acme`: a company with two root cards, three cloud keys (one for each root), a day-to-day card, three roots (X.509, OpenPGP and SSH CA), two delegations and thirteen trust sets. It follows the example of [the bundle page](/reference/bundle/) and has five scenes.
- `globex`: another company, with three roots, each with one cloud key, and no card.
- `personal`: one person, with an OpenPGP key in a key file and three day-to-day cards. Its ceremonies run in the offline system.

Every name, fingerprint, serial and date in it is invented and looks it. Today in the demo is always 2026-11-24.

- **It acts on nothing.** The page has no button that applies, signs, runs, confirms, revokes or publishes. Every command is text with a Copy control.
- **It says the command line is not built yet,** under every command and in the message after Copy: the commands are examples.
- **It says it is a demo,** on every screen, with a link back here.
- **The scenes.** For `acme`, a control "Scene" steps through five moments of one change: a renewal that waits for a request, a user ID added in an editor, the plan printed in the terminal, the signing, and the record. A line says what was done outside the page.
- **You can change the example bundle.** A switch in the bar changes which bundle the page shows. It exists only in the demo.
- **You can change the page state.** A second switch makes the page answer as an empty bundle, a failed read, or no answer yet, so you see how each screen speaks in each case. The Waiting state never ends by itself, on purpose.
- **Its commands follow the [command reference](/reference/cli/).** A few flags are proposals that the reference marks as such.

## What is the same in the program and what is not

| | In the demo | In the program (planned) |
|---|---|---|
| The screens, the words, the states | The real ones | The same build |
| Which bundle | Three example bundles and a switch | The bundle the page is opened on |
| Where the answers come from | Fixtures in the page's build, through an in-memory transport | The ritueel process: one background process, started by the first command, that serves the command line and the page on one fixed loopback port (7488), with a full-rights token for the command line and a one-time page-rights token for the browser that opens only the reads. It is guarded as [the wizard's profile](/reference/wizard/#the-web-page-the-security-profile) says (127.0.0.1 only, an exact Host check and a separate Origin check, one lock for each bundle), and ends after 15 minutes without a call |
| Time of the read | Fixed by the scene | The time of the read; a page left open longer than the process lives shows a failed read |
| What a command does, in History | One sentence for `apply` and one for `close`, from a small catalogue in the page | The same catalogue as the guided mode |

## How it is built

The page and the program talk through an API written in Protobuf and served with ConnectRPC; the command line calls the same process on the same port ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md)). The page's token opens only the reads, and the first build of the page has no write. The page is React with TypeScript, Material UI and Tailwind CSS, built with Vite. The contract is `proto/`, the page is `ui/`, and the page's own README lists its safety rules and what enforces each: no `innerHTML` or `eval`, nothing fetched from another host, every string from the data shown with unusual characters as visible `U+XXXX` codes, a key identified by its full fingerprint, no text field and no control named like an act. These are checked by tests on every pull request.

## Run it yourself

From a checkout, inside the devbox shell:

1. `just ui-install` installs the page's dependencies from its lock file.
2. `just ui-demo` builds the demo into `site/public/demo/`, which the site build copies to `/demo/`.
3. `just ui-test` and `just ui-e2e` run the page's tests, and the page in headless Chrome.

For development, `cd ui && npm run dev` serves the page in demo mode with live reload. [Tools, checks and verification](/contributing/tools/) lists the recipes.
