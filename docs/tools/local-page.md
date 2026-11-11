---
title: The local page and its demo
description: The local page is ritueel's view of your own bundle, in your browser. The demo on this site is that page over made-up data. The program behind it is not built.
sidebar:
  order: 3
---

:::caution[Partly built]
The page itself and its [demo](/demo/) exist, as a design to look at and click through. **Planned, not built:** the program that serves the page from your own computer, and every call it makes. It comes with milestone M2 of the [roadmap](/roadmap/). Nothing on the demo reads a real bundle or a real card. ritueel is in its design phase.
:::

The local page is the third face of the program, beside the command line and the guided mode in the terminal ([The wizard](/tools/wizard/)). It is served by the one ritueel process on your own computer, to your own browser, only while you use it, and it is a **view**: it shows your keys, what is due and what is wrong, which card holds what, and it helps you build a plan for the next ceremony. It never confirms anything, and it never asks for or receives a PIN, a passphrase or any secret. You confirm in the terminal, on your workstation or on the offline system, where the ceremony runs.

## The demo

[Open the demo](/demo/). It is the real page, built in a demo mode, shown with made-up data: one holder with three example bundles. A [bundle](/reference/bundle/) is the directory with a fixed structure that holds everything ritueel knows about one trust domain, with its own history, roots and cards. Across bundles a root is written with the bundle's name, `acme/A`. The example bundles are:

- `personal`: the holder's own OpenPGP key in a key file, with its subkeys by year and by card, two root cards, three day-to-day cards and a rehearsal card. Its trust file is the public certificate, in two forms.
- `acme`: a company root pair, `acme/A` and `acme/B`, on two root cards, with delegated keys, the trust files (a CRL for each root) and ten ceremonies over three years.
- `globex`: another company's cloud root, which needs no card.

Every name, fingerprint and serial in it is invented and looks it.

- **It acts on nothing.** Every screen that names an action shows the command and a Copy button. "Save the plan" shows what it would write and says that nothing was written.
- **It says the command line is not built yet,** under every command and in the message after Copy: the commands are examples.
- **It says it is a demo,** on every screen, with a link back here.
- **You can change the example bundle.** A switch in the bar, "Example bundle", changes which example bundle the page shows. It exists only in the demo: the program shows the bundle the page is opened on.
- **You can change the page state.** A second switch, "Page state", makes the page answer as an empty bundle, a failed read, or no answer yet, so you see how each screen speaks in each case. The Waiting state never ends by itself, on purpose, and the screen says so; choose another page state to end it. In the Empty state the wizard answers as an empty bundle, not with the loaded bundle's data.
- **The wizard is one sequence:** goal, choices, plan with its digest and the exact command, then save. The plan says where it runs: in the offline system for a key that can be copied, a key file; on your workstation or in the offline system for a root on cards or a cloud root. The USB-stick step shows only where it is needed. In the demo the plan is the same whatever you choose, except in the Empty state, where it is an example plan for an empty bundle.
- **Its commands follow the [command reference](/reference/cli/)** where a command exists there, with `--dir` naming the bundle in a command that runs a plan; a few are proposals that the reference does not have yet (the personal key's `primary`, `userid` and `subkey revoke` commands, and the flag that names a cloud key to adopt).
- **Where the saved plan goes.** [Record 0006](../decisions/0006-bundle-history-and-trust-files.md) decides that the running process writes it inside your bundle, at `history/<ceremony>/plan.json`. The demo shows that place. The exact member names inside the folders are still to be fixed with the code, so the file name is not final.

## What is the same in the program and what is not

| | In the demo | In the program (planned) |
|---|---|---|
| The screens, the words, the states | The real ones | The same build |
| Which bundle | Three example bundles and a switch | The bundle the page is opened on |
| Where the answers come from | Fixtures in the page's build, through an in-memory transport | The ritueel process: one background process, started by the first command, that serves the command line and the page on one fixed loopback port (7488), with a full-rights token for the command line and a one-time page-rights token for the browser. It is guarded as [the wizard's profile](/reference/wizard/#the-web-page-the-security-profile) says (127.0.0.1 only, an exact Host check and a separate Origin check, one lock for each bundle), and ends after 15 minutes without a call |
| Saving a plan | Shows the file it would write, at `history/<ceremony>/plan.json`, and says that nothing was written | The process rebuilds the plan, and writes one inert file inside your bundle (the place is in [record 0006](../decisions/0006-bundle-history-and-trust-files.md), see above) |
| Steps of a ceremony in History | The usual steps of that kind of ceremony | The steps in the plan.json of the ceremony's sub-folder of the history |

## How it is built

The page and the program talk through an API written in Protobuf and served with ConnectRPC; the command line calls the same process on the same port ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md)), and the page's token opens only the reads and `SavePlan`; the page is React with TypeScript, Material UI and Tailwind CSS, built with Vite. The contract is `proto/`, the page is `ui/`, and the page's own README lists its safety rules and what enforces each: no `innerHTML` or `eval`, nothing fetched from another host, every string from the data shown with unusual characters as visible `U+XXXX` codes, and a key identified by its full fingerprint. These are checked by tests on every pull request.

## Run it yourself

From a checkout, inside the devbox shell:

1. `just ui-install` installs the page's dependencies from its lock file.
2. `just ui-demo` builds the demo into `site/public/demo/`, which the site build copies to `/demo/`.
3. `just ui-test` and `just ui-e2e` run the page's tests, and the page in headless Chrome.

For development, `cd ui && npm run dev` serves the page in demo mode with live reload. [Tools, checks and verification](/contributing/tools/) lists the recipes.
