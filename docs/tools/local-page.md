---
title: The local page and its demo
description: The local page is ritueel's view of your own bundle, in your browser. The demo on this site is that page over made-up data. The program behind it is not built.
sidebar:
  order: 3
---

:::caution[Partly built]
The page itself and its [demo](/demo/) exist, as a design to look at and click through. **Planned, not built:** the program that serves the page from your own computer, and every call it makes. It comes with milestone M2 of the [roadmap](/roadmap/). Nothing on the demo reads a real bundle or a real card. ritueel is in its design phase.
:::

The local page is the third face of the program, beside the command line and the guided mode in the terminal ([The wizard](/tools/wizard/)). It is served by the one ritueel process on your own computer, to your own browser, only while you use it, and it is a **view**: it shows your keys, what is due and what is wrong, which card holds what, and it helps you build a plan for the next ceremony. It never confirms anything, and it never asks for or receives a PIN, a passphrase or any secret. You confirm in the terminal, on the offline system or on your workstation, where the ceremony runs.

## The demo

[Open the demo](/demo/). It is the real page, built in a demo mode, shown with made-up data: one holder with three example bundles. A bundle is the directory of one trust domain, with its own ledger, roots and cards, and a root is written `acme/A`. The example bundles are:

- `personal`: the holder's own OpenPGP key in a key file, with its subkeys by year and by card.
- `acme`: a company root pair, `acme/A` and `acme/B`, on two root cards, with delegated keys, trust files and ten ceremonies over three years.
- `globex`: another company's cloud root, which needs no card.

Every name, fingerprint and serial in it is invented and looks it.

- **It acts on nothing.** Every screen that names an action shows the command and a Copy button. "Save the plan" shows what it would write and says that nothing was written.
- **It says it is a demo,** on every screen, with a link back here.
- **You can try a bundle.** A switch in the bar, "Try a bundle", changes which example bundle the page shows. It exists only in the demo: the program serves the one bundle it was started on.
- **You can try the states.** A second switch makes the page answer as an empty bundle, a failed read, or no answer yet, so you see how each screen speaks in each case.
- **The wizard is one sequence:** goal, choices, plan with its digest and the exact command, then save. The plan says where it runs: on the offline system for a root on cards or in a key file, on your workstation for a cloud root. The USB-stick step shows only where it is needed. In the demo the plan is the same whatever you choose.
- **Its commands follow the [command reference](/reference/cli/)** where a command exists there; a few are proposals that the reference does not have yet.

## What is the same in the program and what is not

| | In the demo | In the program (planned) |
|---|---|---|
| The screens, the words, the states | The real ones | The same build |
| Which bundle | Three example bundles and a switch | The one bundle the process was started on |
| Where the answers come from | Fixtures in the page's build, through an in-memory transport | The ritueel process: one long-running background process, started on demand, on a Unix socket for the command line and on the loopback address for the browser while the page is in use. The loopback listener is guarded as the [wizard's rules](/reference/wizard/) say (127.0.0.1 only, exact Host, Origin and Sec-Fetch-Site on every request, no permissive CORS), and is trusted no more than any other web request |
| Saving a plan | Shows the file it would write, `ledger/<ceremony>/plan.json` | Writes one inert file inside your bundle |
| Steps of a ceremony in History | The usual steps of that kind of ceremony | The steps in the plan.json of the ceremony's sub-folder of the ledger |

## How it is built

The page and the program talk through an API written in Protobuf and served with ConnectRPC; the command line calls the same process through a Unix socket ([ADR 0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)), and the page's listener offers only the reads and `SavePlan`; the page is React with TypeScript, Material UI and Tailwind CSS, built with Vite. The contract is `proto/`, the page is `ui/`, and the page's own README lists its safety rules and what enforces each: no `innerHTML` or `eval`, nothing fetched from another host, every string from the data shown with unusual characters as visible `U+XXXX` codes, and a key identified by its full fingerprint. These are checked by tests on every pull request.

## Run it yourself

From a checkout, inside the devbox shell:

1. `just ui-install` installs the page's dependencies from its lock file.
2. `just ui-demo` builds the demo into `site/public/demo/`, which the site build copies to `/demo/`.
3. `just ui-test` and `just ui-e2e` run the page's tests, and the page in headless Chrome.

For development, `cd ui && npm run dev` serves the page in demo mode with live reload. [Tools, checks and verification](/contributing/tools/) lists the recipes.
