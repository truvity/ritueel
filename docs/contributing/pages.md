---
title: Pages and writing
description: Where a page of the ritueel site lives, how it says what is built, and how pages, records and reports are written for an engineer reader.
sidebar:
  order: 6
---

The pages on this site teach first: the logic of handling roots and intermediates securely, then what the tools do to simplify it. Everything in this repository is written for an engineer who has not followed the discussion: pages, decision records, research, pull requests and commit messages.

## Where a page lives

Docs live in `docs/`, next to the thing they describe. When the thing changes, its docs change in the same pull request.

| Kind | Where | For |
|---|---|---|
| Learn | `docs/learn/` | The teaching: what a root is, why it stays offline, the custody chain, the key stores compared, the life of a root. Written before any tool exists, and kept true after. It comes first on the site. |
| Guides | `docs/guides/` | One guide per ritual, ceremony or transition, step by step, with its drill on test keys. A guide says how; the matching Learn page says why and when. |
| Tools | `docs/tools/` | What the command line and the wizard do, and whether each is built. |
| Principles | `docs/principles.md` | The rules the design follows, each linked to the record that decides it. |
| Reference | `docs/reference/` | Commands, file formats and the hand-off contract. Exact, versioned, no reasoning. |
| Research | `docs/research/` | Dated results of spikes and research, verdict first ([Spikes and research](/contributing/research/)). The name ends in the date. |
| Decisions | `docs/decisions/` | The decision records. They cite research and reference pages and do not repeat them. |

Say a thing once, in the page that owns it, and link to it from the others: a measurement in its research page, a rule in its record, a format in its reference page.

## What is built

Say it in the first paragraph of a page about a tool or a store: "Planned", "Not built yet", "Partly built: X works, Y does not", or nothing when it is built and released. Change it in the same pull request that builds the thing. A guide never describes a command that does not exist as if it did.

## Page format

Pages are Markdown (`.md`). A page is MDX (`.mdx`) only when it places components, which today is the home page (`docs/index.mdx`) alone. The reasons: `.md` renders readably on GitHub and in other tools, reviews stay text-only, and a broken component in `.mdx` breaks the whole build. Starlight's Markdown already has asides, code blocks, tables and links, so a page that wants any of those stays `.md`. `just check-mdx-pages` fails an `.mdx` file that imports no component or places none ("use .md: MDX only for pages that place components").

The "Edit page" link of each page opens the file in `docs/` (`docs/<page>.md`, or `.mdx`). `site/src/route-middleware.ts` builds it, because Starlight alone would use the path of the symlink under `site/src/content/docs/`; the generated decision pages set their own source file. `check-built.sh` fails when a link does not point at a file in the repository.

## Asides and diagrams

How settled a point is shows in how it is written. Plain prose is agreed. `:::note[Proposed]` is the design as proposed, awaiting the maintainer. `:::caution[Open]` is undecided and links to the decision issue.

Use a table or a short numbered list rather than a diagram. A Mermaid diagram (a ```` ```mermaid ```` fence) may arrive with the site; one that needs scrolling to be read is too big.

## Links

A link to another page uses its site path with a trailing slash, `/learn/key-stores/`. A link to a heading, on the same page or another, uses the full form `/learn/key-stores/#choosing`: the link check is strict and resolves both.

## Home pages

A home page, and the first screen of a section, starts from the reader's pain: what goes wrong when a root is handled badly. Then the mission, then what the project does about each pain, with honest status (designed, built or planned). The mission and the pain come before the feature list and before any logo or badge.

## Plain and short

- Say the verdict first, then the reasons.
- Use plain words and short sentences. Prefer the active voice: "the holder confirms the touch", not "the touch is confirmed".
- Use a table to compare options, versions or numbers, not a paragraph.
- One idea per paragraph. Cut a word that adds nothing.

## Teaching pages

A Learn or Guides page is written for a reader who is new to PKI and OpenPGP but technically capable. Do not explain what a hash is; do explain what a root is. The `teaching-page` skill is the checklist. Judge the page against the mission first ([How we design](/contributing/design/#the-mission-is-the-test)).

- **Start from the reader's question or pain,** not from the feature: what goes wrong in the real world, then the rule. Name the key store or the format before you use its short name.
- **Why before how.** A Learn page gives the reason; a guide gives the steps and links the Learn page that holds the reason.
- **Link the custody chain and the rituals.** Say where in [the custody chain](/learn/custody-chain/) the page sits, and link the ceremony or guide that carries out what it teaches.
- **Mark a tool that is planned as planned,** in the first paragraph ([What is built](#what-is-built)).
- Show a transition as numbered steps with the result of each step: what exists now, what an outsider sees.
- A drill states what the learner starts with, what they do, and how they know it worked.
- A moved or renamed page keeps its old address alive with a redirect ([Changing the site](#changing-the-site)).

## Dated and checkable

- Date every claim that can rot: a measurement, a version, a firmware behaviour, a price, the state of an upstream project. "Measured 2026-10-31" lets the next reader judge it.
- Every external fact carries a source and an "as of" date. Label each claim while you work: **READ** (you read it in the source), **MEASURED** (you ran it; say where and when) or **UNVERIFIED**. The labels go in the pull request and the research page, with the claim and its source. No UNVERIFIED fact goes on a page of the site: confirm it, or leave it out and open an issue.
- A fetch tool summarises a page. Open the source and check any exact quotation, number or version before you publish it.
- Hardware and price facts name the model, the firmware or revision, the price with its currency, the seller or list it came from, and the day.
- Name the version of a tool or a standard when the claim depends on it.
- Cite the principle or the record for a decision, not the day it was made.

## Instructions

- In guidance for people and agents, prefer soft wording ("prefer", "avoid") and say why. Keep "never" and "must" for the rules that have no exception, such as secrets and the public-content rules.
- Write steps as numbered lists in the imperative.

## Files

- Use the `.yaml` extension for YAML files, not `.yml`. The exceptions are the file names a tool requires: `.github/ISSUE_TEMPLATE/config.yml` and `.yarnrc.yml`. `just check-yaml-ext` checks it.
- After an edit, reflow the paragraph you changed so it keeps the wrapping the file already uses.
- Text files use LF line endings; `.gitattributes` enforces it.

## Changing the site

The `site-change` skill is the checklist for a change to `site/`, `site/public/` or the look of a page. The mechanics of the build, the headers and the deploy are in [Tools, checks and verification](/contributing/tools/#the-site).

- **HSTS is preloaded.** The domain is on the browsers' preload list, with a one-year `max-age`, `includeSubDomains` and `preload`. Never lower the header, never serve a name over plain HTTP, and change the line in `site/public/_headers` only to match the zone.
- **The Content-Security-Policy is `'self'` plus Cloudflare Web Analytics and nothing else:** `https://static.cloudflareinsights.com` in `script-src` and `https://cloudflareinsights.com` in `connect-src`. Inline scripts are listed by hash. Do not widen a directive to make a page work; change the page.
- **No remote assets:** no font, script, image, style or embed from another host. Use inline SVG, or a CC0 icon (for example from simple-icons) inlined and used only to name the product it stands for, or an asset in the repository.
- **Edit links point at the real file.** `site/src/route-middleware.ts` rewrites Starlight's "Edit page" URL from `site/src/content/docs/<id>.md` to `docs/<id>.md`, and `site/scripts/check-edit-links.mjs` (run by `check-built.sh`) fails when a link in the built site is not a file in the checkout or not the source of its page. Do not point `editLink.baseUrl` back at `docs/`.
- **A moved or renamed page** gets a `301` line in `site/public/_redirects` in the same pull request, and every link to it is updated.
- **Link checking is bounded.** `lychee` runs with a timeout, bounded retries, a limit on redirects and a wall-clock `timeout` around the whole run, and with `-v` so a stall names its URL. A host that loops on redirects, such as `www.rfc-editor.org`, is excluded in `lychee.toml`. A job that runs past its usual time is a finding: cancel one run, read its log, fix the bound, then rerun.
- **A strict build fails on one warning.** A slow external fetch is such a warning. Retry that one failure; keep strict mode for everything else.
- **Rerunning an old run uses its old merge commit** and so its old configuration. After a fix lands on `main`, a stuck pull request needs a fresh push or a rebuilt branch ([Branches and pull requests](/contributing/workflow/#rebuild-instead-of-rewriting)).
- **A change you can see is seen.** Build and serve the site, then take screenshots with headless Chrome at 1440 px and 390 px wide, in the light and the dark theme. Look at all four and fix what is off before the pull request. There is no horizontal scroll at 375 px.
- **After every deploy,** check with `curl`: the page answers 200, a moved page answers 301 to its new address, and the `Strict-Transport-Security` and `Content-Security-Policy` headers are intact.
