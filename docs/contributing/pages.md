---
title: Pages and writing
description: Where a page of the ritueel site lives, how it says what is built, and how pages, records and reports are written for an engineer reader.
sidebar:
  order: 6
---

The pages on this site teach first: the logic of handling roots and intermediates securely, then what the tools do to simplify it. Everything in this repository is written for an engineer who has not followed the discussion: pages, decision records, research, pull requests and commit messages.

## What is published

What ritueel.id publishes is the list in `site/published.txt`, and nothing else. A new page is added to the list only if a reader of the target needs it: the path of six, the going-further pages, the three pictures pages of How it works, the glossary, where it stands, the decisions. Everything else is written under `docs/` at its usual path and read on GitHub: it is working material of the design. Do not add a page to the list to make a link work; link it as usual, and the build turns a link to an unpublished page into a link to the file on GitHub.

Today the site publishes the Learn index and its ten pages, the three How it works pages (the overview, the three cards, the bundle and the USB stick), the demo (`/demo/`, a build product of `ui/`), the glossary, the roadmap, the status page (`/status/`), the decision records as an archive, the hand-off contract and the 404 page. Guides, Tools, Reference (apart from the hand-off contract), Principles, Research and Contributing are not on the site.

The menu has six entries, Learn, How it works, Demo, Glossary, Where it stands and Decisions, written in `site/astro.config.mjs`. A page is added to the menu there, and its slug must also be a line of `site/published.txt`. The hand-off contract is not in the menu; the decisions index links it.

## Where a page lives

Docs live in `docs/`, next to the thing they describe. When the thing changes, its docs change in the same pull request. The last column says whether the kind is on the site ([What is published](#what-is-published)).

| Kind | Where | For | Published? |
|---|---|---|---|
| Learn | `docs/learn/` | The teaching: what a root is, why it stays offline, the custody chain, the key stores compared, the life of a root. Written before any tool exists, and kept true after. It comes first on the site. | The Learn index and ten pages of the list |
| How it works | `docs/how-it-works/` | ritueel in pictures: the five ideas, the ceremony, the three cards, the bundle and the USB stick. Few words, each picture with its caption. The program is not built, so each page says once that the pictures show the design. | Yes: the overview and two pages |
| Guides | `docs/guides/` | One guide per ritual, ceremony or transition, step by step, with its drill on test keys. A guide says how; the matching Learn page says why and when. | No |
| Tools | `docs/tools/` | What the command line and the wizard do, and whether each is built. | No |
| Principles | `docs/principles.md` | The rules the design follows, each linked to the record that decides it. | No |
| Reference | `docs/reference/` | Commands, file formats and the hand-off contract. Exact, versioned, no reasoning. | Only the hand-off contract |
| Research | `docs/research/` | Dated results of spikes and research, verdict first ([Spikes and research](/contributing/research/)). The name ends in the date. | No |
| Decisions | `docs/decisions/` | The decision records. They cite research and reference pages and do not repeat them. | Yes, as an archive |

Say a thing once, in the page that owns it, and link to it from the others: a measurement in its research page, a rule in its record, a format in its reference page.

## What is built

Say it in the first paragraph of a page about a tool or a store: "Planned", "Not built yet", "Partly built: X works, Y does not", or nothing when it is built and released. Change it in the same pull request that builds the thing. A guide never describes a command that does not exist as if it did.

## Page format

Pages are Markdown (`.md`). A page is MDX (`.mdx`) only when it places components. Today those are the home page (`docs/index.mdx`), the three pages of `docs/how-it-works/`, and the two Learn pages that carry figures, `how-a-yubikey-holds-keys.mdx` and `how-passkeys-work.mdx`. A page that places `<Figure>` or `<Proposed>` is `.mdx`; a page with only asides stays `.md`. The reasons: `.md` renders readably on GitHub and in other tools, reviews stay text-only, and a broken component in `.mdx` breaks the whole build. Starlight's Markdown already has asides, code blocks, tables and links, so a page that wants only those stays `.md`. `just check-mdx-pages` fails an `.mdx` file that imports no component or places none ("use .md: MDX only for pages that place components"). An `.mdx` page other than the home page also carries `slug:` with its own address (`slug: learn/how-passkeys-work`): the link validator reads an MDX page by its real path under `docs/`, outside the site's content directory, and without `slug:` it takes every link to the page, and every link to a heading of it, for broken. `site/test/figures.test.mjs` checks the value.

The "Edit page" link of each page opens the file in `docs/` (`docs/<page>.md`, or `.mdx`). `site/src/route-middleware.ts` builds it, because Starlight alone would use the path of the symlink under `site/src/content/docs/`; the generated decision pages set their own source file. `check-built.sh` fails when a link does not point at a file in the repository.

## Asides

How settled a point is shows in how it is written. Plain prose is agreed. `:::note[Proposed]` is the design as proposed, awaiting the maintainer. `:::caution[Open]` is undecided and links to the decision issue. A decision that is made and not yet proven on hardware is plain prose that says so: "decided, not yet proven", with the record that decides it.

In an `.mdx` page write `<Proposed>…</Proposed>` instead of the directive. It is the same note, titled "Proposed", and it comes from `site/src/components/Proposed.astro`: a page under `docs/` has no `node_modules` to resolve a bare import from, so an `.mdx` page imports site components by a relative path (`import Proposed from '../../site/src/components/Proposed.astro'`).

## Figures

A figure is a drawing on the page. Draw when a picture says it better than a table or a short numbered list: what moves between whom and in which order, where things sit on a card or a stick. A table is still the way to compare options, versions or numbers. One figure makes one claim. A page that is only a picture of text it already has does not get a figure.

**Where they live.** A figure is a Node module in `site/figures/<name>.mjs`, registered in `site/figures/index.mjs`, and a page places it with `<Figure name="…">caption</Figure>` after `import Figure from '../../site/src/components/Figure.astro'`. The drawing is inline SVG, built from the helpers of `site/figures/draw.mjs`; the slots of the cards come from the one table in `site/figures/slots.mjs`, so the wide and the tall drawing of a card cannot differ. Not a raw `<svg>` in a `.md` page (GitHub strips it), not an image file (it cannot follow the light and the dark theme), not Mermaid (it needs a script, and the policy lists scripts by hash). The styles are `site/src/styles/figures.css`, which ships only on a page that places a figure.

**The look.** Ink is `currentColor`; every other colour is a Starlight variable, so both themes work with no second copy. One accent marks the one thing the figure is about, with a heavier outline as a second cue. A held slot is a solid outline with a key, an empty slot is dashed, a row kept free is dotted and hatched.

**Words and sizes.** A label in a drawing is at most three words and at least 12 px at the drawn scale; a sentence belongs in the caption. Every arrow has a label that says what it does ("copies", "signs"). The caption is one or two sentences in the page, and states what the figure shows. The `aria-label` says what is drawn and does not repeat the caption. A strip is six panels, each 280 by 224 units, each with a title of one or two words and a caption of at most 18 words. A layout has a wide drawing (760 units) and a tall one (360 units) for a phone; CSS shows one by the width of its column. Use the fixed words of the glossary, and none of the words the design dropped ("staff", "board card", "ceremony machine", "test card", "folder" for a bundle). Draw no real name, serial, address or secret: examples are `acme`, `globex`, `example.com` and `00000001`.

**What a figure says about the design.** The program is not built, and each page that carries figures says so once, near the top. A name or a layout that is only proposed is marked with a note titled "Proposed" next to the figure, and the figure carries the same word where it prints the name; where a name is still being changed, the figure prints none. A fact from outside, such as another project's slot plan, carries its source and the day it was read in the caption.

**Checks.** `site/test/figures.test.mjs` runs in `just site-lint` and checks every figure: the size and the number of panels, the label on each drawing, the classes against `figures.css`, no font under 12 px, the label length, a label on every arrow, one accent object, the banned words, and that every `<Figure name>` in `docs/` is registered and every registered figure is placed. `site/scripts/check-built.sh` checks the built pages: a figure page holds its `<figure>` and drawings with `role="img"`. Neither one sees what is drawn. Look at it: `node site/figures/preview.mjs <dir>` writes one standalone page per figure and theme, to open in headless Chrome. Check at 1280 px and at 390 px, in the light and the dark theme, that nothing overlaps or is cut off and that the page does not scroll sideways.

## Links

A link to another page uses its site path with a trailing slash, `/learn/key-stores/`. A link to a heading, on the same page or another, uses the full form `/learn/key-stores/#choosing`: the link check is strict and resolves both.

Write this site path form for every page, published or not. The build rewrites a link to a page that is not published into a link to its file on GitHub, anchor kept (`site/lib/docs-links.mjs`), so a link comes back to the site by itself when the page is published. `site/scripts/check-github-links.mjs` checks that the file and the heading of each rewritten link exist.

## Home pages

A home page says what the project is, what exists today, who it is for and where to start, in about 400 words at most, with about ten links in the text, besides a row of the menu entries, which the home page carries because it has no sidebar. It gives an honest status (designed, built or planned) and promises no tool that is not built. It may carry a short block of the project's main ideas, one sentence each, that links to How it works. Prose that starts from the reader's pain belongs in the Learn pages, not on the home page.

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
- A moved or renamed page keeps its old address alive with a redirect ([Changing the site](#changing-the-site)). A Learn or Guides page reaches the site only if it is in `site/published.txt`.

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
- **The Worker runs first for `/api/*` only.** Every other request is a static asset and never invokes the Worker, which keeps the site off the Free plan's daily Worker request limit. Never widen `assets.run_worker_first` in `site/wrangler.jsonc`, and never turn on Workers Cache. The page script of the live status stays a file of this site (`vite.build.assetsInlineLimit` is 0), so the Content-Security-Policy needs no new entry.
- **No remote assets:** no font, script, image, style or embed from another host. Use inline SVG, or a CC0 icon (for example from simple-icons) inlined and used only to name the product it stands for, or an asset in the repository.
- **Edit links point at the real file.** `site/src/route-middleware.ts` rewrites Starlight's "Edit page" URL from `site/src/content/docs/<id>.md` to `docs/<id>.md`, and `site/scripts/check-edit-links.mjs` (run by `check-built.sh`) fails when a link in the built site is not a file in the checkout or not the source of its page. Do not point `editLink.baseUrl` back at `docs/`.
- **A moved or renamed page** gets a `301` line in the hand-written part of `site/public/_redirects` in the same pull request, and every link to it is updated. A page that is not published is redirected (`302`) to its file on GitHub by the generated block of the same file: run `just site-redirects` and commit the result. `just site-lint` fails when the block is out of date. The block holds each address with and without its closing slash; and the no-slash form of each hand line too, so a hand line is written with the slash only.
- **Link checking is bounded.** `lychee` runs with a timeout, bounded retries, a limit on redirects and a wall-clock `timeout` around the whole run, and with `-v` so a stall names its URL. A host that loops on redirects, such as `www.rfc-editor.org`, is excluded in `lychee.toml`. A job that runs past its usual time is a finding: cancel one run, read its log, fix the bound, then rerun.
- **A strict build fails on one warning.** A slow external fetch is such a warning. Retry that one failure; keep strict mode for everything else.
- **Rerunning an old run uses its old merge commit** and so its old configuration. After a fix lands on `main`, a stuck pull request needs a fresh push or a rebuilt branch ([Branches and pull requests](/contributing/workflow/#rebuild-instead-of-rewriting)).
- **A change you can see is seen.** Build and serve the site, then take screenshots with headless Chrome at 1440 px and 390 px wide, in the light and the dark theme. Look at all four and fix what is off before the pull request. There is no horizontal scroll at 375 px.
- **After every deploy,** check with `curl`: the page answers 200, a moved page answers 301 to its new address, an unpublished address answers 302 to `github.com/truvity/ritueel/blob/main/docs/...`, and the `Strict-Transport-Security` and `Content-Security-Policy` headers are intact.
