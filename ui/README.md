# ritueel, the local page (and its demo)

Status: the page and its demo exist; the program that serves the page is not built
(ritueel is in its design phase). See [the local page](https://ritueel.id/tools/local-page/)
on the site, and `proto/README.md` for the API.

Before you change the interface, read the Material UI guidance for agents in
`.claude/skills/material-ui-tailwind/`, `material-ui-theming/` and
`material-ui-styling/` (copied from the Material UI repository, see
`.claude/skills/NOTICE-mui.md`).

The local page of [ritueel](https://ritueel.id): the screen a holder opens in
their own browser to see their keys, what is due, what is wrong, which card holds
what, and to build a plan for the next ceremony. Built in **demo mode** it is the
demo that is served under `/demo/` on the site: the real interface, answering
from made-up fixtures, refusing to act.

The page shows **one bundle** at a time. A bundle is the directory of one trust
domain (for example `personal` or `acme`), with its own ledger, root list and roots.
A root is written `bundle/label`, for example `acme/A`. The real process serves the
one bundle it was started on. The demo has three example bundles and a switch to
choose between them (see "How the demo mode works").

The page is a view. It never confirms a ceremony and never asks for or receives a
PIN, a passphrase or any secret. Every screen that names an action shows the
command that does it, and no screen performs one. Confirmation happens in the
terminal, on the offline system or on your workstation.

## Screens

| Route | Screen |
|---|---|
| `#/start` | The verdict, what is wrong, what is due, the ledger seal, getting started |
| `#/findings` | Every finding with its reason, evidence, command and one next step; filter by level |
| `#/roots` | The roots of the bundle by store (encrypted file, root cards, cloud KMS) and its delegated keys |
| `#/key/<root label>` | One root of the bundle in full, for example `acme/A`: its certificate, keys, card and delegated keys. For a root that has subkeys, such as `personal/A` and `acme/A`, it adds the subkeys by year and by card or cloud key, and, from three sets on, a matrix and a validity chart |
| `#/cards` and `#/cards/<serial>` | The inventory; one card opened with every slot (a slot opens its details) |
| `#/history` and `#/history/<id>` | The ledger; one ceremony opened with its steps and records |
| `#/trust` | The trust files and their checks |
| `#/plan` and `#/plan/<goal>` | The wizard: goal, choices, plan with its digest and commands, save |

Goals: `renew-due`, `retire-subkeys`, `adopt-key`, `add-card`, `replace-card`. A
goal that does not apply to the bundle is greyed, with the reason.
An unknown hash shows a "not found" screen, never another screen.

Every screen handles four states, in honest words: **loaded**, **empty** (the read
worked and nothing is there, with what comes next), **failed** (the read did not
work: never drawn as empty, with the reason and a retry) and **waiting** (no
answer yet). In the demo, a switch in the bar at the top ("Try the states") makes
the in-memory transport answer in each state. A second switch ("Try a bundle")
chooses the example bundle.

## Install, test, build, serve

From the repository, inside the devbox shell, the recipes are: `just ui-install`,
`ui-lint`, `ui-test`, `ui-build`, `ui-demo` (builds the demo into
`site/public/demo/`, where the site build picks it up), `ui-e2e` (the page in Chrome
under the site's own policy), and `proto-gen` / `proto-check` for the generated code
in `src/gen/`. CI runs them. The same steps by hand, from this directory (`cd` there first):

```sh
npm ci                 # or npm install; the network is needed only for this step
npm run typecheck      # tsc --noEmit
npm test               # vitest: banned calls, text safety, every screen with hostile text, demo transport, every example bundle, links, routes
npm run build          # the demo: tsc, then vite build -> dist/, base path /demo/
node scripts/serve.mjs 8765    # serves dist/ under /demo/ on 127.0.0.1:8765, prints the URL
# open http://127.0.0.1:8765/demo/
npm run e2e -- http://127.0.0.1:8765/demo/       # browser test: keyboard, focus, popover, theme, wizard, states
npm run shots -- http://127.0.0.1:8765/demo/     # screenshots of every screen into shots/
npm run build:real     # the real build -> dist-real/ (real transport, no fixtures)
npm run check:dist     # greps both bundles: no remote host, demo only in the demo
npm run check          # typecheck, test, both builds, check:dist
```

`BASE=./ npm run build` makes a build that works under any path. `SITE_URL` sets
where "Back to ritueel.id" goes (default `https://ritueel.id/`). `npm run dev`
starts the Vite dev server in demo mode. e2e and shots need Chrome (`google-chrome`, or the path in `CHROME`) and use
no library (they drive headless Chrome over the DevTools protocol).

## How the demo mode works

- The ConnectRPC services are in `src/gen/` (generated from `../proto/` by `just
  proto-gen`, with `buf` and `protoc-gen-es`, and committed). The page calls them through
  `createClient(InspectService, transport)` and `createClient(PlanService, transport)`.
- `src/api/client.ts` loads the transport on first use. `__RITUEEL_MODE__` is a
  build-time constant: in the demo build the transport is `createRouterTransport`
  from `src/api/demo.ts`, in a chunk of its own with the fixtures; in the real
  build it is `createConnectTransport` from `@connectrpc/connect-web` and the
  fixtures are not in the bundle (`npm run check:dist` checks this).
- The demo handlers answer from `src/fixtures/<bundle>/*.json`, one directory for
  each example bundle (the same messages as the real service, parsed with the
  generated schema, so a wrong field is an error). Each directory has its own
  `manifest.json`, which chooses the file for a call. `src/fixtures/common/` holds
  the refusals the bundles share; a manifest names them as `common/...`.
  `ListFindings` applies `min_severity` in the transport. A call with no recorded
  answer fails loudly.
- The three example bundles are trust domains of their own, each with its own
  ledger, roots, cards, findings, trust files and goals. `personal` is one holder's
  OpenPGP key in a key file, with its subkeys by year and by card, and six cards.
  `acme` is a company with roots `acme/A` and `acme/B` on a pair of root cards,
  delegated keys and six trust files. `globex` is another company's cloud root
  `globex/A`, with no card.
- The bundle switch (`src/api/demoState.ts`, "Try a bundle", beside "Try the
  states") is demo chrome only. It is not in the contract and not in the real
  build (`npm run check:dist` checks that it is absent from `dist-real/`). Screens
  never name a bundle: they read its name from `GetSummary.bundle.name` and write
  roots as `bundle/label`. Switching also returns the page to `#/start`, so no route
  points at a card or a root the new bundle lacks.
- The one call that would act, `SavePlan`, answers with `written: false`, a notice
  that this is a demo and nothing was written, and the file it would have written:
  `ledger/<ceremony>/plan.json` inside the bundle, where the engine writes any
  plan. The file is canonical JSON and its SHA-256 is the digest
  ([the ceremony record](https://ritueel.id/reference/ceremony-record/)). Nothing is
  written anywhere. The wizard builds a plan in memory (`StartPlan`: questions,
  then the plan with its steps, digest and commands). In the demo the plan is the
  same whatever is chosen. The plan says where it runs (`Plan.run_place`): on the
  offline system for a root on cards or in a key file, on your workstation for a
  cloud root. The USB-stick step shows only on the offline system.
- The state switch makes the same transport answer as an empty bundle, with an
  error, or not at all until the state changes.
- Routes are hash routes, so a static host needs no fallback.
- Nothing is fetched from another host: no CDN, no remote font, no analytics. A
  Content-Security-Policy in `index.html` (`default-src 'self'`, `connect-src
  'self'`, `form-action 'none'`, no inline script) is a second layer.
- **Style needs `'unsafe-inline'`.** Emotion (the engine under MUI) writes its CSS
  into `<style>` elements at run time, so `style-src` keeps `'unsafe-inline'`;
  without it the page renders unstyled (tested). A hash cannot cover CSS that is
  built at run time, and a static host cannot give a nonce per request. Scripts
  stay strict: `script-src 'self'`, no inline script. If a stricter policy is wanted
  later, give Emotion a cache with a fixed nonce and list that nonce in `style-src`
  (not tested).
- **On the site, two policies stack and the stricter wins.** The site's header
  allows Cloudflare Web Analytics; this page's `script-src 'self'` blocks that
  beacon, on purpose (the page has no analytics), and the browser console shows
  one blocked script. The meta tag cannot set `frame-ancestors`, so the protection
  against framing comes from the site's header.
- **The paths are relative to the base.** `index.html` names `scheme.js` and the
  icon through `%BASE_URL%`, so they follow the base path (`/demo/`, or `./` in the
  real build). `/demo` without the slash is redirected to `/demo/` by the site's
  static host.
- **Licences travel with the code.** The minified bundle carries no notices, so
  Vite writes the licence of every bundled package into `THIRD-PARTY-LICENSES.md`
  next to `index.html` (`build.license` in `vite.config.ts`), and the footer links
  to it.

## Safety rules, and what enforces them

| Rule | Enforced by |
|---|---|
| No `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, string timers, computed access to those names | `src/safety.test.ts` (scans every source file, comments stripped) |
| No `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `EventSource`, remote URL, remote `@import`, hand-made `<script>`/`<link>` | `src/safety.test.ts`; the CSP; `scripts/check-dist.mjs` on the built bundles |
| Text from the data shows non-ASCII, bidirectional, zero-width and control characters as `U+XXXX`, and is capped. This holds for every string of the data, identifiers too, and for the attributes (`aria-label`, `title`, `id`, `value`, `href`) | `src/lib/safe.ts`, `src/ui/T.tsx`; `src/text.test.tsx`; `src/hostile.test.tsx` renders every screen with every string of the world ending in a bidirectional override, a joiner and a control character, and fails if one reaches the markup raw, in text or in an attribute |
| The Copy button writes exactly what the screen shows: a command with a newline, a bidirectional or other escaped character, or more than 500 characters is not copied (the button is off and says why) | `copyable` in `src/lib/safe.ts`; tests in `src/text.test.tsx`; e2e reads the clipboard |
| A guide link is a plain site path; a card serial is put into a command only when it is digits | `learnPathOk` in `src/lib/finding.ts`, `isSerial` in `src/lib/safe.ts` |
| A key is its full fingerprint, in groups of four, never a name or a short id | `src/ui/Fp.tsx`; findings join on the full fingerprint (`src/lib/touch.ts`) |
| Days are counted from `as_of`, never the browser clock | `src/lib/format.ts` |
| No text smaller than 12px | `src/safety.test.ts`, "text is readable" |
| No call takes or returns a secret; no free-text field | the contract has no field for one; the wizard has choices only (e2e checks there is no text input) |

The rules are a test and not an ESLint rule on purpose: ESLint's TypeScript parser
does not run on TypeScript 7 yet, and a second TypeScript only for linting was not
worth it. `npm test` is the gate; run it in CI.

## Design

Warm paper and dark ink by day, a lamplit page by night; one accent (a pen
blue-black). Sentences and headings in a serif face, data (fingerprints, commands,
dates) in monospace. No font is shipped or fetched: the stacks in
`src/index.css` name the common serif and monospace faces of the big systems and
end in the generic family. Severity is a colour, a shape and a word together
(diamond critical, triangle alert, disc notice, ring info, tick ok). Slots are
solid (in use), dashed (reserved), dotted (spare), thin (empty).

The design lives in `src/theme.ts` (MUI 9 theme, light and dark colour schemes with
CSS variables). `src/index.css` hands the same variables to Tailwind v4 with
`@theme inline`. Cascade layers follow MUI's guide: `@layer theme, base, mui,
components, utilities;`, `StyledEngineProvider enableCssLayer`, so Tailwind
utilities do layout and win over MUI without `!important`. One unlayered
`:focus-visible` rule gives every control the same ring (it beats MUI's
`outline: 0`).

## Dependencies

Runtime (these are in the bundle):

| Package | Version | Licence |
|---|---|---|
| @bufbuild/protobuf | 2.16.0 | Apache-2.0 AND BSD-3-Clause |
| @connectrpc/connect | 2.3.0 | Apache-2.0 |
| @connectrpc/connect-web | 2.3.0 | Apache-2.0 (real build only) |
| @emotion/react | 11.14.0 | MIT |
| @emotion/styled | 11.14.1 | MIT |
| @mui/material | 9.5.0 | MIT |
| react, react-dom | 19.3.1 | MIT |

Build and test only:

| Package | Version | Licence |
|---|---|---|
| tailwindcss, @tailwindcss/vite | 4.3.5 | MIT |
| vite | 8.3.7 | MIT |
| @vitejs/plugin-react | 6.3.0 | MIT |
| vitest | 5.1.0 | MIT |
| typescript | 7.0.2 | Apache-2.0 |
| @types/react, @types/react-dom | 19.3.0 | MIT |
| @types/node | 24.x | MIT |

No router, no state library, no font package, no ESLint, no screenshot library.

## What the real program replaces

Only the transport. The process is the owner's decision of 2026-11-11: one
long-running background process, started on demand, bound to a Unix socket. The
command line uses the socket. A browser cannot open a Unix socket, so the page
reaches the same process over the loopback address while the page is in use. Both
get the same calls and the same answers, and the process serves one bundle. Same calls, not the same trust: the loopback listener binds 127.0.0.1 only, checks the Host header exactly and Origin or Sec-Fetch-Site on every request, and sets no permissive CORS header ([reference/wizard](https://ritueel.id/reference/wizard/), rules 1 and 4). It has the same calls as the socket, but any program or web page on the computer can send it a request, so it is trusted no more than any other web request.

In the real program the same page bundle (`npm run build:real`, `BASE=./`) is
embedded in the binary and served by that process; `src/api/client.ts` then builds
`createConnectTransport({ baseUrl: '/' })` and the process serves `InspectService`
and `PlanService` with connect-go. Gone from the real build: the fixtures, the
in-memory transport, the demo bar, the state switch and the bundle switch. The
screens, hooks and generated code do not change. What the real program must add:
`SavePlan` actually writes `ledger/<ceremony>/plan.json` into the bundle, one inert
file, create-only, in the form the engine uses for any plan; the step list of a
ceremony (see below); and the shell quoting of every name inside a command it sends
(`fix_command`, `equivalent_command`, `run_command`): the page shows a command as
it is given and copies it only when it is plain, one line and short, but it cannot
tell whether a user ID inside it is quoted.

## Known gaps

- The demo's ceremonies have no plan file. The ceremony screen shows the usual
  steps of that kind of ceremony from a small catalogue in `src/lib/steps.ts`, and
  says so. The real program should send the steps it reads from the plan in the
  ledger.
- The demo's wizard returns the same plan whatever is chosen (the fixtures have one
  plan per goal).
- Fonts depend on what is installed (see Design).
- Tested in headless Chrome only (1440 and 390 px, light and dark).
