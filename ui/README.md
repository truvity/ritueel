# ritueel, the local page (and its demo)

Status: the page and its demo exist; the program that serves the page is not built
(ritueel is in its design phase), the contract is `v1alpha1` and may change in any
pre-release (no breaking-change check runs). See [the demo](https://ritueel.id/demo/) and
[the design of the process and the page](https://ritueel.id/design/#the-process-and-the-page)
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

The page shows **one bundle** at a time. A bundle is the directory with a fixed
structure that holds everything ritueel knows about one trust domain (for example
`personal` or `acme`): its own history, trust sequence and roots, and, for a company, its
own root list. It is named by its directory. A root is written with the bundle's name
across bundles, `bundle/label`, for example `acme/A`; inside a bundle it is `A`. The
trust file is always "the CA bundle", and its command is `ritueel ca-bundle build`;
this README calls the built JavaScript "the build" and never a bundle. The real
process serves the one bundle it was started on. The demo has three example bundles
and a switch to choose between them (see "How the demo mode works").

The page is a view. It never confirms a ceremony and never asks for or receives a
PIN, a passphrase or any secret. Every screen that names an action shows the
command that does it, and no screen performs one. Confirmation happens in the
terminal, in the offline system or on your workstation. A key that can be copied (a
key file) is used only in the offline system. A key that cannot be copied (a root on
cards or in the cloud) may be used on your workstation, under four conditions that the
plan lists with its counts of signatures and touches (record 0005, rules 17 and 18). A
test root may run on your workstation (wording only, no flag).

## Screens

| Route | Screen |
|---|---|
| `#/start` | The verdict, what is wrong, what is due, the history seal, getting started |
| `#/findings` | Every finding with its reason, evidence, command and one next step; filter by level |
| `#/roots` | The roots of the bundle by store (encrypted file, root cards, cloud KMS) and its delegated keys |
| `#/key/<root label>` | One root of the bundle in full, for example `acme/A`: its certificate, keys, card and delegated keys. For a root that has subkeys, such as `personal/A` and `acme/A`, it adds the subkeys by year and by card or cloud key, and, from three sets on, a matrix and a validity chart |
| `#/cards` and `#/cards/<serial>` | The inventory; one card opened with every slot (a slot opens its details) |
| `#/history` and `#/history/<id>` | The history; one ceremony opened with its steps and records |
| `#/trust` | The trust files and their checks |
| `#/plan` and `#/plan/<goal>` | The wizard: goal, choices, plan with its digest and commands, save |

Goals: `renew-due`, `retire-subkeys`, `adopt-key`, `add-card`, `replace-card`. A
goal that does not apply to the bundle is greyed, with the reason.
An unknown hash shows a "not found" screen, never another screen.

Every screen handles four states, in honest words: **loaded**, **empty** (the read
worked and nothing is there, with what comes next), **failed** (the read did not
work: never drawn as empty, with the reason and a retry) and **waiting** (no
answer yet). In the demo, a switch in the bar at the top ("Example bundle") chooses
the example bundle, and a second ("Page state") makes the in-memory transport
answer in each state. The Waiting state never ends by itself, on purpose, and the screen says so. The ritueel command line is not built yet, and the demo says so under every command.

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
npm run check:dist     # greps both builds: no remote host, demo only in the demo
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
  fixtures are not in the build (`npm run check:dist` checks this).
- The demo handlers answer from `src/fixtures/<bundle>/*.json`, one directory for
  each example bundle (the same messages as the real service, parsed with the
  generated schema, so a wrong field is an error). Each directory has its own
  `manifest.json`, which chooses the file for a call. `src/fixtures/common/` holds
  the refusals the bundles share; a manifest names them as `common/...`.
  `ListFindings` applies `min_severity` in the transport. A call with no recorded
  answer fails loudly. Where an answer in `common/` names the bundle's place (the
  `--dir` of a command, the path of a saved plan), the transport puts the open
  bundle's place in.
- The three example bundles are trust domains of their own, each with its own
  history, roots, cards, findings, trust files and goals. `personal` is one holder's
  OpenPGP key in a key file, with its subkeys by year and by card, and six cards
  (two root cards, three day-to-day cards and a rehearsal card); its trust files are its
  public certificate, as a personal bundle has no root list. Its pair of root cards is
  shared with another bundle of the holder: row 3 of both cards is declared in the card's
  file as that bundle's (drawn as OTHER, with no key digest), and row 4 of card two is
  occupied by a key nobody declared, which is a finding (the names are proposed, record
  0003, issue 11). `acme` is a company with roots `acme/A` and `acme/B` on a pair of
  root cards, delegated keys and six trust files (a CRL for each root). Each record of
  the history says where its ceremony ran (record 0005, rule 2): the first record of
  `acme` ran in the offline system, the others on the workstation. `globex` is another company's cloud root
  `globex/A`, with no card.
- The bundle switch (`src/api/demoState.ts`, "Example bundle", beside "Page
  state") is demo chrome only. It is not in the contract and not in the real
  build (`npm run check:dist` checks that it is absent from `dist-real/`). Screens
  never name a bundle: they read its name from `GetSummary.bundle.name` and write
  roots as `bundle/label`. Switching keeps the screen you are on. Only a detail view
  falls back, and only as far as needed (`routeForBundle` in `src/lib/route.ts`, fed by
  what the transport holds for the new bundle): a card to Cards unless the new bundle
  has that serial, a history record to History unless it has that id, a root's key to
  Roots unless it has a root with that label, and the wizard of a goal to the goals
  unless the new bundle offers the goal (a goal that applies to it). So no route
  points at a card, a root, a record or a goal the new bundle lacks. A fallback
  replaces the history entry, so Back does not return to an address the new bundle
  cannot show. Until the demo transport has loaded (on the first call) nothing says
  what a bundle holds, and the address is left alone. The wizard is keyed by the
  bundle as well as the goal, so after a switch it asks its choices again.
- The one call that would act, `SavePlan`, answers with `written: false`, a notice
  that this is a demo and nothing was written, and the file it would have written.
  The demo shows that file at `history/<ceremony>/plan.json` inside the bundle, the
  place record 0006 (rule 7) decides; the names of the other members of that folder
  are proposed, and the [bundle reference](../docs/reference/bundle.md)
  marks them so. The file is canonical JSON and its SHA-256 is the
  digest ([the ceremony record](../docs/reference/ceremony-record.md)).
  Nothing is written anywhere. The wizard builds a plan in memory (`StartPlan`: questions,
  then the plan with its steps, digest and commands). In the demo the plan is the
  same whatever is chosen. The plan says where it runs (`Plan.run_place`) and with which
  store it signs (`Plan.signing_store`), because the page cannot tell a key file from a
  cloud key by its other data. A key that can be copied (a key file) is used only in the
  offline system. A key that cannot be copied (a root on cards or in the cloud) may be
  used on the workstation, under four conditions: a touch for every signature, the number
  of signatures stated in the plan (`signature_count`, with `touch_count`), no retry of a
  failed touch, and the result checked against the plan on a second device. How the touch
  reads for a cloud key is only proposed (record 0005, issue 30), and the page marks it. The
  stick step (vanilla AirgapOS on the ceremony stick) shows only in the offline system. A
  test root may run on the workstation; that is wording only, as there is no flag for it.
  The commands follow [the command reference](../docs/reference/cli.md): the
  run command is `ritueel --dir BUNDLE run PLAN --confirm DIGEST`, and a plan of an
  empty bundle starts with `init`.
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
- **Licences travel with the code.** The minified build carries no notices, so
  Vite writes the licence of every bundled package into `THIRD-PARTY-LICENSES.md`
  next to `index.html` (`build.license` in `vite.config.ts`), and the footer links
  to it.

## Safety rules, and what enforces them

| Rule | Enforced by |
|---|---|
| No `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, string timers, computed access to those names | `src/safety.test.ts` (scans every source file, comments stripped) |
| No `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `EventSource`, remote URL, remote `@import`, hand-made `<script>`/`<link>` | `src/safety.test.ts`; the CSP; `scripts/check-dist.mjs` on the built files |
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

Runtime (these are in the build):

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

Only the transport. The process is described by [record 0010](../docs/decisions/0010-the-engine-the-process-and-the-page.md),
rules 6 to 12, in plain words:

- There is one ritueel process, the same program as the command line. The first command
  that needs it starts it in the background, and the command line then talks to it. It is
  not a service: it is not installed, never started at login or boot, and never outlives
  logout or reboot. There is no second door for the command line and no separate step that
  the user must run to serve the page.
- It serves the command line and the page on one fixed loopback port (`127.0.0.1` only).
  The number 7488 is proposed and not yet checked against the IANA list of assigned
  ports; what happens when a process of another version answers is also proposed.
- There are two kinds of token. A full-rights token, read from a file only the user can
  read, is for the command line. A page-rights token is for the browser: it is used once,
  becomes an `HttpOnly`, `SameSite=Strict` cookie, and can call only the reads and
  `SavePlan` (`InspectService` and `PlanService`). No call that confirms, signs, creates a
  key or runs a ceremony is open to it. A ceremony is confirmed in the terminal.
- Every request is checked for its `Host` and, separately, its `Origin`. Before the
  command line sends a confirmation or a PIN, the listener proves that it knows the secret
  in the token file.
- There is one exclusive lock per bundle, and the process serves one bundle. It keeps no
  ceremony state and no PIN.
- It ends after 15 minutes without a call (never in the middle of a running ceremony),
  at once on a stop command, and at logout or reboot.

Other programs of the same user can reach the port while the process runs, so the page
is trusted no more than any other web request. This page does not depend on the
proposed details.

In the real program the same built page (`npm run build:real`, `BASE=./`) is
embedded in the binary and served by that process; `src/api/client.ts` then builds
`createConnectTransport({ baseUrl: '/' })` and the process serves `InspectService`
and `PlanService` with connect-go. Gone from the real build: the fixtures, the
in-memory transport, the demo bar, the state switch and the bundle switch. The
screens, hooks and generated code do not change. What the real program must add:
`SavePlan` rebuilds the plan, refuses a digest that is not the rebuilt plan's, and
writes the plan as one inert file, create-only, inside the bundle (the demo shows
`history/<ceremony>/plan.json`, the place record 0006 decides); the step list of a
ceremony (see below); and the shell quoting of every name inside a command it sends
(`fix_command`, `equivalent_command`, `run_command`): the page shows a command as
it is given and copies it only when it is plain, one line and short, but it cannot
tell whether a user ID inside it is quoted.

## Known gaps

- The demo's ceremonies have no plan file. The ceremony screen shows the usual
  steps of that kind of ceremony from a small catalogue in `src/lib/steps.ts`, and
  says so. The real program should send the steps it reads from the plan in the
  history.
- The demo's wizard returns the same plan whatever is chosen (the fixtures have one
  plan per goal).
- The empty state ("Page state") answers the same for every example bundle, and its
  adoption plan is the company, cloud-key case: a root on the workstation and a first
  root list. A personal bundle has no root list and adopts an existing OpenPGP key; the
  demo does not show that adoption.
- The `card-check` records in the acme history and the six-monthly card check among the
  due items are the demo's own idea. The records say the check is read-only and write
  `cards.yaml`; they do not say it writes a history record.
- `PLAN` in the run command is shown as a path relative to the bundle
  (`ritueel --dir ~/ritueel/acme run history/<ceremony>/plan.json ...`). The command
  reference does not say what `PLAN` is relative to, and on the offline system the
  bundle sits at another path, so the `--dir` value is only the path on this computer.
  The preview of the bundle changes lists the history files and the trust files, not each
  root certificate that a ceremony re-issues.
- The personal example shares its pair of root cards with another bundle (a declared row
  and one undeclared row); no server card and no test root are drawn. The kind exists in
  the contract and the Cards screen has a place for it; no example draws it.
- Still proposed in the records, and so shown as proposed: the member names inside
  `history/<ceremony>/`, `trust/<number>/` and `requests/<name>/` (record 0006 decides
  only the folders and `history/<ceremony>/plan.json`); how the touch condition reads for
  a cloud key (record 0005); and the name and the severity of the finding for an occupied
  row that nobody declared (record 0003).
- The page lists no requests: no record asks for a screen of `requests/<name>/`.
- The times of day in the made-up dates are approximate: the days follow the pages, the
  clock does not always follow the ceremony time. The page shows days only.
- Fonts depend on what is installed (see Design).
- Tested in headless Chrome only (1440 and 390 px, light and dark).
