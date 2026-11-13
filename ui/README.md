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
their own browser to see what is not applied yet, what is wrong, where every key is
and what it is for, what happened, and what outsiders install. It is a **view** and
it writes nothing. Built in **demo mode** it is the demo that is served under `/demo/`
on the site: the real interface, answering from made-up fixtures.

The page shows **one bundle** at a time. A bundle is the directory with a fixed
structure that holds everything ritueel knows about one organisation or one person (for example
`personal` or `acme`): its own history, trust sequence and roots, and, for a company, its
own root list. It is named by its directory. A key is written with the bundle's name
across bundles, `bundle/label`, for example `acme/A`; inside the page it is "key A".
A root is one for each kind (an X.509 anchor, an OpenPGP identity, an SSH CA), built
from keys in any place; "A" and "B" are keys of a root. The trust file of the
CA is "the CA bundle". This README calls the built JavaScript "the build" and never a
bundle. In this contract no call names a bundle; which bundle the process serves is not
decided by the records (record 0010, rules 8 and 9). The demo has three example bundles,
in the order `acme`, `globex`, `personal`, and a switch to choose between them (see
"How the demo mode works").

The page is a view. It has no control that applies, signs, runs, confirms, revokes or
publishes, and no text field. It never asks for or receives a PIN, a passphrase or any
secret. Every screen that names an action shows the command that does it, as text with a
Copy control, and no screen performs one. Confirmation happens in the terminal, in the
offline system or on your workstation: you type the first eight characters of the
plan's digest there. A key that can be copied (a key file) is used only in the offline
system. A key that cannot be copied (a root on cards or in the cloud) may be used on
your workstation, under conditions that record 0005 (rules 17 and 18) lists. A test
root may run on your workstation (wording only, no flag).

The page reads when a screen opens and when its window gets the focus. It has no timer.
Every screen shows the time of its read, and the state is as of that read, not live.

## Screens

Four entries, in this order. To do is the home.

| Route | Screen |
|---|---|
| `#/todo` | To do, tab Not applied yet: every change not applied yet, on its object, with what it needs and whether it is ready or waits; the command to apply them, as text; the bundle block |
| `#/todo/findings` | To do, tab Findings: every finding with its reason, evidence, command and one next step; filter by level |
| `#/inventory`, `#/inventory/cards`, `#/inventory/roots`, `#/inventory/dates` | Inventory in three views: by card, by root, by date. One panel at the right shows the object that is chosen |
| `#/inventory/<view>/<kind>/<id>` | The same view with one object chosen: a `card`, `root`, `key` (by its full fingerprint), `userid`, `delegation`, `certification` or `request` |
| `#/history` and `#/history/<ceremony>` | The ceremonies, newest first, each planned, started, recorded or closed; a plan that was never run is folded into one line; the panel of one ceremony folder |
| `#/trust` | The newest trust set, the check of each file and the command that verifies it |

An unknown hash shows "No such screen", never another screen. The addresses of the older
page (`#/start`, `#/findings`, `#/roots`, `#/key/<label>`, `#/cards`, `#/plan`) are
unknown too.

Every screen handles four states, in honest words: **loaded**, **empty** (the read
worked and nothing is there, with what comes next), **failed** (the read did not
work: never drawn as empty, with the reason, the sentence that the ritueel process ends
after 15 minutes without a call, and a retry) and **waiting** (no answer yet). In the demo,
a switch in the bar at the top ("Example bundle") chooses the example bundle, a second
("Scene", for `acme` only) steps through its five scenes, and a third ("Page state") makes
the in-memory transport answer in each state. The Waiting state never ends by itself, on
purpose, and the screen says so. The ritueel command line is not built yet, and the demo
says so under every command.

## Install, test, build, serve

From the repository, inside the devbox shell, the recipes are: `just ui-install`,
`ui-lint`, `ui-test`, `ui-build`, `ui-demo` (builds the demo into
`site/public/demo/`, where the site build picks it up), `ui-e2e` (the page in Chrome
under the site's own policy), and `proto-gen` / `proto-check` for the generated code
in `src/gen/`. CI runs them. The same steps by hand, from this directory (`cd` there first):

```sh
npm ci                 # or npm install; the network is needed only for this step
npm run typecheck      # tsc --noEmit
npm test               # vitest: banned calls, text safety, every screen with hostile text, the demo transport and the scenes, the contract, links, routes
npm run build          # the demo: tsc, then vite build -> dist/, base path /demo/
node scripts/serve.mjs 8765    # serves dist/ under /demo/ on 127.0.0.1:8765, prints the URL
# open http://127.0.0.1:8765/demo/
npm run e2e -- http://127.0.0.1:8765/demo/       # browser test: keyboard, focus, panel, scenes, states
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

- The ConnectRPC service is in `src/gen/` (generated from `../proto/` by `just
  proto-gen`, with `buf` and `protoc-gen-es`, and committed). The page calls it through
  `createClient(InspectService, transport)`. The service has five reads and no write
  (see `proto/README.md`).
- `src/api/client.ts` loads the transport on first use. `__RITUEEL_MODE__` is a
  build-time constant: in the demo build the transport is `createRouterTransport`
  from `src/api/demo.ts`, in a chunk of its own with the fixtures; in the real
  build it is `createConnectTransport` from `@connectrpc/connect-web` and the
  fixtures are not in the build (`npm run check:dist` checks this).
- The demo handlers answer from `src/fixtures/<bundle>/*.json`, one directory for
  each example bundle, five files each, one for each call, named
  `inspect.<call in kebab case>.json` (the same messages as the real service, parsed with
  the generated schema, so a wrong field is an error). There is no manifest and no shared
  directory. `ListFindings` applies `min_severity` in the transport. The Empty state is
  built by code from the loaded answers (an empty bundle that keeps its name and path).
- Each of the three example bundles is for a different organisation or person, with its own history,
  roots, cards, findings and trust files. The example company is the one of the
  [bundle reference](../docs/reference/bundle.md); the fixtures copy it. `acme` is a
  company with two root cards (`root-a`, `root-b`) and one cloud key service, a
  day-to-day card (`day-ana`), three roots (`acme-tls`, `acme-release`, `acme-ssh`), two
  delegations (`acme-ca`, `acme-release`), the request `acme-ca-2027` and thirteen trust
  sets; the keys are A and B on the two cards and C in the cloud, in each root. `globex` is
  another company with one cloud root and no card. `personal` is one person: an OpenPGP
  key in a key file, three subkeys on day-to-day cards, and a certificate as its only
  trust files, as a personal bundle has no root list. Every name, serial, fingerprint,
  date and count is made up, and looks it. The names of the bundle reference are copied.
  The fixed day is Tuesday 2026-11-24; the first read is at 09:00 UTC.
- The five **scenes** of `acme` are in `src/fixtures/acme/scenes.json`, read by
  `src/api/scenes.ts`. A scene is the base files plus its own patches
  (`set`, and `replace`, `prepend` or `append` for a list), and the time of its read.
  The control "Scene" in the demo bar (`src/ui/SceneSwitch.tsx`) shows the five scenes as
  `Scene N of 5` and, under it, one line that says what was done outside the page. The
  scenes: a renewal that waits for a request; a user ID added in an editor; the plan
  printed in the terminal; the signing; the record. The control is drawn for `acme` and
  the Loaded state only. A patch that names a call, a field or a list the answer does not
  have is an error when the file loads.
- The bundle switch and the scene switch (`src/api/demoState.ts`) are demo chrome only.
  They are not in the contract and not in the real build (`npm run check:dist` checks
  that they are absent from `dist-real/`). Screens never name a bundle: they read its
  name from `GetSummary.bundle.name`. Switching keeps the screen you are on. Only a detail
  view falls back, and only as far as needed (`routeForBundle` in `src/lib/route.ts`, fed
  by what the transport holds for the new bundle or scene): an object to the list of its
  view unless the new bundle or scene has it, a ceremony to History unless it has that
  folder. A fallback replaces the history entry, so Back does not return to an address
  the new bundle cannot show. Until the demo transport has loaded (on the first call)
  nothing says what a bundle holds, and the address is left alone.
- The commands follow [the command reference](../docs/reference/cli.md): one of its
  thirteen words after `ritueel`, and flags it lists. `REASON` and `TEXT` in a command are
  placeholders that the page says to replace. No command holds a digest, and `apply` never
  carries `--confirm`: you type the first eight characters of the digest in the terminal.
  A few flags are proposals that the reference marks as such.
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
| A key is its full fingerprint, in groups of four, never a name or a short id; a row of a key carries the whole fingerprint in `data-key-fp` | `src/ui/Fp.tsx`; `src/inventory.test.tsx` |
| Days are counted from `read_at`, never the browser clock | `src/lib/format.ts`; `src/reads.test.tsx` |
| No text smaller than 12px | `src/safety.test.ts`, "text is readable" |
| No call takes or returns a secret, no call writes, and the page has no text field and no control named like an act | the contract has no field for a secret and no write (`src/contract.test.ts`); the page has choices only; `src/acts.test.tsx`; e2e checks there is no text input on any entry and no control named like an act |
| The page reads when a screen opens and when the window gets the focus, with no timer, and every screen shows the time of its read | `src/reads.test.tsx`; e2e (the focus read) |
| No command holds a digest or `--confirm` | `src/demo.test.ts` (the commands are read from the fixtures, the scenes and the source) |
| Width and height: a list and a panel side by side on a wide screen and no line of text longer than 70 characters; the aim is one screen for To do and at most one and a half for the others | the browser test (layout, measured at 1440 by 900 and 1920 by 970; it prints the numbers, reports a height above its aim and fails above the aim plus 0.15; the aims do not change) |

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
  The number is 7488 (record 0010; the IANA registry lists 7479 to 7490 as unassigned,
  checked on 2026-11-11). What happens when a process of another version answers is still
  proposed.
- There are two kinds of token. A full-rights token, read from a file only the user can
  read, is for the command line. A page-rights token is for the browser: it is used once,
  becomes an `HttpOnly`, `SameSite=Strict` cookie, and can call only the reads (the five
  calls of `InspectService`). No call that confirms, signs, creates a key or runs a
  ceremony is open to it. A ceremony is confirmed in the terminal.
- Every request is checked for its `Host` and, separately, its `Origin`. Before the
  command line sends a confirmation or a PIN, the listener proves that it knows the secret
  in the token file.
- There is one exclusive lock per bundle (record 0010, rule 8). It keeps no
  ceremony state and no PIN.
- It ends after 15 minutes without a call (never in the middle of a running ceremony),
  at once on a stop command, and at logout or reboot.

Other programs of the same user can reach the port while the process runs, so the page
is trusted no more than any other web request. This page does not depend on the
proposed details.

In the real program the same built page (`npm run build:real`, `BASE=./`) is
embedded in the binary and served by that process; `src/api/client.ts` then builds
`createConnectTransport({ baseUrl: '/' })` and the process serves `InspectService`
with connect-go. Gone from the real build: the fixtures, the in-memory transport and the
demo bar (the bundle, scene and state switches). The screens, hooks and generated code do
not change. What the real program must add: the step list of a ceremony (see below), and
the shell quoting of every name inside a command it sends (`apply_command`,
`fix_command`, `revoke_command`, `close_command`, `publish_command`,
`verify_command`): the page shows a command as it is given and copies it only when it is
plain, one line and short, but it cannot tell whether a user ID inside it is quoted. The
one write the page may cause later, an inert proposal that is accepted in the terminal
(record 0010, rule 11), is not built.

## Known gaps

- What `apply` and `close` do is one sentence each in `src/lib/commands.ts` (the guided
  mode, which would share it with the page, does not exist). The panel of a ceremony
  shows the sentence of its command under "What apply does" or "What close does".
- A started ceremony may be running or may have stopped. The page shows what the
  bundle holds at its last read and says what to do in both cases (the Attempt section
  of its panel).
- The page does not say that a new name is a new key (record 0007, rule 28). Where
  and in which words is open: issue #155.
- The folding of the plans that were never run is a choice of the page build (a plan
  that is stale is folded; no record gives an age limit).
- The Empty state shows no starter files: it is an empty bundle.
- Only `acme` has scenes.
- The older request folders of `acme` are not all listed: the fixtures list two answered
  requests.
- The page lists the requests with their answer. It does not compare the limits that a
  request asks for with the limits that the bundle declares, because the contract has no
  field for them and no text decides how they are compared.
- The words that no record and no reference page decides are marked `proposed` in the
  comments of the contract (`proto/ritueel/local/v1alpha1/`) and listed in the pull
  request that added them: the kinds and the two states of a change, the four names of a
  ceremony, the fold of stale plans, the chain states and the status of the history, the
  words for slots and applications, and the texts the program writes for a ceremony and
  a card.
- The paths of the files of a request and of a trust set inside a ceremony folder are
  proposed in the records.
- The layout was measured only in headless Chrome, at 1440 by 900, 1920 by 970, 1280 by
  900, 390 by 844 and 360 by 740. The browser test prints the heights as a multiple of the
  window; some are above their aim (see the pull request).
- Fonts depend on what is installed (see Design).

## What went

The page of the older design had seven entries, a wizard, a plan screen and a save
call. They went with record 0010 and are not built: `PlanService` (`StartPlan`,
`SavePlan`, `ListIntentions`), the types `Intention`, `DueItem`, `Plan` and `PlanStep`
with their questions and refusals, the screens Start, Findings, Roots, Key, Cards and
Plan, the routes `#/start`, `#/findings`, `#/roots`, `#/key/<label>`, `#/cards` and
`#/plan`, the command `ritueel run PLAN --confirm DIGEST`, and the fixtures of the plan
goals. The page now has four entries and no write.
