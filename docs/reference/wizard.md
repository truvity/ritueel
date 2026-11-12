---
title: The guided mode and the local page
description: What the guided mode and the read-only local page drive, how they share one engine and one API with the commands, and the security profile of the page.
sidebar:
  order: 14
---

*Partly built: the local page exists as code and a demo (`ui/`, `proto/`); the program that serves it, the guided mode and every test of the profile below are not built. The demo and the contract show the page of [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md): four entries, five reads and no write. This is the page that record 0010 leaves for the details; the code is [issue #16](https://github.com/truvity/ritueel/issues/16) for the guided mode (after the first signed release) and [issue #17](https://github.com/truvity/ritueel/issues/17) for the local page (M2). What the wizard is for is on [the Tools page](/tools/wizard/); the threats behind the profile are in [the research](/research/local-wizard-threats-2026-11-01/).*

## What the guided mode and the page drive

The command line, the guided mode and the local page are three faces of one binary and one ceremony engine. The command line and the page use one API of one ritueel process, written in Protobuf and served with ConnectRPC (`ritueel.local.v1alpha1`) ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rules 1 and 6; [the process](/reference/wizard/#the-ritueel-process)).

"Wizard" means the guided mode of the command line only. The page is no wizard: it makes no plan and has no plan screen (rules 3 and 10).

Rule numbers without a record name are those of record 0010.

The page is a read-only view. It changes no key, no ceremony and no wanted file, it never confirms a ceremony, and it never sees a secret (rule 10). The one write it can cause is an inert proposal, built later ([the proposal](#the-inert-proposal), rule 11).

A change ends in the terminal (rule 22):

1. The person writes the wanted files ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11).
2. `ritueel apply` makes the plan and shows it with its digest ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 4 and 10).
3. The person types the first eight characters of the digest, then gives the PIN and the touch where the store asks (0005, rule 6).

A key that can be copied is used only in the offline system; a key that cannot be copied may also be used on the workstation; a cloud root always runs on the workstation, because the offline system has no network (0005, rules 17, 18 and 20). On the workstation the page shows the progress. In the offline system there is no page and no network, and the progress is in the terminal. The last step, the keyserver upload, is shown with its command and done in the terminal after a typed confirmation: the page has no button (0010, rules 5 and 22). For a key that can be copied, `apply --plan-only` writes the plan in the bundle, and the holder runs it in the offline system ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 7; 0005, rule 21). There is no full-screen terminal interface, and the process is not a service (0010, rules 2 and 9).

```sh
ritueel wizard            # the guided mode, in the terminal
ritueel wizard --web      # prints the address of the read-only page of this computer
```

:::note[Proposed]
The flag `--web`, as the way to ask for the address of the page, is proposed and waits for the maintainer ([#17](https://github.com/truvity/ritueel/issues/17)). Record 0010 decides only that the program prints the address and does not start a browser (rule 12).
:::

### What the guided mode drives

The guided mode drives the ceremonies and the checks. It does not drive the preparation of a card (the maker's tool) or the change of a PIN. Those are the holder's, and the guided mode names the guide for them. Publishing a key to the keyservers is a separate command that runs after a ceremony; the page shows that step with its command and has no button ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rule 5; [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md)).

| Task | The commands | Decided by |
|---|---|---|
| First set-up | `new`, `want`, then `apply` | 0005 rule 15; 0006 rule 11 |
| A change of a wanted file | `want`, then `apply` | 0006 rule 11; 0005 rule 10 |
| A renewal | `apply` | 0005 rule 11 |
| A change of the keys of a root | `want` the keys and the dates, then `apply` | 0007 rules 5 and 12 |
| Trust files | `apply` builds them; `verify` is the host's side | 0006 rules 12, 13 and 28 |
| A drill | `check restore` | 0007 rule 23 |
| A person's key | The wanted files of the person, then `apply` ([personal OpenPGP](/reference/personal-openpgp/)) | 0008 rules 1 and 4 |
| A change of name or address | The wanted user IDs, then `apply` | 0008 rule 17 |
| A revocation | `revoke` | 0007 rule 8 |
| A stopped attempt | `close` | 0005 rule 7 |

:::note[Proposed]
Which of these tasks the guided mode drives, and that it shows the edit of a wanted file that follows and opens `want` for the person, who saves it, are proposed. The guided mode never writes a wanted file itself ([#16](https://github.com/truvity/ritueel/issues/16)).
:::

## One engine

The guided mode asks the engine for a plan with the same options the command line builds, shows the plan and its digest, and hands the confirmation to the terminal. The page does not ask for a plan: `apply` makes it, in the terminal (rule 10). Neither face has code that builds a request, a plan or a signature, and the calls of the page are the API below, nothing else.

- Every step of the guided mode prints the **equivalent command line**, complete, with the flags the choices produced (rule 3).
- A test runs a guided-mode session with a fixed clock, collects the commands it printed, runs them (`apply` with `--confirm DIGEST`), and compares: the plan digests are equal, and so are the ceremony records but for the time of the run (rule 3).
- The text of each step (what this does, what exists after, what to check) is written once, in one catalogue in the repository, and both faces read it. The Learn page that holds the reason is named in it (rule 4).

## The four entries

The page has four entries: To do, Inventory, History and Trust set (rule 10). There is no wizard and no plan screen.

| Entry | What it shows |
|---|---|
| **To do** (the home) | A to-do list with two tabs. "Not applied yet" lists the changes, each on its object, with what it needs and whether it is ready or waits (0005, rule 29). Above the list is the command `ritueel apply`, as text to copy. "Findings" lists what is wrong, each with the command that fixes it. When nothing waits, the page says so and shows the next date. |
| **Inventory** | Where every key is and what it is for. One screen with three views and one panel (see below). |
| **History** | The ceremonies, newest first, each in one of four states. For one ceremony: the plan and its digest in full, to compare; the changes in the plan, and the changes left out with the reason; the sentence "type the first eight characters in the terminal"; and, after the run, the keyserver step with its command. |
| **Trust set** | The newest trust set: its number, its files, the check of each file and the command that verifies it. |

Decided in rule 10: the four entries, the home with the findings as its second tab, the three views with one panel, and no wizard and no plan screen. The demo on the site has the same four entries (rule 17).

:::note[Proposed]
What each entry holds, the four states of a ceremony, the rules for every entry and the aims for width and height, as written in this section ([#17](https://github.com/truvity/ritueel/issues/17)). The page step may change them.
:::

**The three views of the Inventory.** All three show the same keys; the view only changes the order.

| View | Order | Rows |
|---|---|---|
| By card | Where each key is | The cards with their keys by slot, then the cloud keys and the key files |
| By root | What each key is for | The roots, their keys, user IDs, delegations and requests |
| By date | What ends when | The certifications, each with its issuer, its subject and its end date |

- The panel at the right shows one object: a card, a root, a key, a user ID, a delegation, a certification, a request, a ceremony or a trust set. It names the wanted file of the object, with a control to copy the path, the ceremonies that touched it, and the revoke command as text.
- A change that is not applied yet is marked on its object in every view. The chosen object stays chosen when the view changes.
- The panel of a card draws its slots (in use, reserved, empty). A table does not.

**The four states of a ceremony in History.** The states are planned, started, recorded and closed. Each is a fact on disk. The table is on [the ceremony files page](/reference/ceremony-record/#the-states-of-a-ceremony-folder).

A ceremony panel also lists the steps from the catalogue of rule 4.

**Rules for every entry.**

- Every entry has four read states: loaded, empty, failed and waiting.
- Every command is text with a control to copy it. No control is named apply, sign, run, confirm, revoke or publish.
- An entry reads when it opens and when the window gets the focus. There is no timer, and every entry shows the time of its read. A page left open for longer than the process lives (rule 9) shows the state "failed" and says how to start again.
- Width and height are aims and are not measured: a list, a table and a panel from 1440 px; one screen for To do and at most one and a half for each other entry, at 1440 by 900 and at 1920 by 970.

**Plans that were never run.** A plan is written at step 1, before the confirmation, and no command withdraws a plan, so a plan that nobody runs stays in the history. A plan made for the offline system stays "planned" until `join` brings its ceremony record back. History folds the plans that were never run into one line with a count.

:::note[Proposed]
The folding of plans that were never run is a choice of the page build and not a rule of a record ([#17](https://github.com/truvity/ritueel/issues/17)).
:::

## One API

The contract is in `proto/ritueel/local/v1alpha1/` and is not copied here. The version `v1alpha1` is a design and may change before a release. The contract in `proto/` has these five reads.

All calls of the first build are reads. Each is marked `NO_SIDE_EFFECTS`, so that it may be a `GET`. No call has a field for a secret, a PIN or a passphrase, and the calls made with the page-rights token do not confirm, sign, create a key or run a ceremony (rules 7 and 10).

| Call | Feeds |
|---|---|
| `GetSummary` | The frame of every entry: the bundle, the time of the read, counts of findings and changes, the number of ceremonies without a ceremony record, the trust set number |
| `ListFindings` | To do, tab "Findings" |
| `GetInventory` | To do, tab "Not applied yet", and the Inventory: one read that returns roots, keys, delegations, cards, user IDs, certifications, requests and changes together |
| `ListCeremonies` | History |
| `ListTrustFiles` | Trust set |

`GetInventory` is one read, and every call reads the bundle again (rule 9), so the three views cannot show two states of the bundle.

:::note[Proposed]
The names and the shapes of these five calls ([#17](https://github.com/truvity/ritueel/issues/17)). Record 0010 decides that the calls are reads, in rule 7 and rule 10.
:::

## The inert proposal

The write of the page is one inert proposal. It is decided in rule 11 and rule 22 of [record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), and it is built after the first build of the page:

1. The person fills a form in the page.
2. The page leaves a proposal: a file that nothing acts on. It changes no wanted file and makes no plan.
3. In the terminal the person accepts the proposal by typing the first eight characters of its digest.
4. `apply` makes the plan. The person types the first eight characters of the plan's digest, then gives the PIN and the touch where the store asks.

A change that starts in the page is therefore typed twice: eight characters for the proposal and eight for the plan (0010, What it costs).

The first build of the page has no write and no text field. A person edits the wanted file in an editor, through `want`, and the page shows the changes that follow.

:::note[Proposed]
What a proposal may hold and where it waits: the fields the form allows (the page never sees a secret), the folder, the commands that accept or decline it (`want accept` and `want decline`, on the [commands page](/reference/cli/)), the calls that preview and leave it, a base digest, the caps on the number and the size of proposals, what accepting does (a wanted file is written by a person only, [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11), what it does with the text it replaces, and that a proposal is created and never replaced ([#147](https://github.com/truvity/ritueel/issues/147)).
:::

## The ritueel process

- **One process,** the same binary as the command line, started in the background by the first command that needs it. The command line then talks to it. It is not installed as a system service, is never started at login or boot, and never survives logout or a reboot ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rule 9).
- **One door, one fixed loopback port.** The command line and the page call the same API on one fixed port of the loopback address, `127.0.0.1`: one number for ritueel. There is no Unix socket and no second listener. The port number is 7488 (rule 6); the IANA registry lists 7479 to 7490 as unassigned, checked on 2026-11-11.
- **Two kinds of token.** A full-rights token, read from a file that only the user can read, is for the command line, which may call every method, including those that run a ceremony. A page-rights token is for the browser, is used once, and opens only the reads, and the one write of rule 11 once the form is built: no call that confirms, signs, creates a key or runs a ceremony is open to it (rule 7).
- **Checks on every request.** Host and Origin are checked on every request. Before the command line sends a confirmation or a PIN, the listener proves that it knows the secret in the token file. There is one exclusive lock for each bundle (rule 8); the running process holds it (rule 23); a lock kept as a file is later ([bundle](/reference/bundle/#later)).
- **A ceremony is confirmed in the terminal.** The digest typed there goes to the process with the full-rights token. The page's token cannot send it, because no such method is open to it (rule 7; [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 6).
- **No ceremony state, nothing secret kept.** Every call reads the bundle again, so a killed process loses nothing. It keeps nothing secret between calls, never keeps a PIN, and holds no card between calls (rule 9). The process holds a card only during a call, so check 2 of the card checks (`card-held`) is not tripped by ritueel's own process between calls (rule 9).
- **It ends by itself** after 15 minutes without a call, at once on a stop command, and at logout or reboot. A running ceremony is never cut by the timer (rule 9).
- **Costs.** A process that lives between commands is a longer-lived target than one that lives for a command, and a process of an older version can outlive an upgrade.

:::note[Proposed]
Proposed, and waiting for the maintainer's word ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), issue 17): what happens when a process of another version answers; and how a test makes sure that a process ends.

- `ritueel stop` ends the process; that it exits 0 also when none runs is proposed.
- The verifiers that need no bundle (`ritueel verify`) run in the command's own process and start nothing.
:::

## The guided mode

- **Line by line.** Numbered questions, plain text, no full-screen interface, so that a screen reader, a log and a pipe all work (rule 2).
- **No colour** when `NO_COLOR` is set or the output is not a terminal; the meaning never depends on colour.
- **Not on a pipe.** Without a terminal on standard input, `wizard` refuses, with the usage error (exit code 2) and the equivalent commands; it never prompts into the void.
- **Secrets as in the commands.** A PIN or a passphrase is read by the same no-echo reader, never shown and never written to the transcript or the ceremony record.
- **No state of its own.** It reads the bundle every time, so it can be stopped and started again.

## The web page: the security profile

The page is served by the one ritueel process, on its one fixed loopback port, for a read-only view. The program prints the address and does not start a browser ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), rule 12; the way to ask for the address is [proposed](#what-the-guided-mode-and-the-page-drive)). The rules are those of record 0010, rules 7, 8, 10, 11 and 12. Every row has a test in the pull request that builds it. A part of a row that the record has not decided is marked Proposed, and rule 12 does not bind it yet.

| # | Rule | How | Test |
|---|---|---|---|
| 1 | Loopback only | `net.Listen("tcp4", "127.0.0.1:PORT")`, on the one fixed port, 7488. There is no flag for another address, and any other address is refused. The literal is printed, never `localhost` ([the research](/research/local-wizard-threats-2026-11-01/#numbers)). | Starting with another address in the environment or arguments still binds 127.0.0.1; a connection from a non-loopback address is impossible. |
| 2 | One fixed port | The port is the same for the command line and the page, and for every start. It is not chosen by the operating system. | Two starts use the same port; a second process cannot bind it. |
| 3 | A one-time page-rights token | 128 random bits, printed once in the address `http://127.0.0.1:7488/?token=TOKEN`. The first request that carries it is answered with a redirect to `/` and a cookie `ritueel_session`, `HttpOnly; SameSite=Strict; Path=/`; the token then stops working. | A request without a token or a cookie is refused (403); a second use of the token is refused; the address after the redirect has no token; the cookie has the flags. |
| 4 | Host and Origin | `Host` must be exactly `127.0.0.1:7488`, or the request is refused (403, no detail). For `POST`, `Origin` must match `Host` (Go's `http.CrossOriginProtection`). Proposed (#17): `Sec-Fetch-Site` must be `same-origin`. The two checks are separate: the second is no defence against rebinding. | Wrong `Host`, a rebinding-style name, wrong `Origin` and `Sec-Fetch-Site: cross-site` are each refused. |
| 5 | No remote assets | The built files of the page (HTML, scripts, stylesheet) are embedded in the binary; no font, image, script or style from elsewhere, no inline script. The component library writes inline styles at run time (see row 6). | A headless browser with the network blocked loads the page with every asset; the page contains no `http` URL that it loads; the built JavaScript bundles contain no remote URL (`check:dist` checks this for the page; the program's own test is still to write). |
| 6 | A strict policy | `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Proposed (#17), also: `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`. The earlier [research](/research/local-wizard-threats-2026-11-01/) lists `style-src 'self'`; the policy differs because the component library of the page writes styles at run time, and the page renders unstyled without it. | Every response carries the headers; `script-src` has no `unsafe-inline` and no host; `style-src` has `unsafe-inline` and no host. |
| 7 | Nothing irreversible from the page | The page has no control that confirms a plan, signs, creates or deletes. History shows the plan and its digest and says to type the first eight characters in the terminal, where the confirmation of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md) is asked. The page shows the command as text, without the digest in it; the flag `--confirm DIGEST` is for scripts. Reads are calls marked side-effect-free and may be `GET`. The only write the page can cause is the proposal of rule 11: one inert file, which nothing acts on. The first build has no write. A PIN, a passphrase or a key is never sent to or from the page. | The service descriptor lists no method that confirms, signs, creates or deletes (a test over the descriptor), and in the first build no method that writes; the page has no control named like an act (apply, sign, run, confirm, revoke or publish); a call with the page-rights token to a method that is not open to it is refused (404). |
| 8 | No telemetry | No call out except those a ceremony needs. The page's access log has no query string and no cookie. | With the network blocked, a full session runs; the log has no token. |
| 9 | A short session | One browser session at a time. It ends when the ceremony is done or after 15 minutes without a request: the cookie stops working. The process itself ends after 15 minutes without a call ([the process](/reference/wizard/#the-ritueel-process)). | An idle session is refused after the time; a second browser is refused. |

:::note[Proposed]
Additions to the profile: a per-session header, a `Sec-Fetch-Site` same-origin check, no CORS, the extra response headers of row 6, and a tighter content security policy. The reason is that cookies do not isolate by port on localhost (RFC 6265, section 8.5) and a browser extension can read the page. ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), issue 17.)
:::

`GET` never changes anything: it is used for the reads, and a write, when it is built, is a `POST`. The program does not open a browser by itself: it prints the address, because starting a browser passes the token on a command line that other processes can read. The holder pastes or clicks it.

### What the profile cannot do

Other processes of the same user can reach a loopback port while the process runs, and a browser extension can read the page. The tokens and the cookie are the only guard against the first, which is why row 7 exists; the guide tells the holder to use a clean browser profile against the second ([the research](/research/local-wizard-threats-2026-11-01/#what-cannot-be-defended-and-the-advice)).

:::note[Proposed]
A text field cannot tell a passphrase from a user ID. The form of the page could therefore allow only a name, an address or a date, if the maintainer decides so ([#147](https://github.com/truvity/ritueel/issues/147)).
:::

### The page is usable

Semantic HTML, reachable by keyboard alone, with text and contrast that follow the browser's settings, `prefers-color-scheme` and `prefers-reduced-motion` (rule 16). A table with a chosen line and a panel needs rules for the focus; they are the work of the page step. The page needs script, so a plan is read in the terminal (`apply --plan-only`, the guided mode) or in the plan file instead.

## Follow-ups

- The guided mode, the catalogue and the conformance test ([issue #16](https://github.com/truvity/ritueel/issues/16)).
- The program side of the local page: the ConnectRPC server, the embedded build and a test for each row ([issue #17](https://github.com/truvity/ritueel/issues/17)).
- The process behind the commands: start by the first command, the fixed port, the two tokens, the lock for each bundle, the idle end and `ritueel stop`, with tests that a second command reuses the process, `stop` ends it, idleness ends it, and a page-rights token reaches no method that is not open to it ([issue #17](https://github.com/truvity/ritueel/issues/17)).
- The first build of the page is in the repository: the four entries, the five reads and the demo. The program side is not built ([issue #17](https://github.com/truvity/ritueel/issues/17)).

## Later

These are named as later. None is a rule.

- The form of the page and the one write, the inert proposal (record 0010, rule 11, and its Proposed line).
- The commands that accept or decline a proposal.
- A list of the next steps after a run, in the panel of the ceremony in History.
- A store of the texts that accepting a proposal replaces. Until it is built, the copies of the wanted files in each ceremony folder keep the texts that a plan used ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 5).
