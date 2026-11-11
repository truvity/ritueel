---
title: The wizard
description: What the guided mode and the read-only local page drive, how they stay one engine and one API with the commands, and the security profile of the page and its tests.
sidebar:
  order: 14
---

*Partly built: the local page exists as code and a demo (`ui/`, `proto/`); the program that serves it, the guided mode and every test of the profile below are not built. This is the page that [ADR 0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/) leaves for the details; the code is [issue #16](https://github.com/truvity/ritueel/issues/16) for the guided mode (after the first signed release) and [issue #17](https://github.com/truvity/ritueel/issues/17) for the local page (M2). What the wizard is for is on [the Tools page](/tools/wizard/); the threats behind the profile are in [the research](/research/local-wizard-threats-2026-11-01/).*

## What the guided mode and the page drive

The command line, the guided mode and the local page are three faces of one binary and one ceremony engine, and the command line and the page use one API of one ritueel process, written in Protobuf and served with ConnectRPC (`ritueel.local.v1alpha1`) ([ADR 0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)). The page reaches the API over loopback while the page is served; the command line calls it in its own process or over a socket, which is not decided. The page is a read-only view: it changes no key, no ceremony and no record, and it never confirms a ceremony and never sees a secret. A flow in the page ends with a preview and the command to run. The page can save the plan: the process writes `ledger/<ceremony>/plan.json`, where `--plan-only` writes it, so that the holder can boot the offline system and run it there. The offline system is for a card root or a real software root, not for a cloud root or a test root ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-plan-runs)). There is no full-screen terminal interface and no background service.

```sh
ritueel wizard            # the guided mode, in the terminal
ritueel wizard --web      # also serves the read-only page on this computer
```

| Flow | The commands it runs | Notes |
|---|---|---|
| Adopt the roots | `init` | Checks the cards or the cloud roles first, and says what to prepare if they are not ready. |
| Renewals | `due`, then `run` | Shows what is due from `status`, writes the plans, and ends with the command `ritueel run PLAN --confirm DIGEST`. |
| An intermediate | `intermediate add`, `replace`, `revoke` | |
| A transition | `root add`, `root retire`, `root revoke` | One flow for each of the five transitions of [Where a key lives](/learn/key-stores/#moving-between-stores). |
| Trust products | `bundle build`, `keyring build`, the verifiers | Builds and checks; publishing is the operator's. |
| A drill | `drill restore` | |
| A person's key | The personal commands of [personal OpenPGP](/reference/personal-openpgp/) | |

It does not drive the preparation of a card (the maker's tool), the change of a PIN, or publishing. Those are the holder's, and the wizard shows the guide for them.

## One engine

The guided mode and the page ask the engine for a plan with the same options struct the command line builds, shows the plan and its digest, and hand the confirmation to the terminal. They have no code that builds a request, a plan or a signature, and the calls of the page are the API below, nothing else.

- Every step prints the **equivalent command line**, complete, with the flags the choices produced.
- A test runs a wizard session with a fixed clock, collects the commands it printed, runs them, and compares: the plan digests are equal, and so are the records but for the time of the run.
- The text of each step (what this does, what exists after, what to check) is written once, in one catalogue in the repository, and both faces read it. The Learn page that holds the reason is named in it.

### One API

The contract is in `proto/ritueel/local/v1alpha1/` and is not copied here. The version `v1alpha1` is a design and may change before a release.

- **`InspectService`:** six read calls, marked `NO_SIDE_EFFECTS`, so that they may be `GET`.
- **`PlanService`:** `ListIntentions` and `StartPlan`, which read; and `SavePlan`, the only write.
- **No call has a field for a secret, a PIN or a passphrase.** No call confirms, signs, creates a key or runs a ceremony.

## The guided mode

- **Line by line.** Numbered questions, plain text, no full-screen interface, so that a screen reader, a log and a pipe all work.
- **No colour** when `NO_COLOR` is set or the output is not a terminal; the meaning never depends on colour.
- **Not on a pipe.** Without a terminal on standard input, `wizard` refuses, with the usage error (exit code 2) and the equivalent commands; it never prompts into the void.
- **Secrets as in the commands.** A PIN or a passphrase is read by the same no-echo reader, never shown and never written to the transcript or the record.
- **No state of its own.** It reads the directory every time, so it can be stopped and started again.

## The web page: the security profile

`ritueel wizard --web` starts the guided mode and, beside it, a web server for one browser session, for a read-only view. The rules are those of [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules). Every row has a test in the pull request that builds it.

| # | Rule | How | Test |
|---|---|---|---|
| 1 | Loopback only | `net.Listen("tcp4", "127.0.0.1:0")`. There is no flag for another address. The literal is printed, never `localhost` ([the research](/research/local-wizard-threats-2026-11-01/#numbers)). | Starting with another address in the environment or arguments still binds 127.0.0.1; a connection from a non-loopback address is impossible. |
| 2 | A random port | The port is chosen by the operating system at each start, and closed when the session ends. | Two starts give two ports. |
| 3 | A one-time token | 128 random bits, printed once in the address `http://127.0.0.1:PORT/?token=TOKEN`. The first request that carries it is answered with a redirect to `/` and a cookie `ritueel_session`, `HttpOnly; SameSite=Strict; Path=/`; the token then stops working. | A request without a token or a cookie is refused (403); a second use of the token is refused; the address after the redirect has no token; the cookie has the flags. |
| 4 | Host and Origin | `Host` must be exactly `127.0.0.1:PORT`, or the request is refused (403, no detail). For `POST`, `Sec-Fetch-Site` must be `same-origin`, or `Origin` must match `Host` (Go's `http.CrossOriginProtection`). The two checks are separate: the second is no defence against rebinding. | Wrong `Host`, a rebinding-style name, wrong `Origin` and `Sec-Fetch-Site: cross-site` are each refused. |
| 5 | No remote assets | The built files of the page (HTML, scripts, stylesheet) are embedded in the binary; no font, image, script or style from elsewhere, no inline script. The component library writes inline styles at run time (see row 6). | A headless browser with the network blocked loads the page with every asset; the page contains no `http` URL that it loads; the built bundles contain no remote URL (`check:dist` checks this for the page; the program's own test is still to write). |
| 6 | A strict policy | `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Also `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`. The earlier [research](/research/local-wizard-threats-2026-11-01/) lists `style-src 'self'`; the policy differs because the component library of the page writes styles at run time, and the page renders unstyled without it. | Every response carries the headers; `script-src` has no `unsafe-inline` and no host; `style-src` has `unsafe-inline` and no host. |
| 7 | Nothing irreversible from the page | The page has no control that confirms a plan, signs, creates or deletes. It shows the plan and its digest, and ends with the command to run in the terminal, `ritueel run PLAN --confirm DIGEST`, where the confirmation of [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) is asked. It can save the plan file: a plan holds public information only. Reads are calls marked side-effect-free and may be `GET`. The only write is `SavePlan` (`POST`), which rebuilds the plan, refuses a digest that is not the rebuilt plan's, and writes one inert file, `ledger/<ceremony>/plan.json`, create-only. A PIN, a passphrase or a key is never sent to or from the page. | The service descriptor lists no method that confirms, signs, creates or deletes (a test over the descriptor); `SavePlan` with a wrong digest writes nothing. |
| 8 | No telemetry | No call out except those a ceremony needs. The access log goes to the terminal's standard error, without the query string or cookie. | With the network blocked, a full session runs; the log has no token. |
| 9 | A short session | One browser session at a time. It ends when the ceremony is done, on Ctrl-C, or after 15 minutes without a request: the cookie stops working and the port is closed. | An idle session is refused after the time; a second browser is refused. |

`GET` never changes anything: it is used for the six reads, and `SavePlan` is a `POST`. The program does not open a browser by itself: it prints the address, because starting a browser passes the token on a command line that other processes can read. The holder pastes or clicks it.

### What the profile cannot do

Other processes of the same user can reach a loopback port, and a browser extension can read the page. The token and the cookie are the only guard against the first, which is why row 7 exists; the guide tells the holder to use a clean browser profile against the second ([the research](/research/local-wizard-threats-2026-11-01/#what-cannot-be-defended-and-the-advice)).

### The page is usable

Semantic HTML, reachable by keyboard alone, with text and contrast that follow the browser's settings, `prefers-color-scheme` and `prefers-reduced-motion`. The page needs script, so a plan is read in the terminal (`--plan-only`, the guided mode) or in the saved plan file instead.

## Follow-ups

- The guided mode, the catalogue and the conformance test ([issue #16](https://github.com/truvity/ritueel/issues/16)).
- The program side of the local page: the ConnectRPC server, the embedded build, a test for each row, and `SavePlan` writing the ledger path ([issue #17](https://github.com/truvity/ritueel/issues/17)).
