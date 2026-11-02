---
title: The wizard
description: What the terminal wizard and the localhost web wizard drive, how they stay one engine, and the security profile of the web page with a test for each row.
sidebar:
  order: 14
---

*Not built yet. This is the page that [ADR 0011](/decisions/0011-the-wizards-one-engine-two-faces-and-a-web-page-that-cannot-confirm-anything/) leaves for the details; the code is [issue #16](https://github.com/truvity/ritueel/issues/16) for the terminal and [issue #17](https://github.com/truvity/ritueel/issues/17) for the web page, in M4. What the wizard is for is on [the Tools page](/tools/wizard/); the threats behind the profile are in [the research](/research/local-wizard-threats-2026-11-01/).*

## What the wizards drive

```sh
ritueel wizard            # in the terminal
ritueel wizard --web      # also serves the page on this computer
```

| Flow | The commands it runs | Notes |
|---|---|---|
| Adopt the roots | `init` | Checks the cards or the cloud roles first, and says what to prepare if they are not ready. |
| A yearly ceremony | `yearly` | Shows what is due from `status`. |
| An intermediate | `intermediate add`, `replace`, `revoke` | |
| A transition | `root add`, `root retire`, `root revoke` | One flow for each of the five transitions of [Where a key lives](/learn/key-stores/#moving-between-stores). |
| Trust products | `bundle build`, `keyring build`, the verifiers | Builds and checks; publishing is the operator's. |
| A drill | `drill restore` | |
| A person's key | The personal commands of [personal OpenPGP](/reference/personal-openpgp/) | |

It does not drive the preparation of a card (the maker's tool), the change of a PIN, or publishing. Those are the holder's, and the wizard shows the guide for them.

## One engine

A wizard asks the engine for a plan with the same options struct the command line builds, shows the plan and its digest, and hands the confirmation to the terminal. It has no code that builds a request, a plan or a signature.

- Every step prints the **equivalent command line**, complete, with the flags the choices produced.
- A test runs a wizard session with a fixed clock, collects the commands it printed, runs them, and compares: the plan digests are equal, and so are the records but for the time of the run.
- The text of each step (what this does, what exists after, what to check) is written once, in one catalogue in the repository, and both wizards read it. The Learn page that holds the reason is named in it.

## The terminal wizard

- **Line by line.** Numbered questions, plain text, no full-screen interface, so that a screen reader, a log and a pipe all work.
- **No colour** when `NO_COLOR` is set or the output is not a terminal; the meaning never depends on colour.
- **Not on a pipe.** Without a terminal on standard input, `wizard` refuses, with the usage error (exit code 2) and the equivalent commands; it never prompts into the void.
- **Secrets as in the commands.** A PIN or a passphrase is read by the same no-echo reader, never shown and never written to the transcript or the record.
- **No state of its own.** It reads the directory every time, so it can be stopped and started again.

## The web page: the security profile

`ritueel wizard --web` starts the terminal wizard and, beside it, a web server for one browser session. The rules are those of [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules). Every row has a test in the pull request that builds it.

| # | Rule | How | Test |
|---|---|---|---|
| 1 | Loopback only | `net.Listen("tcp4", "127.0.0.1:0")`. There is no flag for another address. The literal is printed, never `localhost` ([the research](/research/local-wizard-threats-2026-11-01/#numbers)). | Starting with another address in the environment or arguments still binds 127.0.0.1; a connection from a non-loopback address is impossible. |
| 2 | A random port | The port is chosen by the operating system at each start, and closed when the session ends. | Two starts give two ports. |
| 3 | A one-time token | 128 random bits, printed once in the address `http://127.0.0.1:PORT/?token=TOKEN`. The first request that carries it is answered with a redirect to `/` and a cookie `ritueel_session`, `HttpOnly; SameSite=Strict; Path=/`; the token then stops working. | A request without a token or a cookie is refused (403); a second use of the token is refused; the address after the redirect has no token; the cookie has the flags. |
| 4 | Host and Origin | `Host` must be exactly `127.0.0.1:PORT`, or the request is refused (403, no detail). For `POST`, `Sec-Fetch-Site` must be `same-origin`, or `Origin` must match `Host` (Go's `http.CrossOriginProtection`). The two checks are separate: the second is no defence against rebinding. | Wrong `Host`, a rebinding-style name, wrong `Origin` and `Sec-Fetch-Site: cross-site` are each refused. |
| 5 | No remote assets | The HTML, one stylesheet and one script are embedded in the binary and hand-written; no font, image, script or style from elsewhere, no inline script or style. | A headless browser with the network blocked loads the page with every asset; the page contains no `http` URL that it loads. |
| 6 | A strict policy | `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Also `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`. | Every response carries the headers; the policy has no `unsafe-inline` and no host. |
| 7 | Nothing irreversible from the page | The page has no control that confirms a plan, signs, creates or deletes. It shows the plan and its digest and says: type the first eight characters in the terminal. The terminal prompt of [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) waits; the page polls the state with `GET`. A PIN, a passphrase or a key is never sent to or from the page. | A `POST` that tries to confirm is refused and changes nothing; the state of the ceremony is unchanged. |
| 8 | No telemetry | No call out except those a ceremony needs. The access log goes to the terminal's standard error, without the query string or cookie. | With the network blocked, a full session runs; the log has no token. |
| 9 | A short session | One browser session at a time. It ends when the ceremony is done, on Ctrl-C, or after 15 minutes without a request: the cookie stops working and the port is closed. | An idle session is refused after the time; a second browser is refused. |

`GET` never changes anything. The program does not open a browser by itself: it prints the address, because starting a browser passes the token on a command line that other processes can read. The holder pastes or clicks it.

### What the profile cannot do

Other processes of the same user can reach a loopback port, and a browser extension can read the page. The token and the cookie are the only guard against the first, which is why row 7 exists; the guide tells the holder to use a clean browser profile against the second ([the research](/research/local-wizard-threats-2026-11-01/#what-cannot-be-defended-and-the-advice)).

### The page is usable

Semantic HTML, reachable by keyboard alone, with text and contrast that follow the browser's settings, `prefers-color-scheme` and `prefers-reduced-motion`. A plan can be read with scripts off: the script only polls for the state.

## Follow-ups

- The terminal wizard, the catalogue and the conformance test ([issue #16](https://github.com/truvity/ritueel/issues/16)).
- The web server, the profile and a test for each row ([issue #17](https://github.com/truvity/ritueel/issues/17)).
