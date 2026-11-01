---
title: The wizard
description: A local wizard, in the terminal and as a page served on localhost, that guides a ceremony, keeps you in charge, and leaves the PIN and the touch on the card.
sidebar:
  order: 2
---

:::caution[Not built yet]
The wizard is planned for milestone M4 ([issue #16](https://github.com/truvity/ritueel/issues/16) for the terminal, [issue #17](https://github.com/truvity/ritueel/issues/17) for the web page). This page is the design that [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) accepts.
:::

Some people prefer a page to a terminal, and a ceremony is easier to follow when each step is shown with its explanation next to it. The wizard is that: a guided front end that looks good and keeps you in charge.

## What it is

- **A second face of the same engine.** The wizard asks the ceremony engine for the plan, shows it, and asks you to confirm. It does not sign, verify or record by any code of its own ([principle 14](/principles/)).
- **In the terminal, or in a browser.** The terminal wizard needs no browser. The web wizard is a page served by the program on your own computer.
- **The user is in charge.** Nothing happens without your confirmation. The PIN is typed at the terminal and goes to the card, and the touch is a touch on the card. The page never sees either.

## What the page may and may not do

| The page may | The page may not |
|---|---|
| Show the plan, the facts about each key, and the teaching text for the step. | Confirm an irreversible step by itself. |
| Collect choices: which root, which request, which store. | Ask for, receive or show a PIN, a passphrase or a key. |
| Show progress, the record and what outsiders will see. | Load anything from outside your computer. |

The confirmation of every irreversible step is given in the terminal, or by the touch on the card, never only by a click in the page.

## Security rules

The web wizard is a program on your computer that acts on root keys, so it is built to be hard to reach from anywhere else, including from another page open in the same browser. The rules follow the way tools such as Jupyter and Syncthing guard their local pages, and the OAuth guidance for native apps (RFC 8252); the checks were read on 2026-11-01.

1. **It listens on 127.0.0.1 only,** and refuses to start on any other address. It prints and uses the literal address, not `localhost`: on a machine with both IPv4 and IPv6, `localhost` can mean two places, and a browser may try the other one, where a different program could be listening. On Windows it takes the port exclusively.
2. **On a random port,** chosen by the system at each start.
3. **With a one-time token** in the address it prints. The first request swaps the token for a cookie (`HttpOnly`, `SameSite=Strict`) and redirects to an address without the token. A request with neither is refused, and nothing works after the wizard stops.
4. **It checks the Host header** against an allow-list of its own addresses. This stops a hostile web page that makes its own name point at your computer (DNS rebinding): after the trick the browser sends the hostile name as the Host, and the request is refused. **It also checks Origin or `Sec-Fetch-Site`** on every request that changes something, against cross-site requests. The two checks are separate, because after a rebind the Origin matches the Host.
5. **It loads no remote assets:** no web fonts, no scripts, no images from other sites, no analytics. The page is embedded in the program, and it works with the network cable out.
6. **It sends a strict Content-Security-Policy** that allows its own files only: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
7. **Every irreversible step needs confirmation in the terminal or by touch.** The PIN is typed at the terminal or on the card's own pad. Typing the first characters of the plan's digest, comparing a fingerprint, and the final "sign" are done in the terminal, never only in the page.
8. **No telemetry,** and no network call other than the ones a ceremony itself needs.

## What these rules do not cover

- **Other users and programs on the same computer.** Loopback is reachable by every local user, so the token and the cookie are the only guard. Do not run the wizard on a shared machine.
- **Browser extensions.** An extension with permission for local addresses can read and change the page. Use a clean browser profile with no extensions, and confirm security-critical values in the terminal, as rule 7 says.
- **A browser's own prompts.** Newer browsers ask before a page reaches the local network; that is a second layer, and a user can click through it, so ritueel does not rely on it.

Each rule has a test in the plan for the wizard: a request with the wrong token, Host or Origin is refused, a page that is not on the allow-list gets nothing, and the page loads nothing when the network is blocked.
