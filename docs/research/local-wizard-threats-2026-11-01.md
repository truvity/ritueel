---
title: A wizard on localhost, the threats (2026-11-01)
description: What a program that serves a page on the user's own machine and acts on root keys must defend against, the defences real tools use, and what cannot be defended.
sidebar:
  order: 4
---

## Question

What must the localhost web wizard of [ADR 0011](/decisions/0011-the-wizards-one-engine-two-faces-and-a-web-page-that-cannot-confirm-anything/) do so that no other web page, program or user on the same machine can make it act on a root key? It feeds the security profile in [The wizard](/reference/wizard/) and does not change the rules of [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules).

## When

Read on 2026-11-01. The rows marked *rechecked* were read again on 2026-11-02, against the primary source and not a summary. One run was made on 2026-11-02 (Go 1.27.0, Linux).

## Verdict

**Bind to the IPv4 loopback literal on a random port, let a one-time token in the address become a `HttpOnly`, `SameSite=Strict` cookie, check the `Host` header against an exact allow-list, and check cross-origin requests as a separate rule. Embed every asset and send a strict Content-Security-Policy.** Two threats cannot be defended by the page: any other process of the same user, which can reach a loopback port, and a browser extension with access to the page. So the page is given nothing irreversible to do: the PIN, the touch and the final confirmation stay in the terminal and on the card.

## Method

Read the standards, the Go standard library source and the documents or advisories of tools that serve a page on localhost. Ran one small Go program. Nothing was exercised against a browser.

## What the setup over- and under-counts

- Nothing here was attacked. The defences are the ones that other tools use after a published fault; whether ritueel's page holds is what the tests in [issue #17](https://github.com/truvity/ritueel/issues/17) show.
- The Go behaviour is the library's on one Linux host; another resolver configuration can differ, which is why the literal address is used and not the name.

## Numbers

| Threat | Defence | Evidence | Label |
|---|---|---|---|
| A web page makes a hostile name point at 127.0.0.1 and talks to the server as if it were its own origin (DNS rebinding). | Check `Host` against an exact allow-list and refuse the rest. | Syncthing answers 403 "Host check error" unless the `Host` is localhost or a loopback address (`lib/api/api.go`, main branch, *rechecked* 2026-11-02); Jupyter Server has a `check_host` (`base/handlers.py`, *rechecked*). | READ |
| Any website sends requests to a server on the machine and reads the answers. | Validate `Origin`, and do not answer with permissive CORS. | Vite advisory GHSA-vg6x-rcgg-rjx6, published 2025-01-20: "Vite allowed any websites to send any requests to the development server and read the response due to default CORS settings and lack of validation on the Origin header for WebSocket connections" (*rechecked*). | READ |
| A page on another site posts a change (CSRF). | Go's `net/http.CrossOriginProtection` rejects non-safe cross-origin browser requests by `Sec-Fetch-Site`, or by comparing `Origin` with `Host`; `GET`, `HEAD` and `OPTIONS` always pass, and a request with neither header is assumed same-origin or not from a browser and is allowed (`src/net/http/csrf.go`, master, *rechecked* 2026-11-02). | It is not a rebinding defence: after a rebind, `Origin` equals `Host`, so it passes. Keep the `Host` check separate. | READ, and an inference for the last sentence |
| Another program on the network, or one that finds the port, calls it. | Listen on the loopback interface only, only while needed, and require a token that is single use and becomes a cookie (ritueel's own rule, [ADR 0011](/decisions/0011-the-wizards-one-engine-two-faces-and-a-web-page-that-cannot-confirm-anything/)). | RFC 8252, October 2017, section 8.3: "Clients should listen on the loopback network interface only"; open the port only for the request and close it after; the loopback IP literal is preferred, and `localhost` is "NOT RECOMMENDED" (*rechecked*). | READ |
| `localhost` is not one address. | Print and use `127.0.0.1`. | On a host whose `/etc/hosts` maps `localhost` to both families, Go 1.27.0 `net.Listen("tcp", "localhost:0")` listened on 127.0.0.1 only, while `net.LookupHost("localhost")` returned `127.0.0.1` and `::1` (2026-11-02, rerun of the 2026-11-01 result). A browser may try `::1` for the same port. | MEASURED |
| The page loads something from elsewhere. | No remote assets; a policy that allows the page's own files only. | `default-src 'none'`, then `script-src`, `style-src`, `img-src` and `connect-src` set to `'self'`, and `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`, which do not fall back to `default-src` (the MDN CSP guide, read 2026-11-01). The line itself is a composition. | READ |

## What cannot be defended, and the advice

| Threat | Why | What ritueel does |
|---|---|---|
| Another process of the same user. | Loopback is reachable by every local process, and a Unix socket, the only per-user transport, cannot be opened by a browser. | The token and the cookie are the only guard, so the page cannot do anything irreversible: confirmation, PIN and touch are in the terminal and on the card. |
| A browser extension. | An extension with access to the page can read and change it. | The guide says to use a clean browser profile with no extensions, and every value that matters is confirmed in the terminal. |
| The local network prompt of newer browsers. | It is a defence in depth that the user can click through (Chrome 142 and later; read 2026-11-01 from the Chrome documentation). | Nothing depends on it. |

## Roads not taken

- **`localhost` in the address.** Friendlier, but it may bind one family and be reached on another ([above](/research/local-wizard-threats-2026-11-01/#numbers)).
- **A Unix socket with a browser.** The only per-user transport, but a browser cannot open one.
- **A token that stays in the address.** Simple, but it lands in history and referrers; it is swapped for a cookie and the address is redirected.
- **CSRF protection as the rebinding defence.** One check fewer, but after a rebind it passes.

## Open questions

None.

## Changes made

None. One Go program was run in a scratch directory outside the repository, and removed.

## Raw logs

Not kept. The command and its two lines of output are in the table.
