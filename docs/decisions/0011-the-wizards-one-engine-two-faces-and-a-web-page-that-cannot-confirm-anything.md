# 0011 — The wizards: one engine, two faces, and a web page that cannot confirm anything

**Status:** Accepted
**Date:** 2026-11-02

## Context

[0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) decides that there are two wizards, one in the terminal and one on a page served on localhost, that both are the one ceremony engine of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/), and that the web wizard follows eight security rules. It does not say how a front end uses the engine, what the terminal wizard looks like, what the page may do about a confirmation, or what the rules mean in code. M4 builds both ([issue #16](https://github.com/truvity/ritueel/issues/16), [issue #17](https://github.com/truvity/ritueel/issues/17)). The threats are in [a dated research page](/research/local-wizard-threats-2026-11-01/). The mission test applies hardest here: a friendly front end is the place a tool starts deciding for the person.

## Decision

- **A wizard is a front end over the plan.** It builds the options of a command, asks the engine for the plan, shows it with its digest, and hands the confirmation to the terminal. It has no code that builds a request, a plan or a signature, and every step prints the equivalent command line. A test runs a wizard session, runs the printed commands, and compares the plans and the records ([the profile](/reference/wizard/#one-engine)).
- **The terminal wizard asks line by line,** in plain text, with no full-screen interface and no dependence on colour. A screen reader, a log and a pipe all work, and without a terminal it refuses rather than prompt.
- **The web page cannot confirm anything.** It has no control that confirms a plan, signs, creates or deletes. It shows the plan and its digest, says "type the first eight characters in the terminal", and follows the state of the ceremony; the terminal prompt of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) waits for the person. This is [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules) rule 7 made structural: a page that never held the control cannot be tricked into using it, whoever else is on the machine.
- **The eight rules of 0007 are a profile with a test for each row,** on [one reference page](/reference/wizard/#the-web-page-the-security-profile): the IPv4 loopback literal on a random port, a one-time token that becomes an `HttpOnly`, `SameSite=Strict` cookie, an exact `Host` check and a separate cross-origin check, embedded assets, a strict policy, no telemetry, and a session that ends. The program prints the address and does not start a browser: that would put the token on a command line other processes can read.
- **The page is embedded and hand-written:** HTML templates, one stylesheet, one script that only polls, all in the binary, with no framework and no bundler in the build. A security-critical program does not take a package tree for a few screens, and the CSP stays free of hashes.
- **The wizards drive the ceremonies and the checks, not the preparation.** `init`, `yearly`, the intermediate and root commands, the builders and verifiers, the drills and the personal commands are in; preparing a card, changing a PIN and publishing are the holder's, and the wizard names the guide for them.
- **The explanation of each step is written once,** in one catalogue read by both faces, and names the Learn page that holds the reason. The wizard teaches where it acts.
- **The page is usable by keyboard and by screen reader,** and a plan can be read with scripts off.

## Consequences

- A person who wants a mouse still touches the terminal for every irreversible step. That is the price of rule 7, and the same price as the card's touch.
- The page is simple to the point of plain; making it look good is a matter of type, space and colour in one stylesheet, which is the job.
- The conformance test and the profile's tests are the wizards' security argument. The security note of every pull request that changes the page cites the row it touches.
- The catalogue is one more file to keep true when a command changes; a command whose text is missing fails the wizard's test.
- The loopback port stays reachable by other processes of the same user, and a browser extension can read the page. The profile says so, and the design assumes it.

## Roads not taken

- **A click to confirm, protected by the token.** The friendliest flow, but any process that can read the cookie or the page, an extension included, could confirm a plan; only the terminal and the touch are out of its reach.
- **A confirmation code shown in the page and typed in the terminal.** Almost the same, but the thing to compare would come from the page that might be lying; the plan digest is printed by the terminal first.
- **A full-screen terminal interface.** Nicer on a good terminal, but it hides the transcript, defeats screen readers and cannot be tested through a pipe.
- **A single-page application framework.** Richer screens, but a bundler, a lockfile and a tree of packages inside a program that acts on root keys, and an inline script the policy would have to admit.
- **Open the browser for the person.** One step fewer, but the token would travel on a command line that other processes read.
- **A separate engine for the wizard.** Freedom to shape the flow, but two implementations of the ceremony to test, the failure that [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) names.
- **The wizard prepares the card and the account.** One guided path from the box, but [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/) keeps the tool out of PINs and accounts, and a wizard is no exception.

## Follow-ups

- The terminal wizard, the step catalogue and the conformance test ([issue #16](https://github.com/truvity/ritueel/issues/16)).
- The web server, the profile and a test for each row ([issue #17](https://github.com/truvity/ritueel/issues/17)).
