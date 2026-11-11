# 0011 — The wizards: one engine, three faces, and a web page that cannot confirm anything

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) decides that ritueel has three faces, the command line, a guided mode and a local page served on localhost, that all are the one ceremony engine of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/), and that the page follows eight security rules. It does not say how a front end uses the engine, what the guided mode looks like, what the page may do about a confirmation, or what the rules mean in code. The page is built in M2 and the guided mode comes after the first signed release ([issue #17](https://github.com/truvity/ritueel/issues/17), [issue #16](https://github.com/truvity/ritueel/issues/16)). In this record, a wizard is the guided mode or the page. The threats are in [a dated research page](/research/local-wizard-threats-2026-11-01/). The mission test applies hardest here: a friendly front end is the place a tool starts deciding for the person.

## Decision

- **A wizard is a front end over the plan.** It builds the options of a command, asks the engine for the plan, shows it with its digest, and hands the confirmation to the terminal. It has no code that builds a request, a plan or a signature, and every step prints the equivalent command line. A test runs a wizard session, runs the printed commands, and compares the plans and the records ([the profile](/reference/wizard/#one-engine)).
- **The guided mode asks line by line,** in plain text, with no full-screen interface and no dependence on colour. A screen reader, a log and a pipe all work, and without a terminal it refuses rather than prompt.
- **The web page cannot confirm anything.** It has no control that confirms a plan, signs, creates or deletes. It shows the plan and its digest, says "type the first eight characters in the terminal", and follows the state of the ceremony; the terminal prompt of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony) waits for the person. The page is a read-only view: it never confirms a ceremony and never sees a secret. Its wizard ends with a preview and the command to run (`ritueel run PLAN --confirm DIGEST`), and it can save the plan file, so that the holder can boot the offline system and run it there ([0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-root-card-is-used)). This is [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules) rule 7 made structural: a page that never held the control cannot be tricked into using it, whoever else is on the machine.
- **The eight rules of 0007 are a profile with a test for each row,** on [one reference page](/reference/wizard/#the-web-page-the-security-profile): the IPv4 loopback literal on a random port, a one-time token that becomes an `HttpOnly`, `SameSite=Strict` cookie, an exact `Host` check and a separate cross-origin check, embedded assets, a strict policy, no telemetry, and a session that ends. The program prints the address and does not start a browser: that would put the token on a command line other processes can read.
- **The page is embedded and hand-written:** HTML templates, one stylesheet, one script that only polls, all in the binary, with no framework and no bundler in the build. A security-critical program does not take a package tree for a few screens, and the CSP stays free of hashes.
- **The wizards drive the ceremonies and the checks, not the preparation.** `init`, `due` and `run`, the intermediate and root commands, the builders and verifiers, the drills and the personal commands are in; preparing a card, changing a PIN and publishing are the holder's, and the wizard names the guide for them.
- **The explanation of each step is written once,** in one catalogue read by both faces, and names the Learn page that holds the reason. The wizard teaches where it acts.
- **The page is usable by keyboard and by screen reader,** and a plan can be read with scripts off.
- **No background service.** Nothing runs between ceremonies.

## Consequences

- A person who wants a mouse still touches the terminal for every irreversible step, and runs the printed command, or the saved plan, there. That is the price of rule 7, and the same price as the card's touch.
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
- **A background service that the page talks to.** Always up, but it holds state and acts on roots while nobody is present.
- **A separate engine for the wizard.** Freedom to shape the flow, but two implementations of the ceremony to test, the failure that [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) names.
- **The wizard prepares the card and the account.** One guided path from the box, but [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/) keeps the tool out of PINs and accounts, and a wizard is no exception.

## Follow-ups

- The guided mode, the step catalogue and the conformance test ([issue #16](https://github.com/truvity/ritueel/issues/16)).
- The read-only local page, the profile, saving a plan file and a test for each row ([issue #17](https://github.com/truvity/ritueel/issues/17)).
