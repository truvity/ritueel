# 0010 — One engine with three faces, one process on one fixed port, and a page that cannot confirm anything

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. ritueel is a Go command-line tool with one ceremony engine and three faces: the command line, a guided mode, and a read-only local page on localhost served by the same binary. The one write the page can cause is in rule 11.
2. The guided mode asks line by line in plain text, does not depend on colour, and refuses to run without a terminal. There is no full-screen terminal interface, and the program is not installed as a service.
3. A wizard (the guided mode or the page) is a front end over the plan. It builds the options of a command, asks the engine for the plan, shows it with its digest and hands the confirmation to the terminal. It has no code that builds a request, a plan or a signature, and every step prints the equivalent command line. A test runs a wizard session, runs the printed commands (the run step with `--confirm DIGEST`) and compares plans and records.
4. The explanation of each step is written once, in one catalogue read by both the guided mode and the page, and names the Learn page that holds the reason. A command whose catalogue text is missing fails the wizard's test.
5. The wizards drive the ceremonies and the checks: init, due, run, the intermediate and root commands, the builders and verifiers, the drills and the personal commands. Preparing a card and changing a PIN are the holder's, not the wizard's; the wizard names the guide for them. Publishing a key to the keyservers is a separate command that runs after a ceremony ([0011](0011-publishing-and-what-to-do-after-a-ceremony.md)); the page shows that step with its command and does not run it.
6. The command line and the page call one API of one ritueel process, written in Protobuf and served with ConnectRPC (package `ritueel.local.v1alpha1`, in `proto/`); the page is in `ui/`. The process is the same program as the command line. The first command that needs it starts it in the background, and the command line then talks to it. It serves both faces on one fixed loopback port: localhost, one number for ritueel. The number is 7488; the IANA registry lists 7479 to 7490 as unassigned (checked on 2026-11-11).
7. A full-rights token, read from a file only the user can read, is for the command line. A page-rights token is for the browser and is used once; it can call only the reads and SavePlan. No call that confirms, signs, creates a key or runs a ceremony is open to it.
8. Every request is checked for its Host and Origin. Before the command line sends a confirmation or a PIN, the listener proves that it knows the secret in the token file. There is one exclusive lock per bundle.
9. The process is not a service: not installed as a system service, never started at login or boot, never surviving logout or reboot. It keeps no ceremony state; every call reads the bundle again. It ends after 15 minutes without a call, at once on a stop command, and at logout or reboot; a running ceremony is never cut by the timer. It keeps nothing secret between calls, never keeps a PIN, and holds no card between calls.
10. The page has no control that confirms a plan, signs, creates or deletes, and never sees a secret, PIN, passphrase or key. It shows the plan and its digest, says "type the first eight characters in the terminal", and follows the state of the ceremony. Its wizard ends with a preview and the short command to run (`ritueel run PLAN`), shown without the digest in it; the flag `--confirm DIGEST` stays for scripts. No API call has a field for a secret, a PIN or a passphrase.
11. The page can save the plan file through SavePlan, so the holder can boot the offline system and run it there. SavePlan rebuilds the plan, refuses a digest that differs from the rebuilt plan's, and writes one inert file: the only write the page can cause.
12. The page follows a security profile, with a test for each row. It binds only the IPv4 loopback literal (127.0.0.1) on the one fixed port and refuses any other address. A one-time page-rights token printed in its address becomes an HttpOnly, SameSite=Strict cookie, and a request without it is refused. It makes an exact Host check and a separate Origin (cross-origin) check. Its assets are embedded, none remote. Its content security policy is strict: scripts, images and connections from its own files only, styles from its own files and inline. It has no telemetry and no network call a ceremony does not need. Every irreversible step is confirmed in the terminal or by touch, never by a click alone. The page session ends. The program prints the address and does not start a browser.
13. The security note of every pull request that changes the page cites the profile row it touches. The page is a security-critical component with its own tests and no second ceremony code.
14. The page is a single-page application in React and TypeScript with MUI and Tailwind CSS, built with Vite from a lock file (`ui/package-lock.json`, versions pinned exactly), built in CI and embedded in the program as static files. Its contract is Protobuf, called over ConnectRPC. Nothing is remote, there is no inline script, and scripts come only from `'self'`. `style-src` allows `'unsafe-inline'` because the component library writes styles at run time; `script-src` never does, and the policy stays free of hashes.
15. Protection today: a lock file; a generated client committed and diffed by `just proto-check`; a `ui` job in the checks; a source scan for innerHTML, eval, fetch, XMLHttpRequest, sendBeacon, WebSocket and remote URLs; a test that hostile strings (bidirectional override, joiner, control characters) reach the markup only as visible U+XXXX escapes; a check of the built files for any remote host or fixture; a headless-browser run under the site's exact headers with no console or policy violation.
16. The page is usable by keyboard and screen reader. Because a single-page application needs script, a plan is read in the terminal (`--plan-only`, the guided mode) or in the saved plan file instead.
17. The site shows a demo built from the real page in a demo mode that answers from fixtures through an in-memory ConnectRPC transport, as static files under `/demo/`, with hash routes. Every action is refused as "this is a demo". The demo keeps three example bundles with a switch, gets first-visit help and its four defects fixed, and its policy keeps blocking the analytics script. The page stays on prototype B.
18. OpenPGP packets are built with ProtonMail/go-crypto, with a small bypass that plugs a card or KMS signer into its signing path. The version is pinned, with a test that builds a certificate with a software signer and runs gpgv, sqv and a tampered control. A go-crypto upgrade is a reviewed change with its signer test, not a routine bump.
19. The `piv` and `openpgp-card` stores need cgo and PC/SC. A build without cgo leaves them out and reports them as not built (exit code 2), so software-root consumers keep a static binary (build tag from #10).
20. ritueel's key handling, signing and revocation get review, tests on real test devices, and the rules in GOVERNANCE.md. A test that needs hardware is tagged, skipped by default, and selects its card by serial.
21. ritueel delivers one statically linked executable for Linux (copy and run, Go only, no installers), a small release signer program for CI until the requester system signs natively, and later a Go library for infrastructure code built on the same policy package.
22. The page flow for a change: in the page the person edits and a plan is written (rule 11); in the terminal one short command runs it, the person types the first eight characters of the plan's digest, then gives the PIN and the touch where the store asks for them. On the workstation the page shows the progress; for a key that can be copied the run is in the offline system, where there is no page and no network, so the progress is in the terminal. The last step, the keyserver upload, is shown in the page with its command and done in the terminal after a typed confirmation: there is no button. The page never confirms or runs a ceremony and never sees a secret. The maintainer agreed to this flow for an identity change; for a new root or a renewal it follows by extension and is open to his word.

## Why

One engine means the ceremony is tested once and the faces cannot drift apart. The confirmation stays in the terminal, because malware could confirm in a daemon or a page. A browser cannot open a Unix socket, so one fixed loopback port serves both faces.

## What it costs

- Other processes of the same user can reach the loopback port while the process runs, and a browser extension can read the page.
- A mouse user still touches the terminal for every irreversible step.
- An unaudited npm tree and a second toolchain (Node, TypeScript) sit beside Go.

## Roads not taken

- **A web wizard that listens on the network.** It is shareable, but a network service that acts on root keys needs authentication and has a larger attack surface.
- **A wizard with its own signing code.** It gives a friendlier flow, but means two implementations of the ceremony to test, and they will drift apart.
- **A separate engine for the wizard.** It gives freedom to shape the flow, but means two implementations of the ceremony to test.
- **A full-screen terminal interface.** It is nicer, but hides the transcript, defeats screen readers and cannot be tested through a pipe.
- **A desktop application instead of a localhost page.** It needs no browser, but is a large dependency, an installer to sign and a wider attack surface.
- **A ceremony service.** Several people could share a web interface, but it is a network service that holds ceremony state and acts on roots.
- **A second API only for the page (plain JSON handlers).** There is nothing to learn beyond HTTP, but two things can drift apart; the maintainer asked for one API.
- **Every command its own process, no shared API path.** Nothing lives between commands, but the command line and the page would reach one ceremony by two paths.
- **A service started at login or boot that both faces call.** It is always warm, but must be installed everywhere, outlives the person's presence and could act on roots while nobody is there.
- **A daemon with the confirmation in it.** Refused: malware could confirm; the confirmation stays in the terminal.
- **The command line over the loopback address with no token and no proof from the listener.** Simpler, but a port every local process can reach would carry the confirmation, and another local process could listen on the port first and receive the confirmation or the PIN; the chosen way adds a full-rights token in a file and the listener's proof.
- **A Unix socket for the command line, and a loopback listener for the page only while the page is used.** A browser cannot open a Unix socket, so the page needs a port anyway and there would be two doors to build and test; the maintainer chose one port against the recommendation.
- **A Save that runs the plan, or a Run button in the page.** It is the simplest flow, but any browser extension could click it, and it cannot work for a person's own key, which lives only in the offline system where there is no page.
- **The run command in the page with the whole digest in it.** One paste, but a person could paste it without reading; the typed characters are the link between the plan the page shows and the run in the terminal.
- **A click to confirm protected by the token.** It is the friendliest, but any process that can read the cookie or the page, an extension included, could confirm.
- **A confirmation code shown in the page and typed in the terminal.** The thing to compare would come from a page that might be lying; the terminal prints the digest first.
- **Open the browser for the person.** It is one step fewer, but the token would travel on a command line that other processes read.
- **A hand-written page (the earlier design).** It had HTML templates, one stylesheet, one script and no package tree, but plain screens, a second stack beside sluis and no page that doubles as the public demo; the maintainer chose the sluis stack.
- **The wizard prepares the card and the account.** It gives one guided path from the box, but the tool stays out of PINs and accounts, and a wizard is no exception.
- **Upstream a signer API to go-crypto, or write the packets ourselves.** It removes the bypass, but waits on review or adds security-critical code to keep.

## Not yet proven or only proposed

- **Not yet proven.** The guided mode, the step catalogue and the test that compares a wizard session with the printed commands ([issue #16](https://github.com/truvity/ritueel/issues/16)). They come after the first signed release.
- **Not yet proven.** The program side of the local page: the ConnectRPC server, the embedded build, the profile tests, SavePlan, and the process behind the commands ([issue #17](https://github.com/truvity/ritueel/issues/17)).
- **Proposed.** What happens when a process of another version answers, and how a test makes sure a process ends ([issue #17](https://github.com/truvity/ritueel/issues/17)).
- **Proposed.** Additions to the page's security profile: a per-session header, a Sec-Fetch-Site same-origin check, no CORS and a tighter content security policy; the reason is that cookies do not isolate by port on localhost and an extension can read the page ([#17](https://github.com/truvity/ritueel/issues/17)).
- **Proposed.** Later, in the build order: the edit form in the page (for example for a user ID) and a hand-over screen that shows the next steps after a run; the flow itself is decided in rule 22 ([#17](https://github.com/truvity/ritueel/issues/17)).

## Replaces

0001, 0003, 0004, 0007, 0008 and 0011, in part, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
