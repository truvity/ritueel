---
title: The wizard
description: A guided mode in the terminal and a read-only page on localhost that guide a ceremony, keep you in charge, and leave the PIN and the touch on the card.
sidebar:
  order: 2
---

:::caution[Not built yet]
The page exists as code and a demo (`ui/`, `proto/`); the program that serves it is planned for milestone M2 ([issue #17](https://github.com/truvity/ritueel/issues/17)), and the guided mode comes after the first signed release ([issue #16](https://github.com/truvity/ritueel/issues/16)). This page is the design that [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) accepts and [ADR 0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/) details; the exact rules are in [the reference](/reference/wizard/).
:::

Some people prefer a page to a terminal, and a ceremony is easier to follow when each step is shown with its explanation next to it. The wizard is that: a guided front end that keeps you in charge. It has two parts, a guided mode in the terminal and a read-only page.

## What it is

- **A face of the same engine.** The command line, the guided mode and the page are three faces of one engine, and the command line and the page use one API of one ritueel process. The wizard asks the ceremony engine for the plan and shows it. It does not sign, verify or record by any code of its own ([principle 14](/principles/#the-principles)). The process behind them is started by the first command that needs it, is not a system service, and ends by itself when it is idle or on `ritueel stop` ([the process](/reference/wizard/#the-ritueel-process)).
- **In the terminal, or in a browser.** The guided mode asks line by line in plain text, so a screen reader and a log both work; there is no full-screen interface, and the program is not installed as a service. The page is a read-only view served by the program on your own computer, only while you use it, beside the guided mode.
- **The user is in charge.** Nothing happens without your confirmation. The PIN is typed at the terminal and goes to the card, and the touch is a touch on the card. The page never sees either.

## What the page may and may not do

| The page may | The page may not |
|---|---|
| Show the plan, the facts about each key, and the teaching text for the step. | Confirm, sign, create or delete anything: the page has no such control. |
| Collect choices: which root, which request, which store. | Ask for, receive or show a PIN, a passphrase or a key. |
| Show progress, the record and what outsiders will see. | Load anything from outside your computer. |

The confirmation of every irreversible step is given in the terminal, or by the touch on the card, never by a click in the page. The page shows the plan and its digest, and ends with a preview and the command to run, `ritueel run PLAN --confirm DIGEST`. The program saves the plan file for you in your directory (`ledger/<ceremony>/plan.json`), so that you can boot the offline system and run it there; only a card root or a real software root needs that. A cloud root runs from your workstation, and a test root may too. You give the confirmation in the terminal.

## Security rules

The page is served by a program on your computer that sits beside the ceremony engine, so it is built to be hard to reach from anywhere else, including from another page open in the same browser. It is read-only, and it never sees a secret.

1. **It listens on 127.0.0.1 only,** and refuses to start on any other address.
2. **On a random port,** chosen each time the page is opened.
3. **With a one-time token** in the address it prints. A request without the token is refused, and the token stops working when the wizard stops.
4. **It checks the Host and Origin headers** of every request against its own address and port. This stops a web page you visit from talking to it, including by a trick that points a hostile name at your own computer (DNS rebinding).
5. **It loads no remote assets:** no web fonts, no scripts, no images from other sites. The page works with the network cable out.
6. **It sends a strict Content-Security-Policy** that allows its own files only for scripts, images and connections. The page's component library may write styles inline; scripts may not.
7. **Every irreversible step needs confirmation in the terminal or by touch.**
8. **No telemetry,** and no network call other than the ones a ceremony itself needs.

Each rule has a test in the plan for the wizard: a request with the wrong token, Host or Origin is refused, and the page loads nothing when the network is blocked. [The reference](/reference/wizard/#the-web-page-the-security-profile) lists the rows, and [the research](/research/local-wizard-threats-2026-11-01/) the threats behind them. Two threats stay: another program of yours on the same computer can reach a local port while the page is open, and a browser extension can read the page. Use a clean browser profile, and remember that nothing irreversible can be done from the page.

## What it drives

The ceremonies and the checks: adopting the roots, the renewals of the yearly ceremony, intermediates, the five transitions, the trust products, the drills and a person's own key. It does not prepare a card, change a PIN or publish; it names the guide for those ([the list](/reference/wizard/#what-the-guided-mode-and-the-page-drive)).
