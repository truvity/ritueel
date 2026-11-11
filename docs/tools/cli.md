---
title: The command line
description: What the ritueel command line will do at a ceremony, the six steps it runs, the checks it makes before each touch, and how it handles PINs, touches and expiry.
sidebar:
  order: 1
---

*Not built yet: no ceremony command exists. This page describes what the commands will do ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)); the commands and their exit codes are in [the command reference](/reference/cli/). To learn what a ceremony is before you meet the tool, read [What a ceremony is](/learn/ceremonies/).*

The command line is the first of three faces of the ceremony engine; the others are the guided mode and the read-only local page ([the wizard](/tools/wizard/)). A ceremony is a scripted, reviewable use of a root. A key that can be copied, a key file, is used only in a machine booted from a read-only system made for the purpose (the offline system), never in the everyday system (ritueel teaches this and does not check it). A key that cannot be copied, a root on cards or a cloud root, may be used on your workstation. A cloud root always runs there, because the offline system has no network; the offline system is an option for a root on cards. A root on cards needs four conditions: a touch for every signature, the number of signatures stated in the plan, no retry of a failed touch, and the result checked on a second device. A cloud key has no touch: for a cloud root the typed digest and the role session stand, its audit trail records every signature, and the other three conditions apply ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 18). The program checks nothing about the machine, so the check on a second device is taught, not checked. A test root may be used on the workstation or on a rehearsal card. The machine is not trusted: the root keys never leave their store, so a compromised machine cannot copy a key it never holds. It can still try to trick the holder, which is why the checks below exist.

## Six steps

Every ceremony runs the same steps: **plan** every byte that will be signed, **confirm** by typing the first eight characters of the plan's digest, **reserve** an attempt before the first signature, **sign**, **verify** each result with code that did not sign it, and **record**. The plan can be written on one machine and reviewed on another before a card is touched.

## What the tool checks

1. **The card.** Read its serial, and check it against the inventory of cards before anything is written: the right card for the root, PIN tries left, no default PIN, PUK or management key ([the checks](/reference/cards/#what-is-checked-on-a-card)). The holder sets the PIN with the maker's tool ([Prepare a root card](/guides/prepare-a-root-card/)); ritueel's adoption of the card replaces the PUK and the management key.
2. **The attestation of every key it certifies, and of every root it creates.** A card's chain must lead to the maker's current root through the maker's intermediates, which ritueel ships and refreshes; a KMS key is read from the service, with its policy and replica ([the checks](/reference/kms-root/#the-checks)). A key that cannot be attested is refused, because an imported key cannot be.
3. **What is about to be signed.** Show the key's fingerprint, its store, its lifetime and the serial before each touch. The holder confirms by comparing, not by pressing a button.
4. **The result.** After signing, verify the certificate or binding against the request and the plan.
5. **The record.** Write a hash-chained ceremony record that contains no PIN, no key and no secret.

A PIN is entered by the holder at the terminal. The tool never retries a wrong PIN ([record 0002](../decisions/0002-where-a-key-lives.md), rule 3) and refuses to run when fewer than three tries are left ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 14), because the card blocks after three and then needs the PUK. The PINs the holder types live in the holder's password manager, one entry per card; the PUK and the management key are random and sealed in the bundle ([record 0003](../decisions/0003-root-cards.md), rule 10).

## The three ceremonies

| Ceremony | When | Card | Result |
|---|---|---|---|
| Renewals, yearly: `ritueel due`, then `ritueel run` | Month 12 of the intermediates' life | The card for the year | New 13-month certificates over the same intermediate keys, and new bindings that extend the same subkeys. The card's own root extended, a new keyring package and root list. |
| Intermediate add, replace or revoke | Between yearly ceremonies | The card for the year; for `revoke`, the card of each root that issued an unexpired certificate of the intermediate | `add`: a certificate, binding or SSH CA key listing for a new intermediate. `replace`: new key material, on an event. `revoke`: the certificate and binding withdrawn, and the certificate put on the issuing root's [CRL](/reference/crl/). |
| Root add, retire or revoke | A card is lost, retired or compromised | Every active card; for a lost one, its stored removal authorisation | A new root that an active root vouches for, an overlap that ends on a day you name, or a root list without the old root ([root transitions](/reference/transitions/)). |

Each is one to three commands. [Adopting the roots](/guides/root-adoption/) is the first one you run, and [A lost root card](/guides/lost-root-card/) walks through the last. An intermediate key is renewed by re-signing ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 15) and replaced on an event, and a key in software also at most every three years ([record 0002](../decisions/0002-where-a-key-lives.md), rules 15 and 16).

## After a ceremony

ritueel prints what to do: a list of next steps (what changed, who needs it, how). For an OpenPGP key the last, optional step is publishing it with a separate command, which asks for a typed confirmation and sends only to the keyservers you list. For a code host, a web site, your software or the trust store of a machine ritueel prints files, links and commands, and runs none of them. See [After a ceremony](/guides/after-a-ceremony/) and [record 0011](../decisions/0011-publishing-and-what-to-do-after-a-ceremony.md). The names are proposed.

## A missed touch

A touch not given comes back from the card after about 15 seconds as a generic security status, not as a touch timeout (measured 2026-10-31). The tool therefore says "the card refused after N seconds: no touch was given in time, or the PIN state was lost" when the PIN was accepted in the same session and the refusal came after 10 seconds or more, and does not retry. It claims no more than it knows.

## Root validity and its extension

A root is valid for about three years, and each use extends it. The card that signs at a ceremony also extends its own root to about three years from that day:

- **OpenPGP.** A new self-signature on the primary moves its expiry.
- **X.509.** The root certificate is re-issued over the same key and the same subject, with a new validity.
- **Pinning holds.** Clients of the signed root list pin the public keys of the roots, not their certificates, so a re-issued certificate keeps the pin.
- **A dead or lost card shows itself.** Its root is not extended, and runs out.

`status` warns about a root 6 months, 3 months and 30 days before it expires. Cards alternate, so a healthy root always has about a year left; a warning means an extension was missed, with time left to act.

## One process behind the commands

Every command that reads or writes a bundle talks to one ritueel process. The first command that needs it starts it; it is not installed as a system service, is never started at login or boot. The command line and the local page reach it on one fixed port of the loopback address (7488), with a token read from a file that only you can read. It ends by itself after 15 minutes without a call, at once on a stop command, and at logout or reboot. It keeps no PIN, no passphrase and no secret between calls, and holds no card between calls. When you confirm a ceremony, the digest you type in the terminal goes to it with that token. ([record 0010](../decisions/0010-the-engine-the-process-and-the-page.md), [the details](/reference/wizard/#the-ritueel-process).)

## Which code talks to the cards

The CLI is written in Go. Both root keys of a card live in PIV slots, reached through piv-go, and ritueel builds the OpenPGP packets itself: one applet, one library, one binary, and no `gpg` at run time. The root cards hold only roots, because the program that holds a card keeps every other out. The ritueel process holds a card only during a ceremony. The reasons, and the roads not taken, are in [record 0003](../decisions/0003-root-cards.md), and the spike behind them in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/).
