---
title: The ceremony
description: What happens when a person uses a root, which checks the tool makes before each touch, and how a yearly renewal differs from an intermediate change.
sidebar:
  order: 6
---

*Design phase: no ceremony command exists yet. This page describes what the commands will do ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)); the commands and their exit codes are in [the command reference](/reference/cli/).*

A ceremony is a scripted, reviewable use of a root. It runs on the holder's ordinary workstation, with no live CD and no air gap, because the root keys never leave their cards: a compromised workstation cannot copy a key it never holds. It can still try to trick the holder, which is why the checks below exist.

## Six steps

Every ceremony runs the same steps: **plan** every byte that will be signed, **confirm** by typing the first eight characters of the plan's digest, **reserve** an attempt before the first signature, **sign**, **verify** each result with code that did not sign it, and **record**. The plan can be written on one machine and reviewed on another before a card is touched.

## What the tool checks

1. **The card.** Read its serial, and check it against the registry of known cards before anything is written: the right card for the role, PIN tries left, no default PIN.
2. **The attestation of every key it certifies, and of every root it creates.** A card's chain must lead to the maker's current root through the maker's intermediates, which ritueel ships and refreshes; a KMS key is read from the service. A key that cannot be attested is refused, because an imported key cannot be.
3. **What is about to be signed.** Show the key's fingerprint, its store, its lifetime and the serial before each touch. The holder confirms by comparing, not by pressing a button.
4. **The result.** After signing, verify the certificate or binding against the request and the plan.
5. **The record.** Write a hash-chained ceremony record that contains no PIN, no key and no secret.

A PIN is entered by the holder at the terminal. The tool never retries a wrong PIN and refuses to run when fewer than three tries are left, because the card blocks after three and then needs the PUK. PINs live in the holder's password manager, one entry per card.

## The three ceremonies

| Ceremony | When | Card | Result |
|---|---|---|---|
| Yearly | Month 12 of the intermediates' life | The card for the year | New 13-month certificates over the same intermediate keys, and new bindings that extend the same subkeys. The card's own root extended, a new keyring package and root list. |
| Intermediate add, replace or revoke | Between yearly ceremonies | The card for the year | `add`: a certificate and binding for a new intermediate. `replace`: new key material, on an event. `revoke`: the certificate and binding withdrawn. |
| Root add, retire or revoke | A card is lost, retired or compromised | The surviving card | A new root, or a root list without the old one. |

Each is one to three commands. [Adopting the roots](/guides/root-adoption/) is the first one you run, and [A lost root card](/guides/lost-root-card/) walks through the last. An intermediate key is renewed by re-signing and replaced only on an event or at most every three years ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)).

## A missed touch

A touch not given comes back from the card after about 15 seconds as a generic security status, not as a touch timeout (measured 2026-10-31). The tool therefore says "the card refused after N seconds: no touch was given in time, or the PIN state was lost" when the PIN was accepted in the same session and the refusal came after 10 seconds or more, and does not retry. It claims no more than it knows.

## Root validity and its extension

A root is valid for about three years, and each use extends it. The card that signs at a ceremony also extends its own root to about three years from that day:

- **OpenPGP.** A new self-signature on the primary moves its expiry.
- **X.509.** The root certificate is re-issued over the same key and the same subject, with a new validity.
- **Pinning holds.** Clients of the signed root list pin the public keys of the roots, not their certificates, so a re-issued certificate keeps the pin.
- **A dead or lost card shows itself.** Its root is not extended, and runs out.

`status` warns about a root 6 months, 3 months and 30 days before it expires. Cards alternate, so a healthy root always has about a year left; a warning means an extension was missed, with time left to act.

## Which code talks to the cards

The CLI is written in Go. Both root keys of a card live in PIV slots, reached through piv-go, and ritueel builds the OpenPGP packets itself: one applet, one library, one binary, and no `gpg` at run time. The root cards are used for nothing else, because the program that holds a card keeps every other out. The reasons, and the roads not taken, are in [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/), and the spike behind them in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/).
