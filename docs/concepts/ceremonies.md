---
title: The ceremony
description: What happens when a person uses a root, which checks the tool makes before each touch, how a yearly ceremony and a board change differ, and what is still open.
sidebar:
  order: 5
---

*Design phase: no ceremony command exists yet. This page describes what the commands will do ([ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)). The card tool is an [open decision](https://github.com/truvity/ritueel/issues/26).*

A ceremony is a scripted, reviewable use of a root. It runs on the holder's ordinary workstation, with no live CD and no air gap, because the root keys never leave their cards: a compromised workstation cannot copy a key it never holds. It can still try to trick the holder, which is why the checks below exist.

## What the tool checks

1. **The card.** Detect it, read its serial, and check the serial against the registry of known cards before anything is written.
2. **The attestation of every key it certifies.** For a YubiKey on firmware 5.7 or newer the chain leads to Yubico Attestation Root 1 (`yubico-ca-1.pem`) through Yubico's intermediates; older cards chain to the earlier PIV root. A key that cannot be attested is refused, because an imported key cannot be attested (measured 2026-10-31).
3. **What is about to be signed.** Show the key's fingerprint, its store, its lifetime and the serial before each touch. The holder confirms by comparing, not by pressing a button.
4. **The result.** After signing, verify the certificate or binding against the request.
5. **The record.** Write a hash-chained ceremony record that contains no PIN, no key and no secret.

A PIN is entered by the holder at the terminal. The tool never retries a wrong PIN and refuses to run when a retry counter is below three, because the card blocks after three attempts and then needs the PUK. PINs and admin PINs are kept in the holder's password manager, one entry per card.

## The three ceremonies

| Ceremony | When | Card | Result |
|---|---|---|---|
| Yearly | Month 12 of the intermediates' life | The card for the year | New 13-month certificates and subkey bindings, a new keyring package and root list |
| Board add or replace | Between yearly ceremonies | The card for the year | A certificate and binding for the new board key |
| Root add, retire or revoke | A card is lost, retired or compromised | The surviving card | A new root, or a root list without the old one |

Each is a few commands. [A lost root card](/guides/lost-root-card/) walks through the last one.

## A missed touch

A missed touch comes back from the card after about 15 seconds as a generic security status, not as a touch timeout (measured 2026-10-31). Whether the tool reports it as "touch not received" is open.

## Open: which code talks to the cards

The CLI is written in Go. For the OpenPGP applet there are three ways, compared by a spike on 2026-10-31 on two YubiKey 5 test cards (firmware 5.8.0, OpenPGP applet 3.4):

| | Rust helper (`openpgp-card` with rPGP) | Go driving `gpg` 2.2.27 |
|---|---|---|
| A P-384 primary generated on each card | yes, 1.2 s | yes, 4.0 s, but it also writes encryption and authentication subkeys |
| A signing subkey bound under both primaries | yes, 0.3 s per binding | **not with `gpg`**: it binds an existing P-384 key as an encryption subkey; a Go program got there by building the binding packets itself and using `gpg-agent` only as the card signer |
| A card signature | 0.27 s | 0.42 s |
| Certificate | 766 bytes: primary, user ID, subkey | 1,459 bytes: also encryption and authentication subkeys |
| Code | 340 lines | 595 lines, plus `gpg`, `gpg-agent` and `scdaemon` at run time |

`gpg` 2.2 also sent two wrong PINs to a card, because it does not say which PIN it asks for. A Go card library is the third option, if a maintained one exists. Because every key is now generated on the card, no key is ever in host memory, so the argument for a memory-safe helper that zeroises keys no longer applies to key material. The decision is [issue #26](https://github.com/truvity/ritueel/issues/26).
