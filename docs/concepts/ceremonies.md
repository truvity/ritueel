---
title: The ceremony
description: What happens when a person uses a root, which checks the tool makes before each touch, how a yearly ceremony and a board change differ, and what is still open.
sidebar:
  order: 5
---

*Design phase: no ceremony command exists yet. This page describes what the commands will do ([ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)). The card library is piv-go, and a spike ([issue #26](https://github.com/truvity/ritueel/issues/26)) showed on 2026-11-01 that a key in a PIV slot works as an OpenPGP primary.*

A ceremony is a scripted, reviewable use of a root. It runs on the holder's ordinary workstation, with no live CD and no air gap, because the root keys never leave their cards: a compromised workstation cannot copy a key it never holds. It can still try to trick the holder, which is why the checks below exist.

## What the tool checks

1. **The card.** Detect it, read its serial, and check the serial against the registry of known cards before anything is written.
2. **The attestation of every key it certifies.** For a YubiKey on firmware 5.7 or newer the chain leads to Yubico Attestation Root 1 (`yubico-ca-1.pem`) through Yubico's intermediates; older cards chain to the earlier PIV root. A key that cannot be attested is refused, because an imported key cannot be attested (measured 2026-10-31). The chains are checked against the maker's current root and its full set of intermediates, which ritueel carries and refreshes ([below](#attestation-roots)).
3. **What is about to be signed.** Show the key's fingerprint, its store, its lifetime and the serial before each touch. The holder confirms by comparing, not by pressing a button.
4. **The result.** After signing, verify the certificate or binding against the request.
5. **The record.** Write a hash-chained ceremony record that contains no PIN, no key and no secret.

A PIN is entered by the holder at the terminal. The tool never retries a wrong PIN and refuses to run when a retry counter is below three, because the card blocks after three attempts and then needs the PUK. PINs and admin PINs are kept in the holder's password manager, one entry per card.

## The three ceremonies

| Ceremony | When | Card | Result |
|---|---|---|---|
| Yearly | Month 12 of the intermediates' life | The card for the year | New 13-month certificates and subkey bindings, the card's own root extended, a new keyring package and root list |
| Board add or replace | Between yearly ceremonies | The card for the year | A certificate and binding for the new board key |
| Root add, retire or revoke | A card is lost, retired or compromised | The surviving card | A new root, or a root list without the old one |

Each is a few commands. [A lost root card](/guides/lost-root-card/) walks through the last one.

## A missed touch

A missed touch comes back from the card after about 15 seconds as a generic security status, not as a touch timeout (measured 2026-10-31). Whether the tool reports it as "touch not received" is open.

## Root validity and its extension

A root is valid for about three years, and each use extends it. The card that signs at a ceremony also extends its own root to about three years from that day:

- **OpenPGP.** A new self-signature on the primary moves its expiry.
- **X.509.** The root certificate is re-issued over the same key and the same subject, with a new validity.
- **Pinning holds.** Clients of the signed root list pin the public keys of the roots, not their certificates, and refuse a list with a lower version. A re-issued certificate has the same public key, so the pin holds.
- **A dead or lost card shows itself.** Its root is not extended, and runs out.

`status` warns about a root 6 months, 3 months and 30 days before it expires, with the exit codes 10, 11 and 12. Cards alternate, so a healthy root always has at least about a year left; a warning at 6 months means an extension was missed, with time left to act. The reasons are in [ADR 0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/).

## Which code talks to the cards

The CLI is written in Go, with **piv-go** as the card library. Both root keys of a card live in PIV slots: the X.509 root in slot 9c and the OpenPGP primary in a retired slot. ritueel builds the OpenPGP packets itself, and the card signs digests. That means one applet, one library and one binary, with no `gpg` or `gpg-agent` at run time, and the attestation works the same for both keys. The OpenPGP applet of the card stays free for the holder's own daily use.

A spike on 2026-10-31 on two YubiKey 5 test cards (firmware 5.8.0, OpenPGP applet 3.4) compared the ways to reach the OpenPGP applet. It also showed that a key in a PIV slot makes back-signatures that `gpg`, `gpgv` and `sqv` accept. Findings that count against the other ways:

- `gpg` 2.2 binds an existing P-384 key as an encryption subkey, so a program has to build the binding packets itself either way.
- `gpg` 2.2 sent two wrong PINs to a card, because it does not say which PIN it asks for.
- A card key generated by `gpg` also gets encryption and authentication subkeys, which makes a 1,459-byte certificate against 766 bytes for a bare one.

Because every key is generated on the card, no key is ever in host memory, so the argument for a memory-safe helper that zeroises keys does not apply to key material.

The open test of the primary's own signatures is done (2026-11-01, a YubiKey 5 with firmware 5.8.0, piv-go v2.6.0). A key in a PIV slot is the primary of an OpenPGP version 4 certificate: it makes the direct-key signature, the user ID certification, the subkey binding and the revocations. `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0, `sq` 1.4.1 and apt 3.2.0 accept the certificate and a subkey signature, and rpm 6.0.2 imports it (a signed `.rpm` was not tested). An AWS KMS P-384 key works the same way, as primary and as subkey.

## Attestation roots

piv-go's built-in attestation roots fail on firmware 5.8: the token's certificate is issued by an intermediate that piv-go v2.6.0 does not embed, so `piv.Verify` reports an unknown authority (measured 2026-11-01). ritueel therefore verifies with the maker's current root plus the full intermediate bundle, passed to `piv.Verifier`. The bundle is a file in the repository with a documented refresh step, so a new intermediate is added by a reviewed change and not by a network fetch during an offline ceremony. A fix upstream is wanted too, and is not awaited.

## One card, one lock

The OpenPGP applet and the PIV applet are independent: using PIV changes nothing in the OpenPGP applet's data, PIN counters or signature counter (measured 2026-11-01). The connection to the card is shared, though. piv-go opens the card exclusively, so while `gpg`'s `scdaemon` holds it, piv-go cannot open it, and the other way round. A ceremony on a workstation whose card is also used for daily `gpg` has to stop `scdaemon` first (`gpgconf --kill scdaemon`), and `gpg` waits until the ceremony ends. The simplest answer is **a separate card for roots.**

## KMS keys in a ceremony

A KMS key follows the same ceremony with three differences that come from the service (measured 2026-11-01):

- A P-384 KMS key signs only 48-byte SHA-384 digests, so every P-384 OpenPGP signature uses SHA-384, on every backend.
- The OpenPGP creation time fixes the fingerprint, and KMS's own creation date is not it. ritueel stores the creation time it chose, as a tag on the key and in the published certificate.
- KMS has no attestation. The evidence for a KMS key is its description, its policy and the audit trail.

## Still open

- **One card or two.** A separate card for roots, or one card shared with daily `gpg`. Recommended: separate. Not decided ([ADR 0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/)).
- **The OpenPGP packet library.** ritueel builds packets with ProtonMail/go-crypto, whose signing path takes any `crypto.Signer` but whose constructor for a signing key panics on one; a small bypass works. Keep it, upstream an API, or write the packets ourselves: not decided.
