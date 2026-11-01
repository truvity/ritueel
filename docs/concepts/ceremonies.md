---
title: The ceremony
description: What happens when a person uses a root, which checks the tool makes before each touch, how a yearly renewal differs from an intermediate change, what is open.
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
| Yearly | Month 12 of the intermediates' life | The card for the year | Renewal by re-signing: new 13-month certificates over the same intermediate keys, and new bindings that extend the same subkeys' expiry. The card's own root extended, a new keyring package and root list |
| Intermediate add, replace or revoke | Between yearly ceremonies | The card for the year | `add`: a certificate and binding for a new intermediate. `replace`: new key material, on an event. `revoke`: the certificate and binding withdrawn |
| Root add, retire or revoke | A card is lost, retired or compromised | The surviving card | A new root, or a root list without the old one |

Each is a few commands (`ritueel yearly`, `ritueel intermediate add|replace|revoke`, `ritueel root add|retire|revoke`). [A lost root card](/guides/lost-root-card/) walks through the last one.

## Renewal and replacement

The yearly ceremony **renews by re-signing**: new certificates over the same intermediate keys, and new bindings that extend the same subkeys' expiry. Roots are extended at each use, as below. **Key material is replaced only on an event** (a suspected compromise, a change of store or algorithm, a change of custody) **or at most every 3 years**, which is the one to three years that NIST SP 800-57 gives for a private signature key. The forced replacement at three years keeps the replace path (`intermediate replace`) tested, so it works on the day an event needs it. The reasons are in [ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/#renewal-and-replacement).

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

The CLI is written in Go. For the roots, **piv-go** is the card library (the `piv` store). Both root keys of a card live in PIV slots: the X.509 root in slot 9c and the OpenPGP primary in a retired slot. ritueel builds the OpenPGP packets itself, and the card signs digests. That means one applet, one library and one binary, with no `gpg` or `gpg-agent` at run time, and the attestation works the same for both keys. The OpenPGP applet of the card stays free for the holder's own daily use.

A spike on 2026-10-31 on two YubiKey 5 test cards (firmware 5.8.0, OpenPGP applet 3.4) compared the ways to reach the OpenPGP applet. It also showed that a key in a PIV slot makes back-signatures that `gpg`, `gpgv` and `sqv` accept. Findings that count against the other ways:

- `gpg` 2.2 binds an existing P-384 key as an encryption subkey, so a program has to build the binding packets itself either way.
- `gpg` 2.2 sent two wrong PINs to a card, because it does not say which PIN it asks for.
- A card key generated by `gpg` also gets encryption and authentication subkeys, which makes a 1,459-byte certificate against 766 bytes for a bare one.

Because every key is generated on the card, no key is ever in host memory, so the argument for a memory-safe helper that zeroises keys does not apply to key material.

The open test of the primary's own signatures is done (2026-11-01, a YubiKey 5 with firmware 5.8.0, piv-go v2.6.0). A key in a PIV slot is the primary of an OpenPGP version 4 certificate: it makes the direct-key signature, the user ID certification, the subkey binding and the revocations. `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0, `sq` 1.4.1 and apt 3.2.0 accept the certificate and a subkey signature, and rpm 6.0.2 imports it (a signed `.rpm` was not tested). An AWS KMS P-384 key works the same way, as primary and as subkey.

## The OpenPGP card store

A person's daily OpenPGP subkey is born on the card's OpenPGP applet, in the `openpgp-card` store, so that `gpg` can use it, and a software primary binds it. The card library is cunicu's go-openpgp-card (OpenPGP card specification 3.4.1; it has moved to Codeberg; latest release v0.3.11; last functional commit in December 2024; one maintainer). ritueel therefore vendors **a patched fork behind a small interface**. If the fork cannot be kept, the fallback is a small driver of our own on go-iso7816, and after that `scdaemon`. What was measured on 2026-11-01 on a test YubiKey 5 (firmware 5.8):

- A card-generated P-384 signing key, a back-signature (`0x19`) made by the card and a binding (`0x18`) made by a software primary are accepted by `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0 and `sq` 1.4.1, and `gpg` 2.2.27 with `scdaemon` signs with the card's subkey.
- On firmware 5.8 the library needs fixes. Reading the supported algorithms fails without a three-line patch. The fingerprint it stores for an ECDSA key is wrong, because it appends ECDH key-derivation parameters; ritueel writes the correct fingerprint with PUT DATA. It has no attestation: the YubiKey command `80 FB 01 00` works after the user PIN is verified, and the certificate chains to Yubico's current roots through "Yubico OPGP Attestation B2 1", with extensions under OID `1.3.6.1.4.1.41482.5`.
- Verifying the PIN does not survive reopening the card, so every process verifies again. The library opens the card exclusively, and closing it resets the card (`SCARD_RESET_CARD`). Signing runs at about four signatures a second, including the PIN check.

The decision and its alternatives are in [ADR 0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/).

## Attestation roots

piv-go's built-in attestation roots fail on firmware 5.8: the token's certificate is issued by an intermediate that piv-go v2.6.0 does not embed, so `piv.Verify` reports an unknown authority (measured 2026-11-01). ritueel therefore verifies with the maker's current root plus the full intermediate bundle, passed to `piv.Verifier`. The bundle is a file in the repository with a documented refresh step, so a new intermediate is added by a reviewed change and not by a network fetch during an offline ceremony. A fix upstream is wanted too, and is not awaited.

## One card, one lock

The OpenPGP applet and the PIV applet are independent: using PIV changes nothing in the OpenPGP applet's data, PIN counters or signature counter (measured 2026-11-01). The connection to the card is shared, though. piv-go opens the card exclusively, so while `gpg`'s `scdaemon` holds it, piv-go cannot open it, and the other way round. A ceremony on a workstation whose card is also used for daily `gpg` has to stop `scdaemon` first (`gpgconf --kill scdaemon`), and `gpg` waits until the ceremony ends. The simplest answer is **a separate card for roots.**

## KMS keys in a ceremony

A KMS key follows the same ceremony with three differences that come from the service (measured 2026-11-01). A company root in KMS is one key and a multi-Region replica in one dedicated root account; with one root there is nothing to alternate, and a compromise is answered by revocation and a transition ([ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)).

- A P-384 KMS key signs only 48-byte SHA-384 digests, so every P-384 OpenPGP signature uses SHA-384, on every backend.
- The OpenPGP creation time fixes the fingerprint, and KMS's own creation date is not it. ritueel stores the creation time it chose, as a tag on the key and in the published certificate.
- KMS has no attestation. The evidence for a KMS key is its description, its policy and the audit trail. For a key in another account, ritueel assumes a small read-only role inside that account, because `GetKeyPolicy` does not work across accounts.

## Still open

- **One card or two.** A separate card for roots, or one card shared with daily `gpg`. Recommended: separate. Not decided ([ADR 0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/)).
- **The OpenPGP packet library.** ritueel builds packets with ProtonMail/go-crypto, whose signing path takes any `crypto.Signer` but whose constructor for a signing key panics on one; a small bypass works. Keep it, upstream an API, or write the packets ourselves: not decided.
