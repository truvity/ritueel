---
title: Card libraries and tooling (2026-11-01)
description: Which Go code drives the root cards and a person's OpenPGP card, measured on YubiKey 5 test cards and AWS KMS keys. Verdict, method and numbers.
sidebar:
  order: 1
---

## Question

Which code should ritueel use to drive the cards: for the root keys, and for a person's daily OpenPGP key? The spike is [issue #26](https://github.com/truvity/ritueel/issues/26); the decision is [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/).

## When

2026-10-31 (two YubiKey 5 test cards, firmware 5.8.0, OpenPGP applet 3.4) and 2026-11-01 (a YubiKey 5, firmware 5.8.0, and two AWS KMS `ECC_NIST_P384` keys).

## Verdict

**piv-go for the roots, with both root keys in PIV slots and ritueel building the OpenPGP packets; a patched fork of go-openpgp-card for a person's OpenPGP card.** A P-384 key in a PIV slot, and one in KMS, works as an OpenPGP version 4 primary and subkey for every verifier tested. piv-go's built-in attestation roots fail on firmware 5.8, go-openpgp-card needs three fixes on it, and the two applets of a card share one PC/SC lock.

## Method

- **Root keys in PIV.** piv-go v2.6.0 generated P-384 keys in slot 9c and in retired slots. ritueel's prototype built the OpenPGP packets with ProtonMail/go-crypto v1.5.2 and had the card sign the digests: a direct-key signature (`0x1F`), a user ID certification (`0x13`), a subkey binding (`0x18`) with the subkey's back-signature (`0x19`), and revocations (`0x20`, `0x28`). The certificates went through the [verifier matrix](/research/openpgp-verifier-matrix-2026-11/).
- **KMS keys.** The same packets with an `ECC_NIST_P384` key as primary and as subkey, through the AWS SDK.
- **The OpenPGP applet.** cunicu's go-openpgp-card (latest release v0.3.11, on Codeberg) generated a P-384 signing key on the applet and made its back-signature; a software primary made the binding.
- **The other ways to reach a card** (2026-10-31): a Go program driving `gpg` 2.2.27 and `gpg-agent`, and a Rust helper on openpgp-card 0.7.0, openpgp-card-rpgp 0.8.1 and rPGP 0.20.0.

## What the setup over- and under-counts

- Test cards on one host, with no other card software running except where the PC/SC lock was tested: real workstations run `scdaemon`, which makes the lock matter more, not less.
- Timings include one PIN verification per process; a ceremony with many signatures in one session is faster per signature.
- The touch policy was not exercised: every test ran without a person at the card, so the behaviour of touch always across a long ceremony is not measured ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Numbers

| What | Result |
|---|---|
| One PIV card signature (P-384) | About 150 ms; a certificate with three signatures about 450 ms. About 7 signatures a second. |
| One KMS signature | About 15 ms; 200 further signatures verified with `gpgv` and `sqv`. |
| OpenPGP applet signing, including the PIN check | About 4 signatures a second. |
| Missed touch | Comes back after about 15 s (14.6 s measured) as a generic security status, not as a touch timeout. |
| Certificate size, bare primary, user ID and subkey | 766 bytes; 1,459 bytes when `gpg` generates the card key, because it adds encryption and authentication subkeys. |
| Spike code | Go with `gpg-agent`: 595 lines. Rust helper: 340 lines. |

Findings that are not numbers:

- **piv-go's built-in attestation roots fail on firmware 5.8.** The token's certificate is issued by an intermediate that piv-go v2.6.0 does not embed, and `piv.Verify` answers "certificate signed by unknown authority". Verification passes with the maker's current root and the full intermediate bundle given to `piv.Verifier`.
- **The two applets are independent.** Generating keys in six PIV slots, signing, and one wrong PIV PIN changed nothing in the OpenPGP applet: its data, PIN counters and signature counter were identical before and after, on two cards.
- **The PC/SC connection is one lock.** piv-go opens the card exclusively. While `scdaemon` holds it, piv-go cannot open it, and the reverse; both fail at once and nothing is corrupted. `gpgconf --kill scdaemon` frees it.
- **go-openpgp-card on firmware 5.8.** Reading the supported algorithms fails without a three-line patch. The fingerprint it stores for an ECDSA key is wrong, because it appends ECDH key-derivation parameters; writing the correct one with PUT DATA fixes it. It has no attestation: the YubiKey command `80 FB 01 00` works after the user PIN is verified, and the certificate chains to the maker's current root through the intermediate "Yubico OPGP Attestation B2 1", with extensions under `1.3.6.1.4.1.41482.5`. The user PIN does not survive reopening the card, and `Close()` resets it (`SCARD_RESET_CARD`). The last functional commit was in December 2024, by one maintainer.
- **go-crypto.** It writes every packet needed, and its ECDSA signing path takes any `crypto.Signer`, but `NewSignerPrivateKey` panics on a signer that is not a concrete key type; a bypass of about 40 lines works. It writes version 4 signatures with the Issuer Fingerprint subpacket only, which `gpg` 2.2.27 rejects on import.
- **KMS and OpenPGP.** A P-384 KMS key signs only 48-byte SHA-384 digests. Its creation date is not the OpenPGP creation time, which fixes the fingerprint and must be stored.
- **`gpg` as the card layer.** `gpg` 2.2.27 and 2.4.7 bind an existing P-384 key only as an encryption subkey, and `--quick-add-key` refuses a keygrip, so a program has to build the binding itself. `gpg` 2.2 sent two wrong PINs to a test card, because it does not say which PIN it asks for.

## Roads not taken

- **Own PC/SC code for the OpenPGP applet of the root cards.** The most used Go PC/SC binding was last pushed on 2024-12-14, and the PIV route needs no applet code.
- **Go with `gpg-agent` as the card signer.** It worked, but depends on `gpg` at run time and on a PIN dialogue the tool does not control.
- **A Rust helper.** It did every step, but adds a second language for a memory-safety argument that is gone when keys are born on the card.

## Open questions

None for the decision. The touch-policy test is a follow-up of ADR 0003 ([issue #11](https://github.com/truvity/ritueel/issues/11)), and so is the encoding of the OpenPGP-applet attestation extensions ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Changes made

Test cards only. On 2026-10-31 both cards were checked to be in factory state before the run and reset to it afterwards, and the software stand-in key was deleted. The two KMS keys made on 2026-11-01 were throw-away keys, for deletion by the maintainer.

## Raw logs

Kept with the maintainer's internal notes; the summaries are in the comments of [issue #26](https://github.com/truvity/ritueel/issues/26).
