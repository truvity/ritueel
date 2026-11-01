---
title: OpenPGP verifier matrix (2026-11)
description: What gpg, gpgv, sqv, apt and rpm accept from ECDSA P-384 release keys on cards and in KMS, how they treat revocations, and what version 6 does.
sidebar:
  order: 2
---

## Question

Which OpenPGP keys, signatures and revocations do the verifiers that users have accept? The answers shape [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/) and the [revocation table](/learn/openpgp-release-keys/#revocation).

## When

2026-10-29 (software keys), 2026-10-31 (two YubiKey 5 test cards, firmware 5.8.0, OpenPGP applet 3.4, and a small-form YubiKey), and 2026-11-01 (a primary in a PIV slot, AWS KMS keys, revocations, version 6).

## Verdict

**ECDSA P-384 version 4 keys with SHA-384 work with every verifier tested, from a card or from KMS; version 6 does not work with GnuPG; and a revocation signature reaches `sqv` only.** `gpgv`, and so apt, ignores revocations, and `gpg --verify` exits 0 for a revoked key. A signing subkey needs its back-signature, and every signature needs the Issuer Key ID subpacket for `gpg` 2.2.

## Method

Certificates were built by test programs (go-crypto v1.5.2 packets, signed by a card through piv-go v2.6.0, by KMS, or in software), then imported and checked with each verifier, reading its status output and not only its exit code. Each run had a tampered file and an unrelated certificate as negative controls.

## What the setup over- and under-counts

- rpm was tested for import only; a signed `.rpm` package was not verified, so rpm's handling of the release signature itself and of revocations is unmeasured ([issue #25](https://github.com/truvity/ritueel/issues/25)).
- Older rpm releases and a combined armoured file were not tested ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- The verifiers were current distribution builds; a distribution that patches `gpgv` could behave differently.

## Numbers

| Date | What | Result |
|---|---|---|
| 2026-10-29 | One subkey bound under two software primaries; certificate A, B, and A with B, in both import orders | `gpg` and `gpgv` 2.4.8, `sqv` 1.5.0, apt 2.6 (via `gpgv`) and 3.0 (via `sqv`), and rpm 6.0 (rpm-sequoia) accepted the signature every time. |
| 2026-10-31 | A P-384 primary on each of two test cards, one signing subkey bound under both | `gpg` and `gpgv` 2.2.27, 2.2.40 and 2.4.7, `sqv` 1.1.0 and 1.3.0, apt 2.4.14, 2.6.1 and 3.0.3, and rpm 6.0.2 with rpm-sequoia 1.10.2 accepted every signature with certificate A, B or both. Tampered files and unrelated certificates were refused. |
| 2026-10-31 | A subkey in a PIV slot of a small token, back-signature made by the card | `gpg`, `gpgv` and `sqv` accept it. Without the back-signature `gpg` and `gpgv` refuse (`not cross-certified`) and `sqv` reports no binding signature. |
| 2026-10-31 | `gpg` 2.2.27 and 2.4.7 asked to bind an existing P-384 key as a signing subkey | Both bind it as an encryption subkey; `--quick-add-key` refuses a keygrip. |
| 2026-11-01 | A P-384 key in a PIV slot as the primary: direct-key signature, user ID certification, subkey binding with back-signature, revocations | `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0, `sq` 1.4.1 and apt 3.2.0 accept the certificate and the subkey's signatures; tampered data is refused; rpm 6.0.2 imports the key. apt needs an armoured `Release` signature. |
| 2026-11-01 | The same with an AWS KMS P-384 key as primary and as subkey | The same result; 200 further signatures verified with `gpgv` and `sqv`. The key accepts only SHA-384 digests. |
| 2026-11-01 | A revoked primary and a revoked subkey, with hard and soft reasons | `sqv` and `sq` reject (hard: every signature; soft: only later ones). `gpg` 2.4.8 marks the key revoked and prints `REVKEYSIG`, and `gpg --verify` exits 0. `gpgv` and apt 3.2.0 report a good signature. |
| 2026-11-01 | A version 6 certificate with a PIV primary | `gpg` 2.4.8 and `gpgv` refuse to parse it ("unknown version 6"); `sqv` 1.5.0 accepts it. |
| 2026-11-01 | A P-384 signing subkey generated on the OpenPGP applet, its back-signature made by the card, bound by a software primary | `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0 and `sq` 1.4.1 accept it; `gpg` 2.2.27 with `scdaemon` signs with the card's subkey. |
| 2026-11-01 | A certificate whose signatures carry the Issuer Fingerprint subpacket only, as go-crypto v1.5.2 writes them | `gpg` 2.2.27 rejects it on import. Adding the Issuer Key ID subpacket fixes it. |

The first two rows bound the subkey under both primaries. The model binds it under the root of the year only, so "certificate A, B or both" now matters only for the keyring.

## Roads not taken

- **Exit codes as the result.** `gpg --verify` exits 0 for a revoked key, so every row reads status output.
- **Version 6 keys in the matrix beyond parsing.** Without GnuPG support there is no consumer to test for.

## Open questions

None for the decisions. The rpm column (a signed `.rpm`, and revocations) belongs to [issue #25](https://github.com/truvity/ritueel/issues/25), and older rpm to [issue #15](https://github.com/truvity/ritueel/issues/15). GnuPG was not yet run on the hand-off test vectors.

## Changes made

Test keys and test cards only. The cards of 2026-10-31 were reset to factory state after the run ([card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/#changes-made)).

## Raw logs

Kept with the maintainer's internal notes; summaries are in [issue #26](https://github.com/truvity/ritueel/issues/26) and [issue #25](https://github.com/truvity/ritueel/issues/25).
