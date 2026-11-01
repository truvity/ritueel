---
title: OpenPGP release keys and the keyring
description: How an OpenPGP root and a board subkey sign releases, what a keyring package carries, how revocation works, and what gpg, sqv, apt and rpm were tested to accept.
sidebar:
  order: 4
---

*Design phase: this page teaches the model of [ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/). The tests were run on 2026-10-29 (software keys) and 2026-10-31 (two YubiKey 5 test cards, firmware 5.8.0, OpenPGP applet 3.4, and one board's Nano). The tools that carry out each step are planned.*

OpenPGP has no certificate chains. It has a primary key, subkeys that the primary binds, and certifications. A release is signed by a subkey that a primary has bound, and users verify with a keyring that holds the primaries.

## The shape

- **Two primaries, one on each root card.** Each is generated on its card and attested. Neither is a copy of the other. The same two cards hold the two X.509 roots.
- **Each board holds one signing subkey,** generated on the board in a PIV slot, bound by the primary of the year. The binding is a signature by the primary. The subkey also makes a *back-signature* (type 0x19) over the primary and itself, which proves that the subkey agreed to be bound. A verifier that checks cross-certification refuses a subkey without it.
- **The subkey lasts about 13 months** and is renewed at the yearly ceremony, so years overlap.
- **Users hold a keyring, not one certificate.** A keyring package carries both primaries and every current subkey binding. A verifier that holds only one primary's certificate cannot check a signature from a subkey that the other bound, so the instructions say "use the keyring package".

## Revocation

- A subkey is revoked by the primary of the year.
- A revocation certificate for each primary is made when it is born and stored apart from the card. Each primary is named the designated revoker of the other, so a primary can be revoked even if its own card and PIN are gone.
- Whether `gpg`, `gpgv`, `sqv`, apt and rpm honour a pre-made revocation certificate and a designated revoker is **assumed, not tested**. A half-day test on test cards must show it before a guide claims it ([issue #24](https://github.com/truvity/ritueel/issues/24)).

## How others do it

Checked on 2026-10-29.

- **Debian** signs a stable release's `Release` file with two keys, the archive key of the time and a per-release key, and the keyring package ships every active key. See the [archive keyring package](https://packages.debian.org/sid/debian-archive-keyring) and the [SecureApt history](https://wiki.debian.org/SecureApt).
- **Arch Linux** has five master keys, and a packager key is valid when at least three of them have signed it. See the [master keys](https://archlinux.org/master-keys/).
- **Key transitions** keep the old and the new key valid together for a while, and the old key signs the new one. See the [Apache guide](https://infra.apache.org/key-transition.html) and the [Riseup template](https://help.riseup.net/en/security/message-security/openpgp/key-transition).

## What was tested

| Date | What | Result |
|---|---|---|
| 2026-10-29 | One subkey bound under two software primaries; certificate A, B, and A with B, in both import orders | `gpg` and `gpgv` 2.4.8, `sqv` 1.5.0, apt 2.6 (via `gpgv`) and 3.0 (via `sqv`), and rpm 6.0 (rpm-sequoia) accepted the signature every time |
| 2026-10-31 | A P-384 primary on each of two YubiKey 5 test cards, one signing subkey bound under both | `gpg` and `gpgv` 2.2.27, 2.2.40 and 2.4.7, `sqv` 1.1.0 and 1.3.0, apt 2.4.14, 2.6.1 and 3.0.3, and rpm 6.0.2 with rpm-sequoia 1.10.2 accepted every signature with certificate A, B or both. Tampered files and unrelated certificates were refused. ECDSA P-384 release signatures work with apt and rpm |
| 2026-10-31 | A subkey whose key is in a PIV slot of a board, back-signature made by the card | `gpg`, `gpgv` and `sqv` accept it. Without the back-signature `gpg` and `gpgv` refuse (`not cross-certified`) and `sqv` reports no binding signature |
| 2026-10-31 | `gpg` 2.2.27 and 2.4.7 asked to bind an existing P-384 key as a signing subkey | Both bind it as an encryption subkey; `--quick-add-key` refuses a keygrip. A tool has to build the binding packets itself |

The first two tests bound the subkey under both primaries. The model binds it under the primary of the year only, so "certificate A, B or both" now matters only for the keyring.

## Packaging notes

- **`gpgv` needs a binary keyring.** It cannot read an armored file. apt takes either a binary `.gpg` or an armored `.asc` in `Signed-By`.
- **rpm imports armored keys only.**
- **apt's `Release.gpg` must be armored.** A binary detached signature fails with `NODATA` (apt 2.4, checked again on 2026-10-31).
- **No encryption subkey in the release certificate.** `gpg`'s card key generation adds an ECDH subkey with an AES-192 key wrap, and rpm-sequoia prints a policy warning about it on every install, although the signature verifies. Write only the primary, its user ID and the signing subkeys.
- **Tampered files and certificates that do not match are refused** by every verifier tested.
