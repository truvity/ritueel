---
title: OpenPGP release keys and the keyring
description: How an OpenPGP root and a board subkey sign releases, what a keyring package carries, how revocation works, and what gpg, sqv, apt and rpm accept.
sidebar:
  order: 4
---

*Design phase: this page teaches the model of [ADR 0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) and [ADR 0004](/decisions/0004-release-keys-primaries-on-the-roots-signing-subkeys-and-the-keyring-package/). No release is signed until the card roots exist and a drill has run. The tests were run on 2026-10-29 (software keys), 2026-10-31 (two YubiKey 5 test cards, firmware 5.8.0, OpenPGP applet 3.4, and one board's Nano) and 2026-11-01 (a primary in a PIV slot, and AWS KMS keys). The tools that carry out each step are planned.*

OpenPGP has no certificate chains. It has a primary key, subkeys that the primary binds, and certifications. A release is signed by a subkey that a primary has bound, and users verify with a keyring that holds the primaries.

## The shape

- **Two primaries, one on each root card.** Each is generated on its card, in a PIV slot, and attested. A PIV key works as an OpenPGP primary (measured 2026-11-01). Neither is a copy of the other. The same two cards hold the two X.509 roots. ritueel builds the OpenPGP packets itself; the OpenPGP applet of the card stays free for the holder's own use.
- **A primary lasts about three years, and each use extends it** with a new self-signature. A dead card shows itself by not extending.
- **No personal key certifies a primary.** Release trust rests on the dedicated release identity and the keyring, not on anyone's own key.
- **Each board holds one signing subkey,** generated on the board in a PIV slot, bound by the primary of the year. The binding is a signature by the primary. The subkey also makes a *back-signature* (type 0x19) over the primary and itself, which proves that the subkey agreed to be bound. A verifier that checks cross-certification refuses a subkey without it.
- **The subkey lasts about 13 months** and is renewed at the yearly ceremony, so years overlap.
- **Users hold a keyring, not one certificate.** A keyring package carries both primaries and every current subkey binding. A verifier that holds only one primary's certificate cannot check a signature from a subkey that the other bound, so the instructions say "use the keyring package".

## Revocation

- A subkey is revoked by the primary of the year.
- A revocation signature for each primary is made when it is born and stored apart from the card, so a primary can be revoked even if its own card and PIN are gone ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 13.9).
- There is no designated revoker: RFC 9580 (section 5.2.3.23) deprecates the Revocation Key subpacket and says applications must not generate it.

**A revocation signature does not protect every user.** Measured on 2026-11-01 with a revoked primary and a revoked subkey:

| Verifier | What a revoked key does |
|---|---|
| `sqv` 1.5.0, `sq` 1.4.1 | Rejects. A *hard* reason (no reason, compromised) rejects every signature of the key. A *soft* reason (superseded, retired) rejects only signatures made after the revocation and accepts earlier ones. |
| `gpg` 2.4.8 | Marks the key revoked (`[r]`, `REVKEYSIG`) and prints the reason, but `gpg --verify` still says "Good signature" and exits 0. |
| `gpgv` 2.4.8 | Ignores the revocation: a good signature, no warning. |
| apt 3.2.0 | Uses `gpgv`, so it behaves the same. |
| rpm 6.0.2 | Not tested. |

What follows:

- **For apt users, the effective revocation is a new keyring package without the key.** The revocation signature still goes out, for the users of `gpg` and Sequoia, but a user of apt is protected only when the new package arrives.
- **Never treat the exit status of `gpg --verify` as a trust decision.** A script that must refuse a revoked key reads `gpg --status-fd` and rejects `REVKEYSIG`, or uses `sqv`.
- **A soft reason is for retirement, a hard one for theft.** Use "superseded" or "retired" when the key was safe and old signatures should stay valid. Use "compromised" when they should not.
- **Open:** whether to give primaries and subkeys a shorter expiry as well, so that a key nobody revoked stops working sooner. It was not tested against `gpgv` and is not decided ([ADR 0004](/decisions/0004-release-keys-primaries-on-the-roots-signing-subkeys-and-the-keyring-package/)).

## Version 4 now, version 6 later

The maintainer decided on 2026-11-01 that release keys are OpenPGP **version 4** now and **version 6** later, once the verifiers people use accept it. GnuPG implements no version 6 in any release: `gpg` 2.4.8, the current one, refuses to parse a version 6 certificate ("unknown version 6"), and `gpgv` with it. Sequoia (`sqv`, `sq`) accepts it, and honours its revocations. A release key that `gpg` and apt cannot read does not serve its users. The reasons and the road not taken are in [ADR 0004](/decisions/0004-release-keys-primaries-on-the-roots-signing-subkeys-and-the-keyring-package/).

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
| 2026-11-01 | A P-384 key in a PIV slot as the primary: direct-key signature, user ID certification, subkey binding (with the subkey's back-signature), revocations | `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0, `sq` 1.4.1 and apt 3.2.0 accept the certificate and the subkey's signatures; tampered data is refused; rpm 6.0.2 imports the key (signed `.rpm` not tested). Apt needs an armoured `Release` signature |
| 2026-11-01 | The same with an AWS KMS P-384 key as primary and as subkey | The same result; 200 further signatures verified with `gpgv` and `sqv`. Only SHA-384 digests are accepted by the key |
| 2026-11-01 | A revoked primary and a revoked subkey, with hard and soft reasons | See [Revocation](#revocation): `sqv` rejects, `gpgv` and apt do not notice |
| 2026-11-01 | A version 6 certificate with a PIV primary | `gpg` 2.4.8 and `gpgv` refuse to parse it; `sqv` accepts it |

The first two tests bound the subkey under both primaries. The model binds it under the primary of the year only, so "certificate A, B or both" now matters only for the keyring.

## Packaging notes

- **`gpgv` needs a binary keyring.** It cannot read an armored file. apt takes either a binary `.gpg` or an armored `.asc` in `Signed-By`.
- **rpm imports armored keys only.**
- **apt's `Release.gpg` must be armored.** A binary detached signature fails with `NODATA` (apt 2.4, checked again on 2026-10-31).
- **No encryption subkey in the release certificate.** `gpg`'s card key generation adds an ECDH subkey with an AES-192 key wrap, and rpm-sequoia prints a policy warning about it on every install, although the signature verifies. Write only the primary, its user ID and the signing subkeys.
- **Tampered files and certificates that do not match are refused** by every verifier tested.

## Old releases

The first version does nothing for old releases. A keyring drops a superseded primary, so to verify an old signature you need the keyring version of that time.
