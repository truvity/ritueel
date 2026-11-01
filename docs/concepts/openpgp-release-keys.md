---
title: OpenPGP release keys and the keyring
description: How an OpenPGP root and an intermediate's subkey sign releases, what a keyring package carries, and what a revocation reaches in gpg, sqv, apt and rpm.
sidebar:
  order: 5
---

*Design phase: this page teaches the model of [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/). No release is signed until the card roots exist and the adoption drill has run. The measurements are in [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/).*

OpenPGP has no certificate chains. It has a primary key, subkeys that the primary binds, and certifications. A release is signed by a subkey that a primary has bound, and users verify with a keyring that holds the primaries.

## The shape

- **The primaries are on the root cards.** Each is generated on its card, in a PIV slot, and attested; neither is a copy of the other. The same cards hold the X.509 roots. A cloud setup has one primary in its root account.
- **A primary lasts about three years, and each use extends it** with a new self-signature. A dead card shows itself by not extending.
- **No personal key certifies a primary.** Release trust rests on a dedicated release identity and the keyring, not on anyone's own key.
- **Each holder of an intermediate holds one signing subkey,** generated where it lives (a PIV slot or a KMS key). The subkey makes a *back-signature* (type `0x19`) over a primary and itself, which proves it agreed to be bound; `gpg`, `gpgv` and `sqv` refuse a signing subkey without one. **The request carries a back-signature for every active primary,** so either root card can make the binding.
- **The root of the year binds the subkey for about 13 months,** and each yearly ceremony re-signs the binding, so years overlap. The subkey is replaced only on an event, or at most every three years.
- **Users hold a keyring, not one certificate.** The keyring package carries every active primary and every subkey binding. A verifier that holds one primary cannot check a subkey that the other bound, so the instructions say "use the keyring package". Its files are in [the keyring package reference](/reference/keyring-package/).

## Revocation

- A subkey is revoked by the root of the year. A primary is revoked with the revocation signature made when it was born and stored apart from its card ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 13.9). There is no designated revoker: section 5.2.3.23 deprecates it.
- **What is revoked hard leaves the next keyring package:** a revoked primary, and a subkey revoked as compromised. Its revocation signature is published beside the package, for the users of `gpg` and Sequoia.
- **What is retired softly stays,** with its revocation inside the package, so its old signatures keep verifying. Expired subkeys stay too.

**A revocation signature does not protect every user.** Measured on 2026-11-01 with a revoked primary and a revoked subkey:

| Verifier | What a revoked key does |
|---|---|
| `sqv` 1.5.0, `sq` 1.4.1 | Rejects. A *hard* reason (no reason, compromised) rejects every signature of the key. A *soft* reason (superseded, retired) rejects only signatures made after the revocation and accepts earlier ones. |
| `gpg` 2.4.8 | Marks the key revoked (`[r]`, `REVKEYSIG`) and prints the reason, but `gpg --verify` still says "Good signature" and exits 0. |
| `gpgv` 2.4.8 | Ignores the revocation: a good signature, no warning. |
| apt 3.2.0 | Uses `gpgv`, so it behaves the same. |
| rpm 6.0.2 | Not tested yet ([issue #25](https://github.com/truvity/ritueel/issues/25)). |

What follows:

- **For apt users, the effective revocation is a new keyring package without the key.** They are protected only when the new package arrives, so the speed of the ceremony and of your pipeline is what counts.
- **Never treat the exit status of `gpg --verify` as a trust decision.** A script that must refuse a revoked key reads `gpg --status-fd` and rejects `REVKEYSIG`, or uses `sqv`.
- **A soft reason is for retirement, a hard one for theft.** Use "superseded" or "retired" when the key was safe and old signatures should stay valid. Use "compromised" when they should not.

## Version 4 now, version 6 later

Release keys are OpenPGP **version 4**, ECDSA P-384, SHA-384, and **version 6** comes once the verifiers people use accept it. GnuPG implements no version 6: `gpg` 2.4.8 and `gpgv` refuse to parse a version 6 certificate, while Sequoia accepts it (measured 2026-11-01). A release key that `gpg` and apt cannot read does not serve its users. Every signature carries both the Issuer Fingerprint and the Issuer Key ID subpacket, because `gpg` 2.2 rejects a certificate whose signatures lack the key ID.

## How others do it

Checked on 2026-10-29.

- **Debian** signs a stable release's `Release` file with two keys, the archive key of the time and a per-release key, and the keyring package ships every active key. See the [archive keyring package](https://packages.debian.org/sid/debian-archive-keyring) and the [SecureApt history](https://wiki.debian.org/SecureApt).
- **Arch Linux** has five master keys, and a packager key is valid when at least three of them have signed it. See the [master keys](https://archlinux.org/master-keys/).
- **Key transitions** keep the old and the new key valid together for a while, and the old key signs the new one. See the [Apache guide](https://infra.apache.org/key-transition.html) and the [Riseup template](https://help.riseup.net/en/security/message-security/openpgp/key-transition).

## Personal OpenPGP

A person's daily signing subkey is born on the card's OpenPGP applet, so `gpg` uses it directly, and an offline software primary binds it: the card makes the subkey and its back-signature, and the primary makes the binding. A software primary can be copied, and ritueel says so in every record. Where it fits among the stores is in [Where a key lives](/concepts/key-stores/).

## Old releases

The first version does nothing for old releases. A keyring drops a superseded primary, so to verify an old signature you keep the keyring version of that time.
