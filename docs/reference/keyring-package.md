---
title: Keyring package
description: The name, version and files of the keyring package that ritueel builds for apt, rpm and gpg users, and the packaging facts behind them.
sidebar:
  order: 3
---

*Not built yet. The package is decided in [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package); the builder is [issue #15](https://github.com/truvity/ritueel/issues/15).*

## Name and version

- **Name.** `<name>-keyring`, where `<name>` is given to `ritueel keyring build --name`. The same name for the `.deb` and the `.rpm`, and for every version, so an upgrade replaces the old keyring.
- **Version.** `<year>.<sequence>`: the year of the ceremony, then the [trust sequence](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#one-counter-the-trust-sequence). A package manager compares the year first, so a newer package always compares newer.
- **Fields.** Architecture-independent, no dependencies.

## Files

| File | In | Content |
|---|---|---|
| `/usr/share/keyrings/<name>-keyring.gpg` | `.deb`, `.rpm`, plain | Every active primary's certificate, binary. For `gpgv`, `sqv` and apt `Signed-By`. |
| `/usr/share/keyrings/<name>-keyring.asc` | `.deb`, `.rpm`, plain | The same, armoured. |
| `/etc/pki/rpm-gpg/RPM-GPG-KEY-<name>-<short fingerprint>` | `.rpm` | One armoured file for each primary, for `rpm --import` and a repository file's `gpgkey=`. |
| `<name>-keyring.fingerprints` | plain | One line for each primary: fingerprint, role, creation and expiry. |
| `SHA256SUMS` | plain | Digests of the files above. |

Beside the package, not in it: the revocation signature of every primary or subkey that was revoked hard and dropped from this version.

## Build

The build needs neither `dpkg-deb` nor `rpmbuild`. It is deterministic: the build time is the ceremony time (`SOURCE_DATE_EPOCH`), entries are sorted, owners and modes are fixed, so the same directory gives the same bytes. ritueel does not sign or publish the package; the user's repository signs it with its current subkey.

## Packaging facts

Measured on 2026-10-29 and 2026-10-31 ([the verifier matrix](/research/openpgp-verifier-matrix-2026-11/)):

- `gpgv` needs a binary keyring; it cannot read an armoured file. apt takes a binary `.gpg` or an armoured `.asc` in `Signed-By`.
- rpm imports armoured keys only. One file with two certificates was imported on rpm 6.0 only, so the package ships one file per primary.
- apt's `Release.gpg` must be armoured; a binary detached signature fails with `NODATA`.
- An encryption subkey in a release certificate makes rpm-sequoia print a policy warning on every install, so the certificates carry signing subkeys only.
