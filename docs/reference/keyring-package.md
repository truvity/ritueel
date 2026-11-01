---
title: Keyring package
description: The name, version, files, build and verify steps of the keyring package that ritueel builds as .deb, .rpm and plain files, and what older rpm support means.
sidebar:
  order: 3
---

*Not built yet. The package is decided in [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package); the builder is [issue #15](https://github.com/truvity/ritueel/issues/15), in M3. This page is the specification the builder follows: what is in the package, how it is built and checked, and which installers it is tested on. What it says was measured carries a date.*

The keyring package carries the public certificates of every active primary to apt, rpm and `gpg` users, so that a signature by any subkey a primary bound verifies. ritueel builds it. It does not sign or publish it: the user's repository signs it with its current subkey ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package)).

## Name and version

- **Name.** `<name>-keyring`, where `<name>` is given to `ritueel keyring build --name`: lower-case letters, digits and hyphens, 1 to 63 characters, starting with a letter or a digit. The same name for the `.deb` and the `.rpm`, and for every version, so an upgrade replaces the old keyring.
- **Version.** `<year>.<sequence>`: the year of the ceremony, then the [trust sequence](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#one-counter-the-trust-sequence). A package manager compares the year first, then the sequence as a number, so a newer package always compares newer (`2026.10` after `2026.9`).
- **Fields.** Architecture-independent, no dependencies, no scripts. The maintainer is the release identity of `ritueel.yaml` (`<name> Release <release_address>`), never a person.

## Files

The package puts these files on the system. The same files are written beside the packages as the plain form.

| File | In | Content |
|---|---|---|
| `/usr/share/keyrings/<name>-keyring.gpg` | `.deb`, `.rpm`, plain | Every active primary's certificate, binary. For `gpgv`, `sqv` and apt `Signed-By`. |
| `/usr/share/keyrings/<name>-keyring.asc` | `.deb`, `.rpm`, plain | The same, armoured. |
| `/etc/pki/rpm-gpg/RPM-GPG-KEY-<name>-<short fingerprint>` | `.rpm` | One armoured file for each primary, for `rpm --import` and a repository file's `gpgkey=`. The short fingerprint is the last 16 hexadecimal digits of the primary's fingerprint, in lower case. |
| `<name>-keyring.fingerprints` | plain | One line for each primary: fingerprint, role, creation and expiry. |
| `SHA256SUMS` | plain | Digests of the files above and of the two packages. |

The builder writes them under `products/<sequence>/keyring/`: the two packages, `<name>-keyring_<version>_all.deb` and `<name>-keyring-<version>-1.noarch.rpm`, and the plain files beside them. A `.deb` holds only the first two files, and a `.rpm` the first three. The key files of a package do not replace a user's own keyring: apt reads `Signed-By`, and rpm imports only when told to.

Beside the packages, not in them, in `products/<sequence>/revocations/`: the revocation signature of every primary or subkey that was revoked hard and dropped from this version, armoured, one file for each, named by the fingerprint it revokes. The holder gives a primary's stored revocation signature to `root revoke`, which checks its digest against `revocation_sha256` of the root ([the directory](/reference/directory/#rootjson)) before it publishes it; a subkey's revocation is made at the ceremony.

## What the certificates hold

For each active primary, in the order of the root list, one complete public certificate, as OpenPGP packets in this order (RFC 9580, section 10.1):

1. The primary key packet.
2. The user ID packet (the release identity) with every certification ritueel made on it, in creation order. The yearly extension adds one each time; a verifier takes the newest as of the time it checks.
3. For every subkey the primary ever bound, in the order of the subkey's creation time and then its fingerprint: the subkey packet, every binding signature ritueel made for it (each with its embedded back-signature), in creation order, then its subkey revocation if it was retired softly.

Left out: an encryption subkey, a third-party certification, a notation, and anything revoked hard, which means a whole certificate of a revoked primary and the whole subkey of one revoked as compromised ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#revocation)). The binding signatures are kept even when newer ones exist, so that a signature made before a renewal verifies at its own time. The certificates are read from the directory: the primary's `openpgp.pgp` and the bindings in `answers/`.

The binary form is the packets, concatenated; the armoured form is a single block of the same bytes (RFC 9580, section 6) with the header `-----BEGIN PGP PUBLIC KEY BLOCK-----`, no `Version` or `Comment` header, Base64 in lines of 64 characters and the CRC-24 line, because every reader of armour reads it.

## Build

The build needs neither `dpkg-deb` nor `rpmbuild`, and the same directory gives the same bytes. In order:

1. **Read** the newest root list of the directory ([the root list](/reference/root-list/)) and the certificates it names. The list's `sequence` and the year of its `signed_at` give the version. A test root and a real root are never mixed, as for the CA bundle.
2. **Assemble** the certificates as above, drop what is revoked hard, and write the binary and armoured forms and one armoured file for each primary.
3. **Write the `.deb`**: an `ar` archive of three members in this order, `debian-binary` (`2.0`), `control.tar` and `data.tar`, then the `.rpm`: the lead, the header with the tags a noarch package of files needs, and a `cpio` payload (`newc` format).
4. **Fix every variable field**: the build time and every file's modification time is the ceremony time (`SOURCE_DATE_EPOCH`), entries are sorted, owner and group are root (numeric 0), files have mode 0644 and directories 0755, there are no extended attributes, and the `.rpm` has no build host or signature.
5. **Verify** the result ([below](/reference/keyring-package/#verify)) and only then write it out. ritueel never writes a package it has not read back.

**Compression.** The tar and cpio members are not compressed. They are a few kilobytes of keys, and a compressor's output changes with its version, which would break the rule that the same directory gives the same bytes across toolchains. `dpkg-deb` 1.23.7 reads an uncompressed `control.tar` and `data.tar` (checked 2026-11-01). Whether the oldest rpm in the matrix reads an uncompressed payload is part of the matrix below; if one refuses it, the payload is gzip from one pinned implementation, and the goldens move with the pin.

**The writer.** An archive writer is chosen for `ar`, `tar`, `cpio` and the rpm header: a library such as nfpm, or code of our own. The criteria are the ones above and in [issue #15](https://github.com/truvity/ritueel/issues/15): no external tool, byte-identical output on a second run, and a reader of its own that the verify step uses, so that nothing is checked by the code that wrote it.

ritueel does not sign the package. A pipeline signs the `.deb` and the `.rpm`, or the `Release` file of its repository, with the current subkey. The pipeline's own steps are a page of the guide, not a feature of ritueel.

## Verify

`ritueel keyring verify FILE... --root-list FILE [--dir DIR]` reads packages and plain files and checks them with code of its own that did not build them. The builder runs the same checks on its output. The first check that fails gives the reason code.

| # | Check | Code |
|---|---|---|
| 1 | Each file parses as what its name says: an `ar` archive of the three members with `debian-binary` `2.0`, or an rpm with a `noarch` header and a `cpio` payload; a `.gpg` or `.asc` of OpenPGP packets. | `malformed` |
| 2 | The name and version fields are those of the file name, and the version is `<year>.<sequence>` with `sequence` equal to the root list's. | `version-mismatch` |
| 3 | The package holds exactly the files of the table above for its kind, with the owner, modes and times of the build. | `files-mismatch` |
| 4 | The primaries in the certificates are exactly the `openpgp_fingerprint` of the roots on the root list, in its order, and each rpm key file holds one of them, named by its short fingerprint. | `primaries-mismatch` |
| 5 | Every binding signature verifies with its primary over the primary and the subkey, with the embedded back-signature of the subkey for that primary; every certification verifies; every signature has both the issuer fingerprint and the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). | `signature-invalid` |
| 6 | No encryption subkey, no third-party certification, and nothing that is revoked hard. With `--dir`, every subkey the directory's answers bound and the records did not revoke hard is present. | `contents-mismatch` |
| 7 | The `.gpg` and the `.asc` hold the same packets, and the digests in `SHA256SUMS` are those of the files. | `malformed` |

Without `--dir`, check 6 can only look at what is inside. It exits 0 when every check passes and 3 with the code when one fails; it writes nothing ([Commands](/reference/cli/#commands-for-the-trust-products-after-m1)). These codes belong to the checker and are not sent anywhere.

## The installer matrix, and what older rpm means

The package is also tested by installing it, on the installers people have, and by verifying a real signature with what it installed. CI does this for the current `dpkg`, `apt` and `rpm` in a scratch root, with no container ([issue #15](https://github.com/truvity/ritueel/issues/15)): install the package, verify a signature by a subkey the keyring lists with `gpgv` and `sqv`, upgrade to a package that drops a key and see the key gone, and see a signature by the dropped key refused. The older releases cannot be a CI job, because they are old operating systems; they are a dated measurement, repeated before a release that changes the package.

**Older rpm.** The keyring is OpenPGP version 4 ECDSA P-384 with SHA-384 ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys)), and ritueel does not change the algorithm to reach an old installer. So *support* for an rpm release is a floor that is measured and not a promise: ritueel supports every rpm release that

1. imports each per-primary armoured key file (`rpm --import`, and `gpgkey=` in a repository file), and
2. verifies a package signed by an ECDSA P-384 version 4 subkey the imported certificate binds (`rpmkeys --checksig`), and
3. installs the package, with its payload as written.

The matrix lists the releases to try: the newest rpm (6.0, whose import was measured on 2026-10-29 and 2026-11-01, [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/)), the rpm of a current Fedora, and the rpm of each enterprise distribution release still in vendor support, down to the oldest. The result is a table of releases against these three checks, with the versions and the date, on a research page and in the guide. A release that fails check 2 is *unsupported*, and the guide says so and says which is the first that works; it is not a reason to change a key. A release that fails check 3 only is a reason for gzip, as above.

**The combined armoured file** (one file with two certificates, which rpm 6.0 imported and nothing else was tried on) is not shipped. The per-primary files work wherever rpm imports at all, and no consumer needs one file. The question is closed unless a consumer asks.

## Packaging facts

Measured on 2026-10-29 and 2026-10-31 ([the verifier matrix](/research/openpgp-verifier-matrix-2026-11/)):

- `gpgv` needs a binary keyring; it cannot read an armoured file. apt takes a binary `.gpg` or an armoured `.asc` in `Signed-By`.
- rpm imports armoured keys only. One file with two certificates was imported on rpm 6.0 only, so the package ships one file per primary.
- apt's `Release.gpg` must be armoured; a binary detached signature fails with `NODATA`.
- An encryption subkey in a release certificate makes rpm-sequoia print a policy warning on every install, so the certificates carry signing subkeys only.

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| Binding signatures kept | All of them, in creation order. | Only the newest for each subkey. | A verifier judges a signature at its own time, and a binding made after the signature would leave it with no binding. The cost is a few hundred bytes a year for each subkey. |
| Compression | None. | gzip or xz with fixed parameters. | Compressor output changes with the library, and the package is a few kilobytes. Gzip is the fallback if an installer in the matrix refuses an uncompressed member. |
| Archive writer | Chosen by the criteria, nfpm or our own. | Fixed now. | The facts that decide it (does a library write the rpm header deterministically, does an old rpm read it) are measured in #15. |
| Where an old rpm stops | A measured floor. | Keep every rpm ever; change the key algorithm to reach old ones. | The algorithm is decided for `gpg` and the cards, and a promise that cannot be tested is not a promise. |
| Combined armoured file | Not shipped. | One file for rpm users. | No consumer, and one installer imported it. |
| Verify | A command of ritueel, run by the builder too. | CI only. | A pipeline that receives a package can check it against the root list it already trusts, and the builder never writes what it has not read back. |

## Follow-ups

- The builder and the verifier, passing a test that the same inputs give the same bytes, and the container-free install test ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- The older-rpm matrix: the releases against the three checks, with versions and date, and the choice of the archive writer and of the payload compression ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- The guide to publishing the output with a pipeline ([issue #25](https://github.com/truvity/ritueel/issues/25)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | Certificates, signatures, subkey bindings and ASCII armour. |
| Debian Policy and `deb(5)` | The `.deb` layout: the `ar` members, the control fields, the version ordering. |
| The RPM file format | The lead, the header tags and the `cpio` payload. |
