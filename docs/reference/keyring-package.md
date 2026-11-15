---
title: Keyring package
description: The keyring file that ritueel makes, and the proposed name, files, build and verify steps of the keyring package that the release pipeline builds from it.
sidebar:
  order: 3
---

*Not built yet. The keyring file and the package are decided in [record 0009](../decisions/0009-release-keys-and-the-keyring.md); the code is [issue #15](https://github.com/truvity/ritueel/issues/15), in M5. The first form of the keyring file, with the primaries only, is written into the trust set from M2; the package and the full file are M5. This page is the specification of the package and of the file it is built from: what is in them, how the package is built and checked, and which installers it is tested on. What it says was measured carries a date.*

The keyring package carries the public certificates of every active primary to apt, rpm and `gpg` users, so that a signature by any subkey a primary bound verifies. ritueel makes the keyring file, which holds those certificates. The release pipeline builds the package from the file (`.deb`, `.rpm` and plain files) and publishes it. ritueel does not build, sign or publish the package: the user's repository signs it with its current subkey ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rules 21 to 23).

:::note[Proposed]
The records fix the content of the keyring file and the name and version of the package. They do not fix the file set of the package, the maintainer field, the file names of the revocation signatures, the build steps, the byte-identical rule, `ritueel verify keyring` or the installer matrix below, which are the proposed specification for the pipeline's builder and its checks, awaiting the maintainer. Below, "the builder" is the pipeline's builder.
:::

## Name and version

- **Name.** `<name>-keyring`, where `<name>` is the name the pipeline gives: lower-case letters, digits and hyphens, 1 to 63 characters, starting with a letter or a digit. The same name for the `.deb` and the `.rpm`, and for every version, so an upgrade replaces the old keyring.
- **Version.** `<year>.<sequence>`: the year of the ceremony, then the [trust sequence](../decisions/0006-bundle-history-and-trust-files.md). A package manager compares the year first, then the sequence as a number, so a newer package always compares newer (`2026.10` after `2026.9`).
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

ritueel writes the keyring file into the trust set, as `keyring.gpg` (binary). The keyring holds the public certificates of the root keys and, from M5, their subkeys ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 12). The pipeline's builder makes from it the two packages, `<name>-keyring_<version>_all.deb` and `<name>-keyring-<version>-1.noarch.rpm`, and the plain files beside them. A `.deb` holds only the first two files, and a `.rpm` the first three. The key files of a package do not replace a user's own keyring: apt reads `Signed-By`, and rpm imports only when told to.

Beside the packages, not in them: the revocation signature of every primary or subkey that was revoked hard and dropped from this version, armoured, one file for each, named by the fingerprint it revokes. The signature stays with the holder, outside the bundle ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 1). The holder gives a primary's stored revocation signature to `revoke`, which checks its digest against the entry of `revocations` for that reason in the `root.json` of that root key ([the bundle](/reference/bundle/#rootjson)) before it uses it; a subkey's revocation is made at the ceremony.

## The first form of the keyring file

From M2 the keyring file of a trust set has the primaries only. It is binary, with no armour. For each entry of the root list that has an `openpgp_fingerprint`, in the order of the list, it holds the packets of one certificate: the primary key packet, the one user ID packet, and the certifications of the primary in creation order. It holds no subkey. The key packet of each certificate gives the fingerprint of its entry, so the file needs no digest of its own: the list pins it. A trust set whose list pins no primary has no keyring file. `check request` reads the primaries of the certifier from this file ([the commands](/reference/cli/#built-so-far)).

ritueel reads the file with one strict reader, `ReadKeyring` in `internal/openpgp`. It takes the bytes of the file and the entries of the list that have a fingerprint, opens no file and writes nothing, and it returns the primaries in the order of the list or an error and no primary. It reads both header formats and every fixed length of RFC 9580, section 4.2, so the certificate files of the hand-off, whose packets have five-octet lengths, are read as they are, and it takes no byte as unique: the same certificate in another header form is the same certificate.

It refuses, in this order, and the first fault gives the error:

1. **The arguments.** A list that is empty, has more than 26 entries, has a label that is not one capital letter or a fingerprint that is not 40 lower-case hexadecimal digits, or names one label or one fingerprint twice. The file is not read.
2. **The size and the form.** A file that is empty, longer than 1 MiB (checked before any packet is read) or armoured; a packet that is not whole, or has a partial or an indeterminate length; a packet that is not, in this order, one public key packet, one user ID packet and one or more signature packets for each certificate, so a subkey, a second user ID, a user attribute and a trust packet are refused; more than 26 certificates, more than 256 certifications for one primary, or more than 6,708 packets.
3. **The primaries.** A certificate that is missing, one too many, one that stands at another place than its entry, one that is not on the list, and a key or a key point that repeats.
4. **The key.** Anything but a version 4 ECDSA key on P-384, with its point on the curve and a creation time that is not zero, whose fingerprint is the fingerprint of the entry at its place.
5. **The user ID.** Anything but the one shape of [the OpenPGP primary](/reference/bundle/#the-openpgp-primary), of at most 1,024 bytes, that names the label of its entry.
6. **A repeated certification.** A certification whose packet body is the same as that of an earlier certification of the same certificate, in whatever header form. No signature is checked for it.
7. **A mix.** A file in which some user IDs carry the mark ` (TEST ONLY)` and some do not.
8. **Each certification.** One that is not the self-signature of that page, row Self-signature: a positive certification of the user ID with exactly the four hashed subpackets and the one unhashed subpacket the row names, each once and in any order, in a packet of at most 512 bytes with at most 32 subpackets in each area, whose two bytes of hash tag are the start of its digest and that verifies with the key over the user ID. A certification dated before the key, or before the one before it, is refused. Every certification must pass, not only one.

A certification that the builder of a primary returns is checked by the same function that the reader uses, so that the builder returns a certificate that the reader accepts, and no other. An error names a position and a label and holds no byte of the file; a code point of a user ID shows as `U+XXXX`.

The reader reads no clock: it does not compare the expiry of a primary with the time of the check, and a primary that has expired is read. It does not read the root list or check its signature. A signature of any other type, a revocation among them, refuses the whole file. The limits above are proposed: no record fixes them. They do not hold all at once, because 26 certificates of 256 certifications each are more than 1 MiB, so one call checks at most about 6,500 signatures. The largest file that the limits allow has 26 certificates and 6,525 certifications in 1,048,519 bytes; it was read in 2.4 s on 2026-11-15 on a machine with a load average of 3.8, and in 4 s to 7 s on a busy machine.

## What the certificates hold

For each active primary, in the order of the root list, one complete public certificate, as OpenPGP packets in this order (RFC 9580, section 10.1):

1. The primary key packet.
2. The user ID packet (the release identity) with every certification ritueel made on it, in creation order. Each extension of the key adds one; a verifier takes the newest as of the time it checks.
3. For every subkey the primary ever bound, in the order of the subkey's creation time and then its fingerprint: the subkey packet, every binding signature ritueel made for it (each with its embedded back-signature), in creation order, then its subkey revocation if it was retired softly.

Left out: an encryption subkey, a third-party certification, a notation, and anything revoked hard, which means a whole certificate of a revoked primary and the whole subkey of one revoked as compromised ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)). The binding signatures are kept even when newer ones exist, so that a signature made before a renewal verifies at its own time. The certificates are read from the bundle: each primary's certificate from the keyring file of the newest trust set, and the bindings from the answers beside the requests, in `requests/<name>/` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). A new keyring is planned to start from the certificates of the newest one: it is to add the new certification of each primary and each new binding, keep what is there, and drop only what is revoked hard ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rules 18 and 19).

The binary form is the packets, concatenated; the armoured form is a single block of the same bytes (RFC 9580, section 6) with the header `-----BEGIN PGP PUBLIC KEY BLOCK-----`, no `Version` or `Comment` header, Base64 in lines of 64 characters and the CRC-24 line, because every reader of armour reads it.

## Build

Record 0009, rule 22, gives the package build to the release pipeline; who writes the archive writer and the verifier is not decided (proposed). Proposed: the build needs neither `dpkg-deb` nor `rpmbuild`, and the same bundle gives the same bytes. In order:

1. **Read** the newest root list of the bundle ([the root list](/reference/root-list/)) and the certificates of the primaries it pins. The list's `sequence` and the year of its `signed_at` give the version. A test root and a real root are never mixed, as for the CA bundle.
2. **Assemble** the certificates as above, drop what is revoked hard, and write the binary and armoured forms and one armoured file for each primary.
3. **Write the `.deb`**: an `ar` archive of three members in this order, `debian-binary` (`2.0`), `control.tar` and `data.tar`, then the `.rpm`: the lead, the header with the tags a noarch package of files needs, and a `cpio` payload (`newc` format).
4. **Fix every variable field**: the build time and every file's modification time is the ceremony time (`SOURCE_DATE_EPOCH`), entries are sorted, owner and group are root (numeric 0), files have mode 0644 and directories 0755, there are no extended attributes, and the `.rpm` has no build host or signature.
5. **Verify** the result ([below](/reference/keyring-package/#verify)) and only then write it out. The builder never writes a package it has not read back.

**Compression.** The tar and cpio members are not compressed. They are a few kilobytes of keys, and a compressor's output changes with its version, which would break the rule that the same bundle gives the same bytes across toolchains. `dpkg-deb` 1.23.7 reads an uncompressed `control.tar` and `data.tar` (checked 2026-11-01). Whether the oldest rpm in the matrix reads an uncompressed payload is part of the matrix below; if one refuses it, the payload is gzip from one pinned implementation, and the goldens move with the pin.

**The writer.** An archive writer is chosen for `ar`, `tar`, `cpio` and the rpm header: a library such as nfpm, or the pipeline's own tool. The criteria are the ones above and in [issue #15](https://github.com/truvity/ritueel/issues/15): no external tool, byte-identical output on a second run, and a reader of its own that the verify step uses, so that nothing is checked by the code that wrote it.

ritueel does not sign the package. The user's repository signs the `.deb` and the `.rpm`, or the `Release` file of its repository, with the current subkey. The pipeline's own steps are a page of the guide, not a feature of ritueel.

## Verify

Record 0009, rule 22, gives the package build to the release pipeline; who writes the verifier is not decided (proposed). `ritueel verify keyring FILE... --root-list FILE [--dir DIR]` is a proposed command that reads packages and plain files and checks them with code that did not build them. The pipeline may run the same checks on its output. The first check that fails gives the reason code.

| # | Check | Code |
|---|---|---|
| 1 | Each file parses as what its name says: an `ar` archive of the three members with `debian-binary` `2.0`, or an rpm with a `noarch` header and a `cpio` payload; a `.gpg` or `.asc` of OpenPGP packets. | `malformed` |
| 2 | The name and version fields are those of the file name, and the version is `<year>.<sequence>` with `sequence` equal to the root list's. | `version-mismatch` |
| 3 | The package holds exactly the files of the table above for its kind, with the owner, modes and times of the build. | `files-mismatch` |
| 4 | The primaries in the certificates are exactly the `openpgp_fingerprint` of the entries on the root list that have one, in its order, and each rpm key file holds one of them, named by its short fingerprint. | `primaries-mismatch` |
| 5 | Every binding signature verifies with its primary over the primary and the subkey, with the embedded back-signature of the subkey for that primary; every certification verifies; every signature has both the issuer fingerprint and the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). | `signature-invalid` |
| 6 | No encryption subkey, no third-party certification, and nothing that is revoked hard. With `--dir`, every subkey the bundle's answers bound and the ceremony records did not revoke hard is present. | `contents-mismatch` |
| 7 | The `.gpg` and the `.asc` hold the same packets, and the digests in `SHA256SUMS` are those of the files. | `malformed` |

Without `--dir`, check 6 can only look at what is inside. It exits 0 when every check passes and 3 with the code when one fails; it writes nothing ([Commands](/reference/cli/#commands-for-the-trust-files-that-come-later)). These codes belong to the checker and are not sent anywhere.

## The installer matrix, and what older rpm means

The package is also tested by installing it, on the installers people have, and by verifying a real signature with what it installed. CI does this for the current `dpkg`, `apt` and `rpm` in a scratch root, with no container ([issue #15](https://github.com/truvity/ritueel/issues/15)): install the package, verify a signature by a subkey the keyring lists with `gpgv` and `sqv`, upgrade to a package that drops a key and see the key gone, and see a signature by the dropped key refused. The older releases cannot be a CI job, because they are old operating systems; they are a dated measurement, repeated before a release that changes the package.

**Older rpm.** The keyring is OpenPGP version 4 ECDSA P-384 with SHA-384 ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)), and ritueel does not change the algorithm to reach an old installer; the one exception is a second primary of RSA-4096, added if a verifier that users need refuses the key ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rule 29). So *support* for an rpm release is a floor that is measured and not a promise: ritueel supports every rpm release that

1. imports each per-primary armoured key file (`rpm --import`, and `gpgkey=` in a repository file), and
2. verifies a package signed by an ECDSA P-384 version 4 subkey the imported certificate binds (`rpmkeys --checksig`), and
3. installs the package, with its payload as written.

The matrix lists the releases to try: the newest rpm (6.0, whose import was measured on 2026-10-29 and 2026-11-01, [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/)), the rpm of a current Fedora, and the rpm of each enterprise distribution release still in vendor support, down to the oldest. The result is a table of releases against these three checks, with the versions and the date, on a research page and in the guide. A release that fails check 2 is *unsupported*, and the guide says so and says which is the first that works; it is not a reason to change a key, apart from that exception. A release that fails check 3 only is a reason for gzip, as above.

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
| Archive writer | Chosen by the criteria, nfpm or the pipeline's own tool. | Fixed now. | The facts that decide it (does a library write the rpm header deterministically, does an old rpm read it) are measured in #15. |
| Where an old rpm stops | A measured floor. | Keep every rpm ever; change the key algorithm to reach old ones. | The algorithm is decided for `gpg` and the cards, and a promise that cannot be tested is not a promise. |
| Combined armoured file | Not shipped. | One file for rpm users. | No consumer, and one installer imported it. |
| Verify | A proposed command of ritueel; the pipeline may run it. | CI only. | A pipeline that receives a package can check it against the root list it already trusts, and the builder never writes what it has not read back. |

## Follow-ups

- The pipeline's builder and the verifier, passing a test that the same inputs give the same bytes, and the container-free install test ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- The older-rpm matrix: the releases against the three checks, with versions and date, and the choice of the archive writer and of the payload compression ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- The guide to publishing the output with a pipeline ([issue #25](https://github.com/truvity/ritueel/issues/25)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | Certificates, signatures, subkey bindings and ASCII armour. |
| Debian Policy and `deb(5)` | The `.deb` layout: the `ar` members, the control fields, the version ordering. |
| The RPM file format | The lead, the header tags and the `cpio` payload. |
