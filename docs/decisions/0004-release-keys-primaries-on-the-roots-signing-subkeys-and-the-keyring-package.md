# 0004 — Release keys: primaries on the roots, signing subkeys, and the keyring package

**Status:** Proposed
**Date:** 2026-11-01

Proposal: [issue #33](https://github.com/truvity/ritueel/issues/33). The guide and the tests are [issue #25](https://github.com/truvity/ritueel/issues/25), the keyring builder is [issue #15](https://github.com/truvity/ritueel/issues/15), and the research on publication channels is [issue #28](https://github.com/truvity/ritueel/issues/28). The record stays `Proposed` while the open parts at the end are undecided.

## Context

A release is a file that people download, and an apt or rpm repository is a set of files that package managers download. Both are trusted because a signature on them verifies against a key that the user already holds. For apt, rpm and `gpg` that signature is OpenPGP, and the key is held in a *keyring*.

[0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) puts two independent OpenPGP primaries on the two root cards. A primary is used once a year, so it cannot sign releases. The signing is done by a system that holds intermediates, with a subkey that a primary has bound ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)). The binding is the hand-off for an OpenPGP subkey in the [hand-off contract](https://github.com/truvity/ritueel/blob/main/docs/reference/hand-off-contract.md).

This record fixes what ritueel contributes to release signing: the keys, the keyring package that carries them to users, the role of Sigstore, and what signs before any hardware system exists. ritueel is not in the signing path. It makes the keys that others sign with, and the package that others verify with.

Facts from tests, which the choices rest on:

- ECDSA P-384 signatures were accepted by `gpg` and `gpgv` 2.2.27, 2.2.40 and 2.4.7, `sqv` 1.1.0 and 1.3.0, apt 2.4.14, 2.6.1 and 3.0.3, and rpm 6.0.2 with rpm-sequoia 1.10.2 (2026-10-29 and 2026-10-31). Tampered files and unrelated certificates were refused.
- `gpgv` needs a binary keyring. apt takes a binary `.gpg` or an armoured `.asc` as `Signed-By`. rpm imports armoured keys only. apt's `Release.gpg` must be armoured.
- A release certificate with an encryption subkey makes rpm-sequoia print a policy warning on every install.
- `gpg` and `gpgv` refuse a signing subkey without a back-signature; `sqv` reports no binding. A back-signature made by a YubiKey PIV key was accepted (2026-10-31).
- A PIV slot signs a whole Ed25519 message and refuses more than about 3 KiB, so it cannot sign an artifact. P-384 signs a digest.

## Decision

### The keys

- **Two primaries, one on each root card,** generated on the card, certify-only, never copies of each other, both authoritative ([0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)). Version 4 keys, ECDSA on P-384, signatures with SHA-384. The expiry of a primary follows the root expiry decision of ADR 0003 ([issue #27](https://github.com/truvity/ritueel/issues/27)).
- **A dedicated release identity.** Both primaries carry the same user ID, a release address of the project, and no person's name. The identity is a role; whoever holds the cards is not in it.
- **Signing subkeys.** The holder of an intermediate generates a signing-only subkey where it lives (a YubiKey slot or a KMS key). A primary binds it with a type `0x18` signature that carries the subkey's own `0x19` back-signature, expires after about 13 months, and is renewed at the yearly ceremony, so years overlap. The primary of the year binds; a subkey is revoked by the primary of the year.
- **The keyring keeps expired subkeys.** A signature made while a subkey was valid keeps verifying after it expires, because `gpgv` and `sqv` judge a signature at its own time. Dropping expired subkeys would break the verification of old releases. A revoked subkey stays too, with its revocation.

### What signs before any hardware system exists

The first user is a project whose releases are signed through its signing service with a subkey held in a cloud key service (AWS KMS). That answers the question: **a KMS-held subkey signs, bound by a primary through the same hand-off as any other.** There is no special bootstrap key, and no release is signed by a primary or by a person's key.

The primary that binds it has to exist when the first release is signed. Until the root cards exist, it is a primary of a **software root** (ADR 0003, `ritueel init --store software`), which the first keyring carries and marks as provisional in its fingerprint list. When the card roots exist, the transition is the ordinary one: the new primaries are created, certified by the provisional one, carried together with it in a new keyring package signed by an old key, and the provisional primary is retired in a later package. This makes the first transition a real one, and it is what the guides teach. The alternative is to publish no release until the cards exist; it is in the open parts.

### The keyring package

- **Contents.** For every active primary, the complete public certificate: the primary, the release identity, its self-certification, every subkey ever bound with its binding, and any revocation. Nothing else: no encryption subkey, no third-party certification. A superseded primary is removed in the package that supersedes it.
- **Name.** `<name>-keyring`, where `<name>` is the project's name given to `ritueel keyring build --name`. The same name for the `.deb` and the `.rpm`.
- **Version.** `<year>.<sequence>`, where `<sequence>` is the *trust sequence*: one integer that grows by one whenever the root list, the CA bundle or the keyring changes, and `<year>` is the year of the ceremony. A package manager compares the year first and then the sequence, so a newer package always compares newer. The same sequence is in the root list and in a comment line of the CA bundle.
- **Files.**

  | File | In | Content |
  |---|---|---|
  | `/usr/share/keyrings/<name>-keyring.gpg` | `.deb`, `.rpm`, plain | All certificates, binary. For `gpgv`, `sqv` and apt `Signed-By`. |
  | `/usr/share/keyrings/<name>-keyring.asc` | `.deb`, `.rpm`, plain | The same, armoured. |
  | `/etc/pki/rpm-gpg/RPM-GPG-KEY-<name>-<short fingerprint>` | `.rpm` | One armoured file for each primary, for `rpm --import` and a repository file's `gpgkey=`. |
  | `<name>-keyring.fingerprints` | plain | One line for each primary: fingerprint, role, creation and expiry. |
  | `SHA256SUMS` | plain | Digests of the files above. |

- **Package fields.** Architecture-independent, no dependencies, the same package name for every version so an upgrade replaces the old keyring.
- **Built by ritueel, without the distribution tools.** `dpkg-deb` and `rpmbuild` are not needed on the holder's machine or in the pipeline. The build is deterministic: the build time is the ceremony time (`SOURCE_DATE_EPOCH`), entries are sorted, owners and modes are fixed. The same directory gives the same bytes. Which library writes the archives is for issue #15; `nfpm` is a candidate (v2.48.0, pushed 2026-11-01).
- **Not signed by ritueel, and not published by it.** The package is signed as every other file in the user's repository is, by the signing service with the current subkey: an apt repository's `Release` file, an rpm package's header. That makes a package that adds a new primary **signed by an old key**, which is how an existing user's keyring accepts the new one. ritueel holds no online key.
- **How users verify.** With the keyring, never with one primary's certificate: `gpgv --keyring /usr/share/keyrings/<name>-keyring.gpg file.asc file`, `sqv`, apt with `Signed-By`, and rpm after `--import`. The instructions say "use the keyring package", because a verifier that holds one primary cannot check a subkey bound by the other.

### Revocation

- A subkey is revoked by the primary of the year. The revocation is a signature inside the keyring and reaches users in the next package.
- A primary is revoked with the escrowed revocation signature made when it was born (ADR 0003, [issue #27](https://github.com/truvity/ritueel/issues/27)). RFC 9580 deprecates the designated-revoker subpacket, so it is not relied on.
- The time from a theft to a verifier's refusal is the time to run the ceremony and to publish the package. Each guide says so.

### Sigstore

- **Sigstore is a complement, not a second root.** A signature says *who vouches* for a file. Build provenance (a signed statement of which workflow built it, from which commit) says *how it was built*. OpenPGP carries the first, and is the only one apt and rpm read. Sigstore, GitHub attestations or SLSA provenance carry the second.
- ritueel neither issues nor verifies Sigstore material, and its roots do not sign it. The verification instructions of a project list OpenPGP first and name provenance as an optional second check. A Sigstore bundle from the signing service is a later feature of that service.

### Algorithm

ECDSA on P-384, version 4 keys, SHA-384, for primaries and subkeys. It works on every store, with every verifier tested, and on a PIV slot. Ed25519 and version 6 keys are not used: a PIV slot cannot sign an artifact with Ed25519, and GnuPG 2.4 does not handle version 6. A post-quantum primary is [issue #32](https://github.com/truvity/ritueel/issues/32).

### Open

- **The first primary** (above). **Recommendation:** start with a provisional software primary and make the first transition real. A release made before the cards exist is marked provisional in the fingerprint list and in the guide.
- **Publication channels and the personal key** ([issue #28](https://github.com/truvity/ritueel/issues/28)): which channels publish the keyring (keyservers, WKD, DNS OPENPGPKEY, the project site, the repository's security file), and whether the maintainer's personal key certifies each primary. **Recommendation on the personal key: no.** It ties release trust to a key that is usually in software, against the dedicated identity. It can be revisited when #28 reports.
- **Old releases after a supersede.** The keyring drops a superseded primary, so a release signed under it does not verify with the new keyring. Options: nothing (a user keeps the old package); a separate `<name>-keyring-historical` package with retired primaries and their revocations. The first is cheaper; the second helps people who verify archives. **Recommendation:** the first for the first version.
- **Older rpm** and a combined armoured file. Importing one file with two certificates was tested on rpm 6.0 only (2026-10-29); the package ships one file for each primary to avoid the question. The matrix of older releases is for issue #15.
- **Who writes the archives** (issue #15).

## Consequences

- Users install one package, and it carries both roots. A user who has only one primary's certificate cannot verify a release, and the instructions say so.
- A release can be signed from day one, by a KMS subkey, without waiting for hardware, at the price of one provisional primary and one real transition.
- The keyring grows by one subkey per signer per year. Expired subkeys stay for as long as a primary is active.
- Because a package that adds a primary is signed by an old key, a user who skips the transition (a very old keyring) cannot verify it and must fetch the new keyring by one of the published channels. The channels in #28 matter for them.
- ritueel needs OpenPGP code of its own: binding, certification, revocation, and a keyring writer that produces certificates other tools accept. The test matrix is `gpg`, `gpgv`, `sqv`, apt and rpm, and it belongs to issue #25.
- A deterministic package builder is code to write and keep, and its tests need no distribution tool.
- The trust sequence couples three products to one counter. A change to any of them is a new package version, even when the keyring did not change.

## Roads not taken

### Sigstore keyless signing as the main mechanism

- Pros: no key to hold or rotate; identity comes from the build's login.
- Cons: apt and rpm do not read it; trust rests on a public service and on the login provider, outside the roots; a verifier needs network access and tools most users lack.
- Why not: the formats package managers read are the formats users have. Provenance is kept as a complement.

### Sign releases with a primary, or with a person's key

- Pros: nothing to bind; one key to trust.
- Cons: a primary is used once a year, from a drawer, so it cannot sign every release; a person's key puts a person in the chain.
- Why not: subkeys exist so the key that signs often is not the key that is rare.

### The keyring package carries only the primary of the year

- Pros: smaller; one anchor at a time.
- Cons: a user's keyring changes every year, and a lost card breaks verification at once; it removes the redundancy that the second root gives.
- Why not: users hold both roots, as [0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) says.

### One package for each primary

- Pros: each root can be added or removed alone.
- Cons: a user must install two; a repository's `Signed-By` lists two files; a missing one looks like a bug.
- Why not: a transition changes one package, the same name, higher version, which is what upgrades do.

### Drop expired subkeys from the keyring

- Pros: smaller; looks tidier.
- Cons: old signatures stop verifying although they were good when made.
- Why not: a release does not stop being genuine when its subkey expires.

### Build packages with `dpkg-deb` and `rpmbuild`

- Pros: the reference tools; no archive code to write.
- Cons: not available on every holder machine or runner; builds are not reproducible by default; two toolchains to pin.
- Why not: the content is small and fixed, and one deterministic builder is easier to test.

### ritueel signs the package it builds

- Pros: a self-contained signed artifact.
- Cons: it needs an online key, which ritueel does not hold ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)); the package would be signed by the primary, which is rarely available.
- Why not: the user's pipeline signs with the current subkey, as it does for every other file.

### Ed25519 or version 6 keys

- Pros: shorter keys and signatures; the direction of the standard.
- Cons: a PIV slot cannot sign an artifact with Ed25519; GnuPG 2.4 does not read version 6; the verifier matrix shrinks.
- Why not: P-384 works everywhere that matters today. A later record can add a profile.

### Wait for hardware before any release

- Pros: no provisional primary; the first keyring is the final one.
- Cons: no signed release until the card back end exists (milestone M2); the first transition is not exercised in earnest.
- Why not (as the default): it is the alternative in the open parts, and the maintainer decides.
