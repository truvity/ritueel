# 0004 — Release keys: primaries on the roots, signing subkeys, and the keyring package

**Status:** Proposed
**Date:** 2026-11-01

Proposal: [issue #33](https://github.com/truvity/ritueel/issues/33). The guide and the tests are [issue #25](https://github.com/truvity/ritueel/issues/25), the keyring builder is [issue #15](https://github.com/truvity/ritueel/issues/15), and the research on publication channels is [issue #28](https://github.com/truvity/ritueel/issues/28). The record stays `Proposed` while the open parts at the end are undecided. Revised in place on 2026-11-01, while ritueel is in its design phase.

## Context

A release is a file that people download, and an apt or rpm repository is a set of files that package managers download. Both are trusted because a signature on them verifies against a key that the user already holds. For apt, rpm and `gpg` that signature is OpenPGP, and the key is held in a *keyring*.

[0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/) puts two independent OpenPGP primaries on the two root cards. A primary is used once a year, so it cannot sign releases. The signing is done by a system that holds intermediates, with a subkey that a primary has bound ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)). The binding is the hand-off for an OpenPGP subkey in the [hand-off contract](https://github.com/truvity/ritueel/blob/main/docs/reference/hand-off-contract.md).

This record fixes what ritueel contributes to release signing: the keys, the keyring package that carries them to users, the role of Sigstore, and the order in which things happen: the card roots first, then the first signed release. ritueel is not in the signing path. It makes the keys that others sign with, and the package that others verify with.

Facts from tests, which the choices rest on:

- ECDSA P-384 signatures were accepted by `gpg` and `gpgv` 2.2.27, 2.2.40 and 2.4.7, `sqv` 1.1.0 and 1.3.0, apt 2.4.14, 2.6.1 and 3.0.3, and rpm 6.0.2 with rpm-sequoia 1.10.2 (2026-10-29 and 2026-10-31). Tampered files and unrelated certificates were refused.
- `gpgv` needs a binary keyring. apt takes a binary `.gpg` or an armoured `.asc` as `Signed-By`. rpm imports armoured keys only. apt's `Release.gpg` must be armoured.
- A release certificate with an encryption subkey makes rpm-sequoia print a policy warning on every install.
- `gpg` and `gpgv` refuse a signing subkey without a back-signature; `sqv` reports no binding. A back-signature made by a YubiKey PIV key was accepted (2026-10-31).
- A PIV slot signs a whole Ed25519 message and refuses more than about 3 KiB, so it cannot sign an artifact. P-384 signs a digest.
- A P-384 key in a PIV slot works as the primary of a version 4 certificate: it made the direct-key signature (`0x1F`), the user ID certification (`0x13`), the subkey binding (`0x18`) and revocations (`0x20`, `0x28`). `gpg` 2.4.8, `gpgv`, `sqv` 1.5.0, `sq` 1.4.1 and apt 3.2.0 accepted the certificate and a subkey signature, and rpm 6.0.2 imported it (signed `.rpm` files were not tested). An AWS KMS P-384 key worked the same way, as primary and as subkey (measured 2026-11-01).
- `gpgv` ignores revocation signatures, and `gpg --verify` exits 0 for a revoked key (it prints `REVKEYSIG`). `sqv` rejects: a revocation with a hard reason (no reason given, compromised) rejects every signature of the key, and one with a soft reason (superseded, retired) rejects only signatures made after it (measured 2026-11-01).
- `gpg` 2.4.8 refuses to parse a version 6 certificate ("unknown version 6"); `gpgv` refuses it too. `sqv` 1.5.0 accepts it (measured 2026-11-01).

## Decision

### The keys

- **Two primaries, one on each root card,** generated on the card, certify-only, never copies of each other, both authoritative ([0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)). Version 4 keys (see Algorithm below), ECDSA on P-384, signatures with SHA-384. A primary is valid for about three years, and a new self-signature at each use of its card extends it ([0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/), [0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/)). Each primary lives in a PIV slot, and ritueel builds the OpenPGP packets itself.
- **A dedicated release identity.** Both primaries carry the same user ID, a release address of the project, and no person's name. The identity is a role; whoever holds the cards is not in it. **No personal key certifies a release primary:** nobody's own key vouches for it, so release trust does not depend on a key that is usually in software.
- **Signing subkeys.** The holder of an intermediate generates a signing-only subkey where it lives (a YubiKey slot or a KMS key). A primary binds it with a type `0x18` signature that carries the subkey's own `0x19` back-signature and expires after about 13 months. The yearly ceremony renews it by re-signing: a new binding that extends the same subkey's expiry, so years overlap and the subkey is not made again. The subkey is replaced only on an event, or at most every 3 years ([0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/#renewal-and-replacement)). The primary of the year binds; a subkey is revoked by the primary of the year.
- **A request back-signs for every active primary.** The subkey's request carries one back-signature for each active primary, after the requester has read the signed root list, so either root card can make the binding, this year or next, or after a card is lost. The binding itself is made by one primary only (decided 2026-11-01; the hand-off contract has the packets).
- **The keyring keeps expired subkeys.** A signature made while a subkey was valid keeps verifying after it expires, because `gpgv` and `sqv` judge a signature at its own time. Dropping expired subkeys would break the verification of old releases. A subkey that was revoked with a soft reason (superseded, retired) stays too, with its revocation, for the tools that read it: it was safe, and its old signatures should stay valid.
- **A subkey revoked as compromised is dropped from the next keyring package** (decided 2026-11-01). `gpgv` and apt ignore revocation signatures, so keeping the subkey in the package, with its revocation, would leave apt users accepting it. The revocation signature is still published, beside the package and not in it, for the users of `gpg` and Sequoia, who read it. Signatures made with that subkey stop verifying against the new package, which is intended: after a compromise they cannot be told from forged ones.

### No signed release until the card roots exist

**The order is fixed: the first root ceremony and a drill come first, then the first signed release.** The maintainer decided to go first with the adoption and the drill of the root keys, and only then sign a release.

- There is no provisional software primary, no special bootstrap key, and no release signed by a primary or by a person's key. A software root never anchors a release keyring.
- When the cards exist, the first signed release is made the ordinary way: the signing subkey lives in a cloud key service (AWS KMS) or a card slot, is bound by the primary of the year through the same hand-off as any other, and the first keyring already carries the two final primaries.
- The first keyring is the final one. The first transition that users see is a real one, between real roots.
- Until then, no release is signed.

The roadmap and the guides carry the same order.

### The keyring package

- **Contents.** For every active primary, the complete public certificate: the primary, the release identity, its self-certification, every subkey ever bound with its binding, and any revocation of a primary or of a subkey with a soft reason. Nothing else: no encryption subkey, no third-party certification. A superseded primary is removed in the package that supersedes it, and a subkey revoked as compromised is removed in the next package.
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

A revocation signature is advisory for some verifiers, so revocation has two parts that reach different users (measured 2026-11-01):

| Verifier | Reads a revocation signature? |
|---|---|
| `sqv`, `sq` | Yes. A hard reason (no reason, compromised) rejects every signature of the key. A soft reason (superseded, retired) rejects only signatures made after the revocation. |
| `gpg` | Partly. It marks the key revoked and prints `REVKEYSIG`, but `gpg --verify` still exits 0. |
| `gpgv`, and so apt | No. It ignores the revocation and reports a good signature. |
| rpm | Not tested. |

- **For `gpg` and Sequoia users,** a subkey is revoked by the primary of the year, and a primary with the pre-made revocation signature, made when it was born and stored apart from the card (RFC 9580, section 13.9; [0002](/decisions/0002-every-key-is-born-in-its-store-two-roots-one-holder-yearly-alternation/)). The signature is inside the keyring and reaches users in the next package. RFC 9580 (section 5.2.3.23) deprecates the designated-revoker subpacket and says applications must not generate it, so it is not used.
- **For apt users, the effective revocation is a new keyring package without the key.** A package that drops a revoked primary or a subkey revoked as compromised is the only thing `gpgv` notices. The revocation signature still goes out, for the users who read it.
- **`gpg --verify` exit status is never a trust decision.** A script that checks a signature uses `sqv`, or `gpg --status-fd` and rejects `REVKEYSIG`. The guides say so.
- The time from a theft to a verifier's refusal is the time to run the ceremony and to publish the package. Each guide says so.

### Packet rules

- **Every version 4 signature carries both the Issuer Fingerprint and the Issuer Key ID subpacket.** go-crypto v1.5.2 writes a version 4 signature with only the Issuer Fingerprint subpacket, and `gpg` 2.2.27 rejects a certificate made of such signatures on import. ritueel always adds the Issuer Key ID subpacket (type 16) as well, to every signature it writes: self-certifications, bindings, back-signatures and revocations. The Key ID goes in the unhashed area and the fingerprint in the hashed area (decided 2026-11-01; the hand-off contract has the same rule for a requester's back-signature).
- The test matrix imports every certificate that ritueel writes into the oldest `gpg` it supports, not only the newest.

### Sigstore

- **Sigstore is a complement, not a second root.** A signature says *who vouches* for a file. Build provenance (a signed statement of which workflow built it, from which commit) says *how it was built*. OpenPGP carries the first, and is the only one apt and rpm read. Sigstore, GitHub attestations or SLSA provenance carry the second.
- ritueel neither issues nor verifies Sigstore material, and its roots do not sign it. The verification instructions of a project list OpenPGP first and name provenance as an optional second check. A Sigstore bundle from the signing service is a later feature of that service.

### Algorithm

**Decided by the maintainer on 2026-11-01: OpenPGP keys are version 4 now, and version 6 comes later, once the verifiers people use accept it.** The reason is measured: GnuPG implements no version 6 in any release, and `gpg` 2.4.8, the current one, refuses to parse a version 6 certificate, while Sequoia (`sqv`, `sq`) accepts it. A release key that `gpg`, `gpgv` and apt cannot read is not a release key. The profile that adds version 6 is a later record.

ECDSA on P-384, version 4 keys, SHA-384, for primaries and subkeys. It works on every store, with every verifier tested, and on a PIV slot. **SHA-384 is used on every backend:** a KMS P-384 key signs only 48-byte SHA-384 digests, and one hash everywhere makes a card, KMS and software key behave alike. Ed25519 is not used: a PIV slot cannot sign an artifact with Ed25519. A post-quantum primary is [issue #32](https://github.com/truvity/ritueel/issues/32).

### Old releases

**Nothing is done for old releases in the first version.** A superseded primary is dropped from the keyring, so a signature made under it does not verify with the new keyring. To verify an old signature, a user needs the keyring version of that time. A separate historical package is not part of the first version.

### Open

- **Publication channels** ([issue #28](https://github.com/truvity/ritueel/issues/28)): which channels publish the keyring (keyservers, WKD, DNS OPENPGPKEY, the project site, the repository's security file). The personal-key question is decided above.
- **Older rpm** and a combined armoured file. Importing one file with two certificates was tested on rpm 6.0 only (2026-10-29); the package ships one file for each primary to avoid the question. The matrix of older releases is for issue #15.
- **Who writes the archives** ([issue #15](https://github.com/truvity/ritueel/issues/15)).
- **Short key expiry as a second line for apt users.** Because `gpgv` ignores revocation, the only brake on a stolen key is a new keyring. Options: (a) rely on the new keyring package alone, which is simplest and already planned; (b) also give primaries and subkeys a shorter expiry and re-sign them more often, which bounds how long a key that nobody revoked stays usable, at the cost of more ceremonies and of a keyring that every user must update more often; the effect on `gpgv` was not tested. Not decided.

## Consequences

- Users install one package, and it carries both roots. A user who has only one primary's certificate cannot verify a release, and the instructions say so.
- No release is signed until the card roots exist and a drill has run. In return, the first keyring is the final one, and no provisional key is ever trusted.
- A user who keeps an old keyring version can verify old releases with it; one who upgrades cannot verify a release signed under a primary that a later package dropped.
- The keyring grows by one subkey per signer for each time a subkey is replaced, which is on an event or at most every three years. Expired subkeys stay for as long as a primary is active.
- A subkey revoked as compromised leaves the package, and so do the old releases it signed, as far as the new package is concerned. A user who needs to check one keeps the keyring of the time and a verifier that reads revocations.
- Version 4 signatures are larger by one subpacket each, and every certificate imports into old `gpg`.
- Because a package that adds a primary is signed by an old key, a user who skips the transition (a very old keyring) cannot verify it and must fetch the new keyring by one of the published channels. The channels in #28 matter for them.
- ritueel needs OpenPGP code of its own: binding, certification, revocation, and a keyring writer that produces certificates other tools accept. The test matrix is `gpg`, `gpgv`, `sqv`, apt and rpm, and it belongs to issue #25. The matrix includes a revoked key, and its checks read the verifier's status output and not its exit code.
- A revocation signature does not protect an apt user. After a theft, the protection is the new keyring package, so the speed of the ceremony and of the package is what counts.
- Version 4 keys carry the SHA-1 fingerprint, and the creation time is part of it; ritueel stores the creation time it chose ([0003](/decisions/0003-ceremonies-plan-confirm-reserve-sign-record-and-the-ritueel-commands/)).
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

### Keep a subkey revoked as compromised in the keyring, with its revocation

- Pros: `gpg` and `sqv` honour the revocation; old signatures stay checkable.
- Cons: `gpgv` and apt ignore revocations, so they keep accepting the compromised subkey, and a forged signature looks like a good one.
- Why not: the maintainer decided on 2026-11-01 that protecting apt users comes first. The revocation signature is still published, for the users who read it.

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

### Version 6 keys now

- Pros: the direction of the standard (RFC 9580); a SHA-256 fingerprint; Sequoia accepts them (`sqv` 1.5.0), and a card or KMS key can be the primary of one (the packets are built the same way).
- Cons: GnuPG implements no version 6 in any release, and `gpg` 2.4.8 refuses to parse the certificate; `gpgv`, and so apt, read the keyring through the same code, so a release signed under a version 6 key would verify only with Sequoia-based tools.
- Why not: the maintainer decided on 2026-11-01 to use version 4 now and to add version 6 once the verifiers people use accept it. A later record adds the profile.

### Ed25519 keys

- Pros: shorter keys and signatures.
- Cons: a PIV slot cannot sign an artifact with Ed25519; the verifier matrix shrinks.
- Why not: P-384 works everywhere that matters today.

### A provisional software primary that binds the first KMS subkey

- Pros: the first release is signed before the cards exist; the first transition is exercised in earnest.
- Cons: a key that can be copied is carried by the first keyring and trusted by early users; every early user lives through a transition that has no purpose but to retire it; the guides teach a path the final design does not need.
- Why not: the maintainer chose to adopt and drill the root keys first and sign a release only afterwards. The transition is rehearsed in a drill on test keys instead.

### A personal key certifies each release primary

- Pros: users who already trust the person have a path to the release key.
- Cons: it ties release trust to a key that is usually in software, against the dedicated identity; it puts a person in the chain.
- Why not: the release identity is a role. The channels in issue #28 carry the primaries' fingerprints.

### A historical keyring package for old releases

- Pros: helps people who verify archives long after a supersede.
- Cons: one more package to build, publish and keep trusted; it carries retired primaries and their revocations.
- Why not: the first version does without; a user keeps the keyring version of the time. A later record may add it.
