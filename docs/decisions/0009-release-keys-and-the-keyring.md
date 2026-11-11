# 0009 — Release keys are the root primaries; the keyring is a file that ritueel makes and a pipeline packages

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. The OpenPGP primaries of the release keys are the root primaries, one per root, on a root card or in the cloud root. Each is certify-only, version 4, ECDSA P-384 with SHA-384, valid about three years and extended at each use.
2. Every release primary carries the project's release address and no person's name. No personal key certifies a primary.
3. Version 6 keys come later, once the verifiers people use accept them.
4. A company root's user ID carries a release-root name and a security contact address. A user ID can be added and revoked; only published copies cannot be withdrawn.
5. The holder of an intermediate makes a signing-only subkey where it lives. The subkey request back-signs for every active primary, so either root can bind it.
6. One primary, the root of the year, binds the subkey for about 13 months. Each yearly ceremony re-signs the binding.
7. Every signature ritueel writes, and every back-signature it accepts, carries the Issuer Fingerprint subpacket (hashed) and the Issuer Key ID subpacket (unhashed). The test matrix imports every certificate into the oldest gpg that ritueel supports.
8. A release subkey is replaced only on an event, or at most every three years. Three years is the upper limit for any release subkey. No shorter expiry is used as a second line of defence: the 13-month bindings and the root extension bound how long an unrevoked key stays usable.
9. The release subkey may be temporary: a cloud KMS signing key in the production account, with exactly one signer, the release workflow. The workflow reaches the key through OIDC to the cloud and a small signer program that uses `kms:Sign`. This lasts until the requester system signs natively.
10. The temporary release subkey is bound for 13 months. It is revoked as superseded from the day the new subkey is in use. The 13 months is the binding, not a calendar for the key; the key is replaced on that event (see the no-calendar rule, rule 16 of [0002](0002-where-a-key-lives.md)).
11. No release is signed before the gate. The first signed release (M5) follows the adoption of the project's root and its drill (M4): the root adopted and attested or read, the revocation signatures stored apart, the adoption drill passed.
12. There is no provisional software primary, no bootstrap key and no release signed by a person's key. Card roots are added after the first release (M6), as a transition.
13. The proof of a ritueel release is the checksum file `SHA256SUMS`, signed by a release subkey that the project's root binds, with a keyless cosign signature beside it. The release subkey is named `ritueel-release-<year-month>`.
14. The release subkey signs the checksum file only, never a git tag. There is no personal signature of the maintainer.
15. The release chain is: an unsigned release candidate, then the personal key rebuilt, then the company's OpenPGP key, then the company's key signs ritueel's release.
16. A revocation signature is published for the users who read it (gpg, Sequoia). For a subkey, the root of the year makes it. For a primary, it is the one made at its birth and stored apart.
17. What is revoked hard, a revoked primary or a subkey revoked as compromised, is dropped from the next keyring package. Its revocation signature is published beside the package, not in it. For apt users, the new package is the revocation.
18. What is retired softly, a subkey superseded or retired, stays in the package with its revocation inside, and its old signatures stay valid. Expired subkeys also stay, because a signature is judged at its own time.
19. The exit status of `gpg --verify` is never a trust decision. The guides say to use `sqv`, or `gpg --status-fd` and reject `REVKEYSIG`.
20. The keyring is a file that ritueel makes. For every active primary it holds the complete public certificate: the primary, the release identity, its self-signatures, the subkeys bound with their bindings, and the soft revocations. It holds nothing else: no encryption subkey, no third-party certification. One file carries every root.
21. The release pipeline builds the package from the file (.deb, .rpm, plain files) and publishes it. It names the package `<name>-keyring` with the version `<year>.<sequence>`, where the sequence is the trust sequence.
22. ritueel does not build, sign or publish the package. The user's repository signs the package with the current subkey, so a package that adds a primary is signed by an old key.
23. Users verify with the keyring, never with one primary's certificate, because a subkey may be bound by either.
24. In the first version the package goes in the user's own repository. The fingerprints of the primaries are published on the project's site and in its security file.
25. The root's key is published in more than one place that would have to be broken into separately: a key server, the release page with the keyring file, and a "how to verify" page with the commands.
26. Sigstore and build provenance are a complement. ritueel neither issues nor verifies provenance for a user's releases.
27. Nothing is done for old releases in the first version. A user keeps the keyring version of the time.

## Why

A release is trusted because its signature verifies against a key the user already holds. The root primaries are used once a year, so a signer works with a subkey that a primary has bound, and either root can bind it. ritueel's scope ends at files: it makes the keyring file, and a pipeline packages it. Hard revocation must reach tools that cannot read a revocation signature, such as gpgv and apt, so the new package is the revocation.

## What it costs

- No release is signed until the root is adopted and its drill is passed.
- Each yearly ceremony re-signs the binding of the subkey.
- A package that adds a primary is signed by an old key.
- A late verifier has only the keyring version of the time: no historical package is built.
- A published copy of a user ID cannot be withdrawn.
- The pipeline must follow the name and version rule of the package.
- The temporary key and its signer program must be built, then replaced by native signing.

## Roads not taken

- **Sign releases with a primary, or with a person's key.** It needs nothing to bind, but a primary is used once a year, and a person's key puts a person in the chain.
- **A keyring with only the primary of the year.** It is smaller, but a lost card breaks verification at once.
- **Version 6 keys now.** It follows RFC 9580, but gpg cannot parse them, so apt users could not verify.
- **Ed25519 keys.** They are shorter, but a PIV slot cannot sign an artifact with them.
- **A personal key certifies each primary.** It gives a path for people who trust the person, but release trust then rests on a key usually kept in software.
- **A shorter expiry for primaries and subkeys.** It bounds an unrevoked key further, but costs more ceremonies and keyring updates for a gain the 13-month bindings already give.
- **Keep a compromised subkey, with its revocation.** Old signatures stay checkable, but gpgv and apt would keep accepting the compromised key.
- **Drop expired subkeys.** The package is tidier, but good old signatures stop verifying.
- **A provisional software primary for the first releases.** Releases start sooner, but early users trust a copyable key and live through a transition with no purpose.
- **Sigstore keyless signing as the main mechanism.** There is no key to hold, but apt and rpm do not read it and trust moves to a public service; it is kept beside the OpenPGP proof, not instead.
- **A personal signature of the maintainer on releases.** There is nothing to build, but a person sits in the chain.
- **The release subkey also signs git tags.** It is one key for two jobs, and a tag signature would let the release workflow vouch for source it did not build.
- **A tag signed with the maintainer's own hardware key from the first release.** It was agreed earlier, then dropped.
- **Cosign later, and a signed tag and checksums now.** It was proposed in a review pass and not taken.
- **A signing endpoint in the requester system's first version.** It would remove the temporary key, but none is planned.
- **One keyring package for each primary.** Each root moves alone, but users install two, and a missing one looks like a bug.
- **ritueel signs the package.** It is self-contained, but it needs an online key that ritueel does not hold.
- **A historical keyring package for old releases.** It helps late verifiers, but it is one more package to build and keep trusted.

## Not yet proven or only proposed

- **Not yet proven.** The release workflow, the small signer program, the binding of the temporary release subkey and the keyless signature are not built yet ([#10](https://github.com/truvity/ritueel/issues/10)).

## Replaces

0006, and the lines of 0005 and 0010 that say how a revocation is published and kept.
