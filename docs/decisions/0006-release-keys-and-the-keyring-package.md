# 0006 — Release keys and the keyring package

**Status:** Accepted
**Date:** 2026-11-01

## Context

A release, or an apt or rpm repository, is trusted because its OpenPGP signature verifies against a key the user already holds in a *keyring*. [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) puts the OpenPGP primaries on the root cards, used once a year, so they cannot sign releases; a system that holds intermediates signs, with a subkey a primary has bound ([the hand-off contract](/reference/hand-off-contract/)). ritueel is not in the signing path: it makes the keys others sign with, and the package others verify with. The proposal was [issue #33](https://github.com/truvity/ritueel/issues/33).

The verdicts of [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/) (2026-10-29 to 2026-11-01) that this record rests on: ECDSA P-384 version 4 keys and SHA-384 work with `gpg`, `gpgv`, `sqv`, apt and rpm, in a PIV slot and in KMS; GnuPG cannot parse a version 6 certificate; `gpgv`, and so apt, ignores revocation signatures; `gpg` 2.2 rejects a signature without the Issuer Key ID subpacket; a signing subkey without a back-signature is refused.

## Decision

### The keys

- **The primaries are the root primaries:** one on each root card (or the one cloud root), certify-only, version 4, ECDSA P-384, SHA-384, valid about three years and extended at each use. Version 6 comes once the verifiers people use accept it.
- **A dedicated release identity.** Every primary carries the project's release address and no person's name, and **no personal key certifies a primary.**
- **Signing subkeys.** The holder of an intermediate makes a signing-only subkey where it lives. Its request back-signs for every active primary, so either root can bind it; one primary, the root of the year, binds it for about 13 months, and each yearly ceremony re-signs the binding. The subkey is replaced only on an event or at most every three years.
- **Packet rule.** Every signature ritueel writes, and every back-signature it accepts, carries both the Issuer Fingerprint subpacket (hashed) and the Issuer Key ID subpacket (unhashed). The test matrix imports every certificate into the oldest `gpg` it supports.

### Revocation

- **A revocation signature is published for the users who read it** (`gpg`, Sequoia): for a subkey, by the root of the year; for a primary, the one made at its birth and stored apart.
- **What is revoked hard is dropped from the next keyring package:** a revoked primary, and a subkey revoked as compromised. Its revocation signature is published beside the package, not in it. For apt users, the new package is the revocation.
- **What is retired softly stays,** with its revocation inside the package: a subkey superseded or retired keeps its old signatures valid. Expired subkeys stay too, because a signature is judged at its own time.
- **The exit status of `gpg --verify` is never a trust decision;** the guides say to use `sqv`, or `gpg --status-fd` and reject `REVKEYSIG`. The table of what each verifier does is on [OpenPGP release keys](/concepts/openpgp-release-keys/#revocation).
- **No shorter expiry as a second line.** The 13-month subkey bindings and the root extension already bound how long an unrevoked key stays usable.

### No signed release before the gate

The first root ceremony on the two cards, with attestation, and the adoption drill come first; only then is a release signed ([#48](https://github.com/truvity/ritueel/issues/48)). For a company on a cloud key service, signed releases also wait until its root account exists. There is no provisional software primary, no bootstrap key and no release signed by a person's key. The first keyring is the final one, so the first transition users see is a real one.

### The keyring package

- **Contents.** For every active primary, its complete public certificate: the primary, the release identity, its self-signatures, every subkey ever bound with its binding, and the soft revocations. Nothing else: no encryption subkey, no third-party certification.
- **Name and version.** `<name>-keyring`, version `<year>.<sequence>`, where the sequence is the trust sequence of [0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/). The file layout, the build and verify steps and the installer matrix are in [the keyring package reference](/reference/keyring-package/).
- **Built by ritueel, deterministically,** without `dpkg-deb` or `rpmbuild`: the same directory gives the same bytes. The builder reads its output back with a checker of its own (`keyring verify`), and a pipeline can run the same checker on a package it received.
- **Not signed or published by ritueel.** The user's repository signs it like every other file, with the current subkey, so a package that adds a primary is signed by an old key, which is how an existing keyring accepts the new one.
- **Users verify with the keyring,** never with one primary's certificate, because a subkey may be bound by either.
- **Where it is published, first version.** The keyring package goes in the user's own repository. The primaries' fingerprints are published on the project's site and in its security file. Keyservers, WKD and DNS `OPENPGPKEY` wait for a consumer.

### Sigstore and old releases

Sigstore and build provenance say how a file was built; OpenPGP says who vouches for it, and is what apt and rpm read. Provenance is a complement and ritueel neither issues nor verifies it. Nothing is done for old releases in the first version: a user keeps the keyring version of the time.

## Consequences

- Users install one package that carries every root; a user who has one primary's certificate cannot verify a release, and the instructions say so.
- No release is signed until the gate is passed; in return, no provisional key is ever trusted.
- A compromised subkey leaves the package, and with it the old releases it signed, as far as the new package is concerned.
- After a theft, apt users are protected only when the new package arrives, so the speed of the ceremony and of the user's pipeline is what counts.
- ritueel writes OpenPGP code of its own (binding, certification, revocation, a keyring writer) and a deterministic package builder, each tested against `gpg`, `gpgv`, `sqv`, apt and rpm, with checks that read status output and not exit codes.
- A user who skips a transition must fetch the new keyring by a published channel.

## Roads not taken

- **Sigstore keyless signing as the main mechanism.** No key to hold, but apt and rpm do not read it and trust moves to a public service.
- **Sign releases with a primary, or with a person's key.** Nothing to bind, but a primary is used once a year, and a person's key puts a person in the chain.
- **A keyring with only the primary of the year.** Smaller, but a lost card breaks verification at once.
- **One package for each primary.** Each root moves alone, but users install two and a missing one looks like a bug.
- **Keep a compromised subkey, with its revocation.** Old signatures stay checkable, but `gpgv` and apt would keep accepting the compromised key.
- **Drop expired subkeys.** Tidier, but good old signatures stop verifying.
- **Build with `dpkg-deb` and `rpmbuild`.** The reference tools, but not on every machine and not reproducible by default.
- **ritueel signs the package.** Self-contained, but it needs an online key ritueel does not hold.
- **Version 6 keys now.** The direction of RFC 9580, but `gpg` cannot parse them, so apt users could not verify.
- **Ed25519 keys.** Shorter, but a PIV slot cannot sign an artifact with them.
- **A provisional software primary for the first releases.** Releases start sooner, but early users trust a copyable key and live through a transition with no purpose.
- **A personal key certifies each primary.** A path for people who trust the person, but release trust then rests on a key usually kept in software.
- **A shorter expiry for primaries and subkeys.** Bounds an unrevoked key further, at the cost of more ceremonies and more keyring updates, for a gain the 13-month bindings already give.
- **Keyservers, WKD and DNS `OPENPGPKEY` in the first version.** More reach, but each is a channel to keep current with no consumer asking yet.
- **A historical keyring package for old releases.** Helps late verifiers, but is one more package to build and keep trusted.

## Follow-ups

- Research the publication channels beyond the first version and the verification tools, for the guide ([#28](https://github.com/truvity/ritueel/issues/28)).
- Measure the oldest rpm releases that import the per-primary key files and verify a signature by the P-384 subkey, which sets the floor of rpm support, and choose the archive writer by the criteria above ([#15](https://github.com/truvity/ritueel/issues/15)).
