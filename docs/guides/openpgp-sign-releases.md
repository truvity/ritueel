---
title: Sign software and releases
description: Sign release files with a detached OpenPGP signature from a key held in a store, publish the public key and its fingerprint, and verify downloads the safe way.
sidebar:
  order: 12
---

*These steps use `gpg` and `sqv`, which exist today. The release key, its keyring package and the guide's drill are planned in ritueel ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/)); no release is signed until the roots are adopted and drilled. Try everything on a test key first.*

A release signature lets a user check that the file they downloaded is the one you published. It only means something if the user knows which key to trust and the key's custody is sound. This page covers signing, publishing and verifying.

## What you start with

- A release signing subkey held in a store (a card, or a cloud key service), bound by a master key that stays offline ([the OpenPGP chain](/learn/chain-openpgp/)).
- The release files, built reproducibly if you can.
- A place to publish: your site, your repository's releases, a package repository.

## Sign

1. **Make a checksum file.** `sha256sum *.tar.gz > SHA256SUMS`.
2. **Sign each file, or the checksum file, with a detached signature.** `gpg --armor --detach-sign --local-user <fingerprint>! SHA256SUMS` writes `SHA256SUMS.asc`. Signing the checksum file covers every file in it with one touch.
3. **Check your own signature** with `gpg --verify SHA256SUMS.asc SHA256SUMS` and with `sqv`, as a user would.

A detached signature sits beside the file and does not change it, so the same file can be fetched with or without verification.

## Publish the public key and its fingerprint

The signature is worthless if users get the key from the same place an attacker could change. Publish in more than one place:

- the **fingerprint**, in full (40 hexadecimal characters), on your project's own site over HTTPS, in the release notes, and in the repository;
- the **public key**, as a file next to the release, and in a **keyring package** that a package manager installs ([keyring package](/reference/keyring-package/));
- for mail-based identities, a Web Key Directory entry.

Also publish the revocation, if there ever is one, in the same places. Say in the instructions that users should check the fingerprint, and show how.

## Verify a download

Give your users these steps:

1. **Get the key from the keyring package, or import it,** and check that its fingerprint is the one on the project's site: `gpg --fingerprint <fingerprint>`.
2. **Check the signature.** The safest is `sqv --keyring release-keyring.pgp SHA256SUMS.asc SHA256SUMS`. With `gpg`, run `gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS` and accept the result only if it contains `GOODSIG` and `VALIDSIG` with your fingerprint and does not contain `REVKEYSIG` or `EXPKEYSIG`.
3. **Check the file against the checksum.** `sha256sum -c SHA256SUMS --ignore-missing`.

**Never treat the exit status of `gpg --verify` as the decision.** Measured on 2026-11-01, `gpg` reports a good signature for a revoked key, and `gpgv` and apt ignore revocations. See [OpenPGP release keys](/learn/openpgp-release-keys/#revocation).

## Where the key lives

A release key that sits in a file on a build server can be copied. Prefer a subkey held in a card or a cloud key service, so that signing is a call that CI makes with its own identity and audit trail, and the private key cannot be taken. The key is replaced, not copied, when custody changes ([Rotate](/learn/rotate/)). Compare the options in [Where a key lives](/learn/key-stores/).

## How you know it worked

- A clean machine that has only the keyring package and the site's fingerprint verifies the release.
- A modified file fails the checksum, and a modified signature fails the check.
- After a revocation drill, a machine with the new keyring refuses the revoked key.
