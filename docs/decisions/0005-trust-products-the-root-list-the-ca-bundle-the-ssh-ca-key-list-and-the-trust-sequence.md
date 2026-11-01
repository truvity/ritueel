# 0005 — Trust products: the root list, the CA bundle, the SSH CA key list and the trust sequence

**Status:** Accepted
**Date:** 2026-11-01

## Context

Outsiders never talk to ritueel. They install files: a TLS client a CA bundle, a package manager a keyring, an SSH host a list of SSH CA keys, and a system that updates its own trust a signed root list. These files carry every root change to the world, so they decide how fast a revocation reaches people and whether an old file can be replayed. A system that holds intermediates reads the root list before it asks for a subkey binding ([the hand-off contract](/reference/hand-off-contract/)), and pins root public keys rather than certificates, so that a re-issued root certificate breaks nothing.

The roots change every year: each use extends the root ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). Earlier work tracked the list in [issue #14](https://github.com/truvity/ritueel/issues/14) and the SSH CA keys in issue #31.

## Decision

### One counter: the trust sequence

The **trust sequence** is one integer that grows by one whenever any trust product changes: the root list, the CA bundle, the SSH CA key list or the keyring. Every product carries it: the root list as its `sequence` member, the CA bundle in a comment line, the keyring package in its version ([0006](/decisions/0006-release-keys-and-the-keyring-package/)). A hand-off answer names the sequence it belongs to, and the requester holds a root list at least that recent before it installs. There is no second counter.

### The signed root list

- **What it holds.** The active roots, each pinned by the SHA-256 of its public key (`SubjectPublicKeyInfo`) and, for OpenPGP, the primary's fingerprint; the `sequence`; when it was signed; when it expires; and the digest of the last ceremony record ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). It pins keys, never certificates.
- **Who signs.** Any one active root (1 of n), with its X.509 root key: the root used at that ceremony. The key whose public key hosts pin is the key that tells them which roots to pin; the slot is in [0003](/decisions/0003-key-stores-and-the-card-layer/).
- **When.** It is re-signed at every yearly ceremony and at every transition, and so at least once a year. It expires 13 months after it is signed, like an intermediate, so a list that stopped being renewed shows itself. `status` warns at 60, 30 and 14 days before it expires.
- **How a host reads it.** A host refuses a list with a lower `sequence` than the one it holds, a bad signature, a signer that is not an active root of the list it holds, or one already expired. When the list it holds passes its expiry and no newer one has arrived, it keeps the last good list and raises a warning; it does not drop its roots.
- **Revoking a root** is a new list, signed by a surviving root, without the revoked one, with new trust products beside it.

### The SSH CA key list

The SSH CA public keys hosts trust are published the same way: signed by an active root's X.509 key, carrying the trust sequence, with the same expiry and the same rules for a host. It holds the SSH CA public keys of the systems that hold intermediates, which keep their private keys, and the break-glass SSH CA of each root card (or of the cloud root account), which ritueel holds offline. How a system's SSH CA key enters the list is part of the format below.

### The CA bundle

The root certificates of the active roots in one PEM file, with the trust sequence in a comment line. It is deterministic: the same directory gives the same bytes.

### The format

The exact members, the encoding and the signature format of the root list and the SSH CA key list are a reference page with test vectors, delivered with [issue #14](https://github.com/truvity/ritueel/issues/14). They follow this record and cannot change it.

## Consequences

- One number tells a requester, a host and a package manager whether they are current, and a replayed old file is refused everywhere.
- The yearly ceremony always produces new trust products, because the root extension changes the CA bundle and the keyring, and the list must be re-signed before it expires.
- A host that misses a year keeps working and warns, rather than failing closed on its roots.
- A missed yearly ceremony is visible to every host after 13 months, not only to the holder.
- The root list is a second format other products depend on, so it gets its own versioned specification and vectors, as the hand-off contract has.

## Roads not taken

- **Full TUF, with separate roles and thresholds.** Mature freeze and rollback protection, but standard verifiers cannot count signatures and one holder cannot staff separate roles.
- **A counter per product.** Each product moves alone, but a requester would need three numbers to tell whether it is current.
- **Pin root certificates.** Easier to compare, but the yearly re-issue would break every pin.
- **A root list with no expiry.** Nothing to renew, but a list that stopped being signed cannot be told from a current one.
- **Fail closed when the list expires.** Stronger on paper, but a missed ceremony would cut every host off its roots at once.
- **A separate key for the list and the SSH CA keys.** Separates their signer, but costs a slot and a touch for a key with the same audience, lifetime and revocation.

## Follow-ups

- The reference page and test vectors of the root list and the SSH CA key list, with rollback, expiry, unknown signer and tamper cases ([#14](https://github.com/truvity/ritueel/issues/14)).
