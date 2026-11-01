# 0005 — Trust products: the root list, the CA bundle, the SSH CA key list, CRLs and the trust sequence

**Status:** Accepted
**Date:** 2026-11-01

## Context

Outsiders never talk to ritueel. They install files: a TLS client a CA bundle and the CRLs of the roots, a package manager a keyring, an SSH host a list of SSH CA keys, and a system that updates its own trust a signed root list. These files carry every root change to the world, so they decide how fast a revocation reaches people and whether an old file can be replayed. A system that holds intermediates reads the root list before it asks for a subkey binding ([the hand-off contract](/reference/hand-off-contract/)), and pins root public keys rather than certificates, so that a re-issued root certificate breaks nothing.

The roots change every year: each use extends the root ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). Earlier work tracked the list in [issue #14](https://github.com/truvity/ritueel/issues/14) and the SSH CA keys in issue #31. An intermediate certificate that must stop being trusted had no channel at all: the profile of an intermediate has no CRL distribution point, and a root revocation covers a whole root only.

## Decision

### One counter: the trust sequence

The **trust sequence** is one integer that grows by one whenever any trust product changes: the root list, the CA bundle, the SSH CA key list, a CRL or the keyring. Every product carries it: the root list and the SSH CA key list as their `sequence` member, the CA bundle in a comment line, a CRL as its CRL number, the keyring package in its version ([0006](/decisions/0006-release-keys-and-the-keyring-package/)). A hand-off answer names the sequence it belongs to, and the requester holds a root list at least that recent before it installs. There is no second counter.

### The signed root list

- **What it holds.** The active roots, each pinned by the SHA-256 of its public key (`SubjectPublicKeyInfo`) and, for OpenPGP, the primary's fingerprint; the `sequence`; when it was signed; when it expires; and the digest of the last ceremony record ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). It pins keys, never certificates.
- **Who signs.** Any one active root (1 of n), with its X.509 root key: the root used at that ceremony. The key whose public key hosts pin is the key that tells them which roots to pin; the slot is in [0003](/decisions/0003-key-stores-and-the-card-layer/).
- **When.** It is re-signed at every yearly ceremony and at every transition, and so at least once a year. It expires 13 months after it is signed, like an intermediate, so a list that stopped being renewed shows itself. `status` warns at 60, 30 and 14 days before it expires.
- **How a host reads it.** A host refuses a list with a lower `sequence` than the one it holds, a list with the same `sequence` whose content differs from the one it holds (only the same list again is accepted, so one sequence names one set of roots), a bad signature, a signer that is not an active root of the list it holds, or one already expired. When the list it holds passes its expiry and no newer one has arrived, it keeps the last good list and raises a warning; it does not drop its roots.
- **Revoking a root** is a new list, signed by a surviving root, without the revoked one, with new trust products beside it.

### The SSH CA key list

The SSH CA public keys hosts trust are published the same way: signed by an active root's X.509 key, carrying the trust sequence, with the same expiry and the same rules for a host. It holds the SSH CA public keys of the systems that hold intermediates, which keep their private keys, and the break-glass SSH CA of each root card (or of the cloud root account), which ritueel holds offline.

- **A system's key enters by the hand-off.** A third request type, `ssh-ca-key`, carries the public key as an OpenSSH line, an SSH signature by that key as the proof of possession, and the same proof file with the same evidence of where the key lives. ritueel checks it, a person confirms it, and the key is listed under the name of an intermediate that the operator declared with that type. There is nothing to certify, so the answer says the key is listed. Nobody edits the list.
- **Each key has a use,** `user` or `host`, asked in the request and fixed by the operator's declaration, so that a host never trusts a user CA as a host CA or the reverse.
- **A break-glass key is made by ritueel** in the store of its root when the root is made, and leaves the list with its root.
- **A key is withdrawn by the next list.** There is no revocation signature for an SSH CA key; hosts stop trusting it when they take a list without it. The list may be empty, so that the last key can be withdrawn.
- **The ECDSA P-384 key only,** as for the rest of the hand-off.

### Revoking an intermediate: a CRL for each root

An intermediate certificate is revoked by a certificate revocation list, the standard way an X.509 client learns it. A CRL is per issuer, so each root signs one of its own.

- **No distribution point in any certificate.** A relying party loads the file, as a server is told which CRL to read. ritueel publishes nothing and a certificate names no host.
- **A root signs its CRL at every ceremony in which it signs,** and when it is made, empty if nothing is revoked, and the CRL of every other active root is copied unchanged beside it. The cards alternate, so a root signs about every second year, and a CRL is valid for 25 months to stay current until its root signs again. Its CRL number is the trust sequence.
- **Revoking an intermediate needs the card of each root that issued one of its unexpired certificates,** usually one, for the CRL of that root gets an entry. A card that is lost cannot sign, and then the root is revoked as a whole, with everything it issued.
- **An entry lasts until the certificate it names expires,** at most 13 months, and the next signing of that CRL drops it.
- **OpenPGP is not covered.** A subkey is revoked by a revocation signature and a keyring package without it ([0006](/decisions/0006-release-keys-and-the-keyring-package/#revocation)).

### The CA bundle

The root certificates of the active roots in one PEM file, with the trust sequence in a comment line. It is deterministic: the same directory gives the same bytes.

### The format

The exact members, the encoding and the signature format of each product are a reference page with test vectors: the root list and the CA bundle in M1 ([root list](/reference/root-list/)), because the first system that holds intermediates reads the root list before anything else exists; the CRLs in M2 ([CRLs](/reference/crl/)), with the command that revokes an intermediate; and the SSH CA key list in M3 ([SSH CA key list](/reference/ssh-ca-key-list/)), with the `ssh-ca-key` request type of [the hand-off contract](/reference/hand-off-contract/#ssh-ca-key). They follow this record and cannot change it.

## Consequences

- One number tells a requester, a host and a package manager whether they are current, and a replayed old file is refused everywhere.
- The yearly ceremony always produces new trust products, because the root extension changes the CA bundle and the keyring, and the list must be re-signed before it expires.
- A host that misses a year keeps working and warns, rather than failing closed on its roots.
- A missed yearly ceremony is visible to every host after 13 months, not only to the holder.
- The root list is a second format other products depend on, so it gets its own versioned specification and vectors, as the hand-off contract has; so do the SSH CA key list and the CRLs.
- A revoked intermediate reaches relying parties only if they load the CRL, and only as fast as the operator's pipeline publishes it; a relying party that never configured the file never learns of it.
- Revoking an intermediate can need a card the holder has to fetch from its place, and a lost card turns the revocation into a root revocation.
- A hand-off request of a third type adds a code path for the SSH signature to the certifier and the requester.

## Roads not taken

- **Full TUF, with separate roles and thresholds.** Mature freeze and rollback protection, but standard verifiers cannot count signatures and one holder cannot staff separate roles.
- **A counter per product.** Each product moves alone, but a requester would need three numbers to tell whether it is current.
- **Accept any list at an equal sequence.** Simpler to check, but two different root sets could then carry one sequence, and a host could not tell which one it holds.
- **Pin root certificates.** Easier to compare, but the yearly re-issue would break every pin.
- **A root list with no expiry.** Nothing to renew, but a list that stopped being signed cannot be told from a current one.
- **Fail closed when the list expires.** Stronger on paper, but a missed ceremony would cut every host off its roots at once.
- **A separate key for the list and the SSH CA keys.** Separates their signer, but costs a slot and a touch for a key with the same audience, lifetime and revocation.
- **OCSP for an intermediate.** Live status, but it needs a responder that signs online, which ritueel never holds, and a certificate that names it.
- **A CRL distribution point in the intermediate's certificate.** Clients could fetch the list by themselves, but the certificate would name a host that outlives it, and TLS libraries do not fetch it by default.
- **One CRL for both roots, signed by the root of the year.** One file, but standard clients take a CRL from the issuer only, and an indirect CRL is poorly supported.
- **Both roots sign their CRL at every ceremony.** A 13-month CRL like the root list, but it needs both cards every year, which the alternation exists to avoid.
- **Revoked intermediates in the root list.** One signed file, but the list pins keys and would grow with every renewal.
- **Version 2 of the hand-off contract for the SSH CA key type, or a contract of its own.** Keeps version 1 as written, but nothing has been released, so no receiver is surprised, and a second version would cost every reader a second code path.
- **The operator edits the SSH CA key list.** No request to write, but a key would be trusted that nothing checked, and the list would have a second author.
- **A key that does both user and host certificates.** One key fewer, but whoever holds it can vouch for hosts as well as users.

## Follow-ups

- Build the root list and the CA bundle to [their reference page](/reference/root-list/), passing its test vectors, in M1 ([#14](https://github.com/truvity/ritueel/issues/14)).
- Build the CRLs and the entries of `intermediate revoke` to [their reference page](/reference/crl/), passing its test vectors, in M2 ([#30](https://github.com/truvity/ritueel/issues/30)).
- Build the SSH CA key list, the `ssh-ca-key` request and the break-glass keys to [their reference page](/reference/ssh-ca-key-list/), passing its test vectors, in M3 ([#55](https://github.com/truvity/ritueel/issues/55)).
