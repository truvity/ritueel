# 0002 — Key custody: every key is born in its store; two root cards, or one KMS root and a replica

**Status:** Accepted
**Date:** 2026-11-01

## Context

The goal is a key-service experience without trusting software with a key: every key is born where it lives, can never be extracted, and software only asks it to sign. Roots are used about once a year, by one person. Four facts shape the model. The proposal was [issue #29](https://github.com/truvity/ritueel/issues/29).

- **Hardware fails, is lost and is stolen.** A root on one card is a single point of failure, and a root copied to a second card has existed outside its device, so no card can attest where it was born.
- **A cloud key service can replicate a key; a card cannot.** A multi-Region replica of a cloud key is the same key, kept by the service for availability.
- **Standard tools cannot count.** An X.509 client or an OpenPGP verifier accepts anything one trusted root signed. Two roots give redundancy, not control.
- **One person.** The maintainer is one holder; a design that needs a second holder at every ceremony needs a person who may not exist.

## Decision

### Keys

- **Every key is born in the store that holds it and never leaves.** Nothing is imported. No root exists in software at any moment; the `software` store serves tests, drills, development and a person's own primary ([0003](/decisions/0003-key-stores-and-the-card-layer/)).
- **Redundancy protects against loss, not against compromise.** So the number of root keys follows the store.
- **On cards: two independent root cards, A and B.** Each card generates its own keys and the two are never copies. Each holds an X.509 root key and an OpenPGP primary key, in PIV slots with PIN always and touch always (the slot map is in [0003](/decisions/0003-key-stores-and-the-card-layer/)). One holder operates both, kept in two places. The two roots are redundancy, not two-person control.
- **On a cloud key service: one dedicated root account and one root.** The account holds nothing else. It holds one X.509 root key and one OpenPGP primary, each a multi-Region key with a replica in a second Region. A replica covers a lost Region or a lost primary copy; it is the same key and is never counted as a second root. A company that wants a root that does not depend on one provider adds a card root.
- **A compromise is answered by revocation and a transition,** in either setup, never by a second copy.
- **No hardware security module.** A YubiHSM adds cost and no material gain for keys used once a year from a drawer.

### The yearly ceremony

- **The cards alternate by year:** A one year, B the next. A cloud root has nothing to alternate with and signs every year.
- **It runs on the holder's ordinary workstation,** with no live CD and no air gap, because keys never leave their store. The workstation can still lie about what is signed, so the ceremony checks are in [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/).
- **PINs and admin PINs** live in the holder's password manager, one entry per card.

### Validity, renewal and replacement

- **A root is valid for about three years, and each use extends it.** The card that signs extends its own root: a new OpenPGP self-signature, and an X.509 root certificate re-issued over the same key and subject. Clients pin public keys, so the extension breaks no pin ([0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)). A dead or lost card shows itself by not extending.
- **An intermediate lasts about 13 months and is renewed by re-signing.** The yearly ceremony makes a new certificate over the same key and a new binding that extends the same subkey, so years overlap. No key is made at a yearly ceremony.
- **Key material is replaced only on an event, or at most every three years.** The events are a suspected compromise, a change of store or algorithm, and a change of custody. Three years is the top of the cryptoperiod NIST SP 800-57 Part 1 gives a private signature key, and the forced replacement keeps the replace path exercised.

### Revocation readiness

- **A revocation signature for each OpenPGP primary is made when it is born** and stored apart from its card ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 13.9). There is no designated revoker: section 5.2.3.23 deprecates the Revocation Key subpacket and says applications must not generate it.
- **An X.509 root is revoked by a root list signed by the surviving root,** and new trust products without it ([0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)).
- **A stolen intermediate is a small event:** revoke it and certify a new key with the root of the year.

### The accepted limit

Whoever holds one root card and its PIN, or the role that uses a cloud root, can sign things outsiders trust until that root is revoked and the update reaches them. Standard tools cannot require m-of-n. A stolen card without its PIN locks after three tries.

## Consequences

- A lost card is survivable: the other root exists, and the lost one is revoked with the stored signature.
- Outsiders install two anchors on cards, and watch them; a cloud setup publishes one.
- The single holder is a single point of human failure; succession is out of scope.
- The stored revocation signature can be lost, and nothing else revokes a primary whose card and PIN are gone. A revocation signature also does not reach every verifier: for apt it is the new keyring package that revokes ([the revocation table](/concepts/openpgp-release-keys/#revocation)).
- Each use changes the root certificate and the primary's self-signature, so the CA bundle and the keyring change every year.
- A cloud root account is a single point of compromise, guarded by its key policy and an organisation policy, and answered by revocation and a transition.
- Pages must not call the second card a spare, call the custody two-person control, or call a replica a second root, and they state the accepted limit.

## Roads not taken

- **Two holders, or a remote second holder.** A second pair of eyes, but either card alone signs, so the separation is procedural and every ceremony waits on a person.
- **A live-CD or air-gapped ceremony.** An isolated machine, but the key never leaves the card, so it gains nothing for the friction.
- **One root on one card, with a spare.** One anchor, but the spare is either a copy of the key or nothing a verifier trusts.
- **One key generated off the card and imported into both.** One anchor and two cards, but the key existed in software and no card can attest where it was born.
- **A software key wrapped by both cards, or split 2-of-2.** Any algorithm, but the key is in memory at every signing, and a split stops all signing when either card is lost.
- **An HSM pair with a wrapped export.** On-device audit and capacity, at about EUR 786 a device (checked 2026-10-29), and the key is copied between devices.
- **Each intermediate certified by both roots.** Survives either loss at any time, but some path builders do not try the second certificate and every renewal needs both cards.
- **One OpenPGP subkey bound under both primaries.** Verifies under either, but rotation needs both cards and a revocation must be made twice.
- **A designated revoker, each root for the other.** Revocation without the stored signature, but RFC 9580 deprecates it and it widens what one stolen card can do.
- **A fixed ten-year root, or no expiry.** No yearly change, but a dead card stays silent for years.
- **A second, independent cloud root in another account.** Two keys like the two cards, but a second account to secure, both still on one provider, and the loss it covers is already covered by the replica.
- **A cloud key service as the only kind of store.** One anchor and full audit, but one provider, no attestation, and no use to an installation on small boards.
- **Replace every intermediate key every year.** Short-lived keys, but a key ceremony per holder per year moves a sound key for no gain.

## Follow-ups

- Adopt the roots on the two cards and run the adoption drill, the gate before the first signed release ([#48](https://github.com/truvity/ritueel/issues/48)).
