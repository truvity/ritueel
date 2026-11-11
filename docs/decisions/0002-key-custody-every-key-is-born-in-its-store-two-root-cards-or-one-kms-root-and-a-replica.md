# 0002 — Key custody: every key is born in its store; two root cards, or one KMS root and a replica

**Status:** Accepted
**Date:** 2026-11-11

## Context

The goal is a key-service experience without trusting software with a key: every key is born where it lives, can never be extracted, and software only asks it to sign. Roots are used about once a year, by one person. Four facts shape the model. The proposal was [issue #29](https://github.com/truvity/ritueel/issues/29).

- **Hardware fails, is lost and is stolen.** A root on one card is a single point of failure, and a root copied to a second card has existed outside its device, so no card can attest where it was born.
- **A cloud key service can replicate a key; a card cannot.** A multi-Region replica of a cloud key is the same key, kept by the service for availability.
- **Standard tools cannot count.** An X.509 client or an OpenPGP verifier accepts anything one trusted root signed. Two roots give redundancy, not control.
- **One person.** The maintainer is one holder; a design that needs a second holder at every ceremony needs a person who may not exist.

## Decision

### Keys

- **Every key is born in the store that holds it and never leaves.** Nothing is imported, with one stated exception, for a person's own key: an existing primary adopted as a software key ([0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/)). A cloud key that already exists and that ritueel adopts was still born in the service, so it is not an import ([0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/)). No root exists in software at any moment; the `software` store serves tests, drills, development and a person's own primary ([0003](/decisions/0003-key-stores-and-the-card-layer/)).
- **Redundancy protects against loss, not against compromise.** So the number of root keys follows the store.
- **On cards: two independent root cards, A and B.** Each card generates its own keys and the two are never copies. Each card holds its own roots: for each root an X.509 root key, an OpenPGP primary and a break-glass SSH CA key (fewer for a root with fewer kinds of key), in the rows of PIV slots that [0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/) fixes, with PIN always and touch always (the slot map is in [0003](/decisions/0003-key-stores-and-the-card-layer/)). One pair of cards may hold several roots of one holder. One holder operates both, kept in two places. The two roots are redundancy, not two-person control.
- **On a cloud key service: one dedicated root account and one root.** The account holds nothing else. It holds one X.509 root key and one OpenPGP primary, each a multi-Region key with a replica in a second Region. A replica covers a lost Region or a lost primary copy; it is the same key and is never counted as a second root. A company that wants a root that does not depend on one provider adds a card root. ritueel creates these keys, or adopts keys that already exist in the service ([0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/)).
- **A compromise is answered by revocation and a transition,** in either setup, never by a second copy.
- **No hardware security module.** A YubiHSM adds cost and no material gain for keys used once a year from a drawer.

### The yearly ceremony

- **The cards alternate by year:** A one year, B the next. A cloud root has nothing to alternate with and signs every year at a ceremony. Renewing it without a person, under a declared renewal policy that can extend trust and never create it, is later (M7; [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)). A card root cannot be renewed unattended; `status` reminds its holder.
- **A card root and a real software root are used only in a machine booted from a read-only system made for the purpose (the offline system),** never in the everyday system ([0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-plan-runs)). The plan can be made anywhere, because it holds public information only. A cloud root is signed from the holder's workstation through the ceremony role. A test root may run on the workstation or on a rehearsal card. In every case the machine is not trusted: the key never leaves its store, and every byte the root will sign is fixed, shown and confirmed before the store signs it. The ceremony checks are in [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/).
- **The PINs the holder types** live in the holder's password manager, one entry per card. The secrets that ritueel makes for a card (the management key, the PUK and, on a day-to-day card, the Admin PIN) are sealed in the directory ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)).

### Validity, renewal and replacement

- **A root is valid for about three years, and each use extends it.** The card that signs extends its own root: a new OpenPGP self-signature, and an X.509 root certificate re-issued over the same key and subject. Clients pin public keys, so the extension breaks no pin ([0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)). A dead or lost card shows itself by not extending.
- **An intermediate lasts about 13 months and is renewed by re-signing.** The yearly ceremony makes a new certificate over the same key and a new binding that extends the same subkey, so years overlap. No key is made at a yearly ceremony.
- **Key material is replaced on an event.** The events are an advisory about the device, its firmware or the cloud key service that affects the key; the deprecation of its algorithm; the loss of a card, or its end of life; a suspected compromise; a change of store or custody. For a key on a card or in a cloud KMS, a root included, it is the only rule: such a key cannot be copied, so what ages it is what happens to the device, the service or the algorithm, not the calendar. [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/#how-long-a-persons-primary-lives) gives an advisory that ended keys on cards.
- **At every yearly ceremony the holder reviews the advisories** for the devices, the services and the algorithms in use, and the record says that they did. A missed advisory is the one event a holder can fail to notice, so the review is a step of the ceremony and not a habit.
- **A key that can be copied is also replaced at most every three years.** A software key, such as a test root or a person's primary, can be copied and read without a trace, so a calendar bound limits how long an unnoticed copy is useful. Three years is the top of the cryptoperiod NIST SP 800-57 Part 1 gives a private signature key, and the forced replacement keeps the replace path exercised.

### Revocation readiness

- **A revocation signature for each OpenPGP primary, one for each of two reasons (`compromised` and `superseded`), is made when it is born** and stored apart from its card ([RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580), section 13.9; the reasons and the places are in [0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/)). There is no designated revoker: section 5.2.3.23 deprecates the Revocation Key subpacket and says applications must not generate it.
- **An X.509 root is revoked by a root list without it,** signed by the surviving roots and carrying its removal authorisation made at birth, and new trust products without it ([0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)).
- **A stolen intermediate is a small event:** revoke it and certify a new key with the root of the year.

### The accepted limit

Whoever holds one root card and its PIN, or the role that uses a cloud root, can sign things outsiders trust until that root is revoked and the update reaches them. Standard tools cannot require m-of-n. A stolen card without its PIN locks after three tries. Whoever will hold a cloud root's renewal role (later, M7) can only keep alive what the directory already holds, past the day it should have lapsed, until a ceremony revokes it.

## Consequences

- A lost card is survivable: the other root exists, and the lost one is revoked with the stored signature.
- Outsiders install two anchors on cards, and watch them; a cloud setup publishes one.
- The single holder is a single point of human failure. Succession is the holder's organisational duty ([principle 15](/principles/#the-principles)); ritueel reminds and does not enforce.
- The stored revocation signature can be lost, and nothing else revokes a primary whose card and PIN are gone. A revocation signature also does not reach every verifier: for apt it is the new keyring package that revokes ([the revocation table](/learn/openpgp-release-keys/#revocation)).
- Each use changes the root certificate and the primary's self-signature, so the CA bundle and the keyring change every year.
- A root on a card or in a cloud KMS has no calendar end: it lives until an event, and the yearly review of the advisories is what finds one. The yearly ceremony gains that step and its record.
- A cloud root account is a single point of compromise, guarded by its key policy, and answered by revocation and a transition.
- Pages must not call the second card a spare, call the custody two-person control, or call a replica a second root, and they state the accepted limit.

## Roads not taken

- **Two holders, or a remote second holder.** A second pair of eyes, but either card alone signs, so the separation is procedural and every ceremony waits on a person.
- **An air-gapped machine kept for the purpose.** An isolated machine, but the key never leaves the card, so it gains little for the friction; the read-only offline system of [0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/) is the middle course.
- **The everyday workstation for a card root.** Nothing to boot, but the card is exposed to everything that machine runs for the whole sitting; the read-only offline system costs one boot ([0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/)).
- **One root on one card, with a spare.** One anchor, but the spare is either a copy of the key or nothing a verifier trusts.
- **One key generated off the card and imported into both.** One anchor and two cards, but the key existed in software and no card can attest where it was born.
- **A software key wrapped by both cards, or split 2-of-2.** Any algorithm, but the key is in memory at every signing, and a split stops all signing when either card is lost.
- **An HSM pair with a wrapped export.** On-device audit and capacity, at about EUR 786 a device (checked 2026-10-29), and the key is copied between devices.
- **Each intermediate certified by both roots.** Survives either loss at any time, but some path builders do not try the second certificate and every renewal needs both cards.
- **One OpenPGP subkey bound under both primaries.** Verifies under either, but rotation needs both cards and a revocation must be made twice.
- **A designated revoker, each root for the other.** Revocation without the stored signature, but RFC 9580 deprecates it and it widens what one stolen card can do.
- **A fixed ten-year root, or no expiry.** No yearly change, but a dead card stays silent for years.
- **Replace every root key at most every three years, whatever its store.** One rule, and the replace path exercised by the calendar, but a card or KMS key cannot be copied, so the calendar forces a new anchor on every relying party for no gain, when an advisory or a lost card is what ends such a key.
- **A second, independent cloud root in another account.** Two keys like the two cards, but a second account to secure, both still on one provider, and the loss it covers is already covered by the replica.
- **A cloud key service as the only kind of store.** One anchor and full audit, but one provider, no attestation, and no use to an installation on single-board computers.
- **Replace every intermediate key every year.** Short-lived keys, but a key ceremony per holder per year moves a sound key for no gain.
- **A renewal role for card roots,** with a card left in a scheduler's host and its PIN cached. No yearly touch, but the card's PIN-always and touch-always policy would have to go, and a card on an online host is no longer a root held offline.
- **Unattended renewal for a mixed set, one card and one cloud root.** The cloud root could keep the set alive alone, but the card's own certificate and CRL still need its touch about every second year, and lists signed by the cloud root alone year after year would hide a card that died; `renew` refuses a directory with a card root.

## Follow-ups

- Adopt the project's root and run the adoption drill, the gate before the first signed release; card roots follow the first release ([#48](https://github.com/truvity/ritueel/issues/48)).
- Ask for the advisory review in the plan that `ritueel due` makes and keep it in the record ([#30](https://github.com/truvity/ritueel/issues/30)).
