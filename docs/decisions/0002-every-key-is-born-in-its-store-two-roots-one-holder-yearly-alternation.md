# 0002 — Every key is born in its store; two roots, one holder, yearly alternation

**Status:** Accepted
**Date:** 2026-11-01

Decided by the maintainer. Proposal: [issue #29](https://github.com/truvity/ritueel/issues/29). The maintainer confirmed the model on 2026-10-31, before the product split of [0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/). The text is the root half of two planned records of [sluis](https://sluis.id), "Two-root PKI hierarchy" and "Signed releases, two roots", which moved here.

## Context

The goal is a KMS-like experience without a cloud key service: every key is born on a card, can never be extracted, and software only asks the card to sign. The roots are used about once a year, from a drawer, by one person.

Three things shape the model.

- **Hardware fails, is lost and is stolen.** A root on one card is a single point of failure. A root copied to a second card has existed outside its device, and no card can then attest where it was born.
- **Standard tools cannot count.** An X.509 client or an OpenPGP verifier accepts anything that one trusted root signed. No standard client can ask for "two roots agreed", so two roots give redundancy and not control.
- **A person, not a team.** The maintainer is one person. A design that needs a second holder in every ceremony needs a second person who may not exist.

## Decision

### Keys

- **Every key is born in the store that holds it and never leaves.** A root is generated on a YubiKey (YubiKey 5 series, current firmware, P-384) or in a cloud key service, and attested where the hardware can attest. Nothing is imported. No key exists in software at any moment.
- **Two independent roots, A and B.** Each root card generates its own root, on the card, and the two are never copies of each other. Each card holds two keys: an X.509 root (PIV, PIN always, touch always) and an OpenPGP primary key.
- **One holder operates both cards**, stored in two separate locations. The two roots are **redundancy, not two-person control**.
- **No hardware security module.** A YubiHSM adds cost and no material gain for keys used once a year from a drawer.

### What outsiders install

- **TLS:** a CA bundle that holds both root certificates.
- **apt, rpm and gpg:** a keyring package that holds both OpenPGP primary keys.
- **Systems that update their own trust:** a signed root list, in the style of TUF. Any single root may change the root set (1 of n). The list carries a version that only increases and an expiry. A client pins the public keys of the roots, not their certificates, and refuses an older or expired list.

### The yearly ceremony

- **Cards alternate by year:** A one year, B the next. An intermediate (a board's X.509 certificate and OpenPGP subkey) lasts about 13 months and is renewed at the yearly ceremony, so years overlap. There is no always-online intermediate.
- **The ceremony runs on the holder's ordinary workstation.** There is no live CD and no air gap, because keys never leave the card. The CLI checks the Yubico attestation of every key it certifies and shows its fingerprint before each touch.
- **Adding or replacing a board** between ceremonies is a short ceremony with the card for the year.
- **PINs and admin PINs** live in the holder's password manager, one entry per card.

### Lifecycle

The commands are `init`, `yearly`, `board add` and `board replace`, `root add`, `root retire` and `root revoke` (lost, stolen or compromised). Their detail is in [issue #27](https://github.com/truvity/ritueel/issues/27), the planned record 0003.

- **Revocation readiness.** A revocation certificate is made when each root is born and stored apart from its card. Each root is named the designated revoker of the other (OpenPGP).
- **Root rotation uses standard tools.** An X.509 cross-certificate is issued from a surviving root. For OpenPGP, a surviving primary certifies the new primary, and a new keyring package is signed by an old key, as the Debian archive keyring does.
- **A stolen board is a small event.** Revoke its certificate and subkey with the card for the year, and certify a new board key. The window runs from the theft to the revocation.

### The accepted limit

Whoever holds one root card **and its PIN** can sign things that outsiders trust, until that root is revoked and the update reaches them. Standard tools cannot require m-of-n. This is the same limit as any PGP key or CA. A stolen card without its PIN locks after three tries.

### Not decided here

Root expiry (none, or about three years, extended at each use), the exact lifetimes, and the tool that talks to the cards are open. They are tracked in [issue #27](https://github.com/truvity/ritueel/issues/27) and [issue #26](https://github.com/truvity/ritueel/issues/26).

## Consequences

- A lost or broken card is survivable: the other root exists, and the lost one is revoked with the pre-made certificate.
- Outsiders have two anchors to install and watch, and ritueel has two sets of ceremony records.
- With alternating years, the loss of a card breaks no chain only during the 13-month overlap. After that, recovery is re-certification from the surviving root, without replacing any board key.
- The single holder is a single point of human failure. The model protects against a lost card, not against the holder's incapacity. Succession is out of scope for this record.
- Whether `gpg`, `gpgv`, `sqv`, apt and rpm honour a pre-made revocation certificate and a designated revoker is assumed, and a half-day test on test cards must show it before a guide claims it.
- Documentation must not describe the second card as a spare, must not call root custody two-person control, and must state the accepted limit.

## Roads not taken

### Two holders, or a remote second holder

- Pros: separation of duties; a second pair of eyes at every ceremony.
- Cons: either card alone signs, so the separation is procedural and not cryptographic; every ceremony waits on a remote person, or needs a three-phase file protocol.
- Why not: the two roots exist for redundancy. A procedural review by one holder, with the record of each ceremony, is enough for a root used once a year.

### A live-CD or air-gapped ceremony

- Pros: an isolated machine.
- Cons: keys never leave the card, so the machine cannot leak them; friction for six to ten sessions a year, and tools that differ from the ones the holder uses every day.
- Why not: no benefit when the key stays on the card.

### One root on one card, with a spare

- Pros: one anchor to publish. The conventional design.
- Cons: the spare holds either a copy of the key, which is the imported key below, or nothing a verifier trusts. Losing the one root card stops all signing.
- Why not: it does not survive hardware failure, and the cheap way to make it survive is to copy the key.

### One key generated off the card and imported into both cards

- Pros: one root and one anchor, and two cards that sign.
- Cons: the key existed in software, and no card can attest where it was born. A ceremony shows what people did, not where a key was made.
- Why not: it gives up attestation, the property that makes a root on a card worth having.

### A software key wrapped by both cards, or split 2-of-2

- Pros: any algorithm, including ones the cards lack; with a 2-of-2 split, both cards are needed to sign.
- Cons: the key is in memory at every signing and has no attestation. With a split, losing either card stops all signing, which is the opposite of surviving a failure.
- Why not: the key is no longer held by hardware. A software root kept off the network stays a candidate for a future post-quantum root, because no listed hardware offers one.

### An HSM pair with a wrapped export between the devices

- Pros: a hash-chained audit log on the device, more capacity, a device that can stay attached to a server, and attestation of keys made on the device.
- Cons: about EUR 786 for each YubiHSM 2 against an ordinary YubiKey (Yubico product page, checked 2026-10-29), a second device family to operate, and a key that is copied between devices as a wrapped export, with no proof of where the copy was born.
- Why not: it reopens the decision to use ordinary YubiKeys and gives up the property that nothing is copied.

### Each intermediate certified by both roots

- Pros: losing either card breaks no chain, at any time.
- Cons: clients see two certificates for one intermediate, and some path builders do not try the second; every renewal needs both cards.
- Why not: alternating years with an overlap gives the same survival with one certificate, and a surviving root re-certifies after a loss.

### One OpenPGP subkey bound under both primaries

- Pros: one signature verifies under either primary's certificate (tested 2026-10-29 and 2026-10-31).
- Cons: creating or rotating the subkey needs both cards; revocation must be made under both because `gpg` and `gpgv` ignore a revocation made under one; no threshold; a compromise is shared.
- Why not: the subkey is bound by the primary of the year, and users hold a keyring package that carries both primaries.

### AWS KMS as the only root

- Pros: one anchor. The key is never in plaintext outside KMS, and every use is recorded.
- Cons: a dependency on one provider, no hardware attestation of its own, and not available to an installation on single-board computers.
- Why not: a KMS root is one of the key stores ritueel supports ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)); it is not the only one.
