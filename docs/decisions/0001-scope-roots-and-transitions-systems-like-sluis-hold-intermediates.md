# 0001 — Scope: roots and transitions; systems like sluis hold intermediates

**Status:** Accepted
**Date:** 2026-11-01

## Context

A chain of trust has a few keys that almost never change and many that do. The few are the roots: an X.509 CA root that clients install, an OpenPGP primary key that a keyring package carries. Everything else hangs from them, so a mistake with a root is expensive and slow to repair: every client, host and package manager that trusts it has to learn the change.

Roots are used rarely, often once a year, and by a person who is present: a card is touched, or the use of a cloud key is confirmed. They also move. A root starts in software, moves to a YubiKey, later to a cloud key management service, and the old one has to keep working until everyone has learned the new one. Each such move is a *transition*, and doing it right is a skill most teams meet once.

Systems that issue certificates and signatures every day, such as [sluis](https://sluis.id), hold *intermediate* keys. They are online, automated, and short-lived by design. Mixing root custody into such a system puts the rarest and most valuable keys beside the busiest code, and buries the teaching about transitions inside a product about something else.

The maintainer decided on 2026-11-01 to make roots and their transitions a separate product, ritueel, with its own repository and site, and to record the scope here. This record replaces no earlier record; ritueel has none.

## Decision

**What ritueel owns.** ritueel owns root keys and root transitions for X.509 CA roots and OpenPGP primary keys, across key stores:

- *create* a root;
- *vouch* for a new root from an existing one, by an X.509 cross-certificate or an OpenPGP certification;
- *overlap* the old and the new, so that clients that know either keep working;
- *supersede* the old root by the new one;
- *revoke* a root, with revocation signatures made in advance and stored apart from the card when the root is born;
- *expire* a root, extend it at each use, and warn before it lapses.

**Ceremonies for intermediates.** ritueel runs the ceremonies that give an intermediate its authority: it verifies where the key lives (a YubiKey attestation chain, or the description of a cloud KMS key), signs a PKCS#10 certificate request into an intermediate CA certificate, and binds an OpenPGP subkey to a primary after checking the subkey's back-signature.

**Trust artifacts.** ritueel produces what outsiders install: CA bundles, keyrings, and signed root lists. It provides the automation and the CLI that build keyring `.deb` and `.rpm` packages. The user's own pipeline publishes them.

**Ceremony records.** ritueel keeps a record of every ceremony: what was done, with which keys, on which store, who confirmed it, and what the outsider-visible result is.

**Personal OpenPGP.** Personal GPG is in scope: a primary key, subkeys, cards, and keyring upkeep. Company-wide GPG management comes later and needs its own record.

**How a person uses it.** Ceremonies are interactive, with a person present (a YubiKey touch, or confirming the use of a KMS root), yet automated down to one to three CLI commands. Routine work, such as keyring maintenance, is fully automated. ritueel offers guided wizards for adoption: a CLI wizard, and a web UI that listens on localhost only.

**A teaching product.** ritueel teaches as well as does: concepts, one guide per transition (software to YubiKey, YubiKey to AWS KMS, and the other directions), and drills on test keys. The site is part of the product.

**Language and stores.** The CLI is written in Go. The first version supports three key stores: software, YubiKey and AWS KMS.

**Generic, with no hard dependency.** ritueel does not depend on sluis, and sluis does not depend on ritueel. They exchange standard formats: a PKCS#10 certificate request, an X.509 certificate, OpenPGP packets (a public subkey and its back-signature), and attestation certificates. The hand-off is specified once, as a versioned contract, and either side can be replaced by another system that speaks it.

**Out of scope.** Online signing and issuing leaf certificates (sluis or another system does that), and storing secrets. ritueel never keeps a private key outside the key store that made it, and keeps no PIN or passphrase.

## Consequences

- A system that holds intermediates gets smaller. It sends a request with proof of where its key lives, and installs what comes back. It never handles a root.
- ritueel needs a hand-off contract that is specified and tested from both sides, with versioning. The first backlog item is that specification.
- A deployment that has no ritueel needs one of the two ends to be something else that speaks the same formats. The contract is the interface, not the product.
- The first version of any system that needs a certified intermediate depends on ritueel's software-root mode, which is therefore built first.
- Three key stores are enough to teach every transition shape: from a file, to a card, to a cloud service, and back. Other stores wait for a later record.
- The localhost-only web wizard avoids a network service that holds ceremony state. It also means a wizard cannot be shared between machines.
- ritueel carries the cost of a security-critical code base by itself: key handling, signing and revocation need review, tests on real test devices, and the security rules in `GOVERNANCE.md`.
- Company-wide GPG management is not designed now. The personal flows are built so that it can extend them.

## Roads not taken

### Keep root ceremonies inside the system that holds intermediates

- Pros: one product to install and learn; code shared between the ceremony and the issuing side; no hand-off contract to maintain.
- Cons: root custody sits next to the busiest and most exposed code; the security boundary between rare and daily keys disappears; a user who only needs roots must adopt a whole issuing system; the teaching about transitions is buried in a product about something else.
- Why not: the boundary between roots and intermediates is the cleanest one in the model, and a product boundary makes it enforceable and teachable.

### Couple the two products tightly, with a shared library or a private protocol

- Pros: less to specify; faster first version; richer integration, such as one-click ceremonies.
- Cons: neither product can be used without the other; other issuing systems are locked out; a change in one breaks the other.
- Why not: standard formats cost a specification but keep both products replaceable, and they are what the outside world already uses.

### Two tools, one for X.509 and one for OpenPGP

- Pros: each tool is smaller; each can follow its ecosystem closely.
- Cons: create, vouch, overlap, supersede and revoke are the same shape in both worlds, so the teaching and the ceremony records would be written twice; a root that is both a CA and a release-signing primary would be handled in two places.
- Why not: the model is shared, and the differences (cross-certificate or certification, revocation certificate or CRL) belong inside one model.

### A hosted service that holds the roots

- Pros: no workstation ceremony; easy sharing between people.
- Cons: someone has to be trusted with every root; it makes the roots online, which is what roots avoid; it needs the secrets storage that is out of scope.
- Why not: roots are used rarely and with a person present, so an online service gives up the property that makes a root safe.

### Support more key stores in the first version

- Pros: wider reach on day one, for example other clouds, HSMs, TPMs and other cards.
- Cons: every store multiplies the tests and the guides; the first version would teach none of them well.
- Why not: software, YubiKey and AWS KMS cover the full set of transition shapes. Later stores need a record each.

### Manage company-wide GPG from the start

- Pros: one tool for personal and company keys.
- Cons: it brings people, roles and policy into the design before the single-person flows work; the right model for it depends on what the personal flows teach.
- Why not: personal GPG first, company-wide management later, with its own record.

### A web UI that listens on the network

- Pros: shareable between people and machines; no local install for the viewer.
- Cons: a network service that holds ceremony state and acts on root keys; authentication, TLS and a larger attack surface.
- Why not: the wizard drives a ceremony on one machine with one person present, and localhost-only keeps it that way.
