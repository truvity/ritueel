# 0001 — Scope: roots and transitions; systems like sluis hold intermediates

**Status:** Accepted; amended by 0007
**Date:** 2026-11-11

## Context

A chain of trust has a few keys that almost never change, the roots, and many that do. Everything hangs from the roots, so a mistake with one is expensive and slow to repair: every client, host and package manager that trusts it has to learn the change. Roots are used rarely, often once a year, by a person who is present, and they move between key stores. Each move is a *transition*, and doing it right is a skill most teams meet once.

Systems that issue certificates and signatures every day, such as [sluis](https://sluis.id), hold *intermediate* keys: online, automated and short-lived by design. Root custody inside such a system puts the rarest and most valuable keys beside the busiest code, and buries the teaching about transitions in a product about something else. The maintainer decided on 2026-11-01 to make roots and their transitions a product of their own.

## Decision

ritueel owns root keys and root transitions for X.509 CA roots and OpenPGP primary keys, across key stores: it *creates* a root, has an existing root *vouch* for a new one (an X.509 cross-certificate or an OpenPGP certification), *overlaps* old and new, *supersedes* the old, *revokes* a root with revocation material made in advance, and *expires* a root, extending it at each use.

- **SSH CA key lists.** An SSH CA key is an anchor, not a chain. The SSH CA keys of a system that holds intermediates stay with that system; hosts trust a signed, versioned list of SSH CA public keys that ritueel publishes. The break-glass SSH CA is ritueel's own, held offline like a root ([0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)).
- **Ceremonies for intermediates.** ritueel verifies where an intermediate key lives, signs its PKCS#10 request into an intermediate CA certificate, and binds its OpenPGP subkey after checking the back-signatures ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)).
- **Trust products.** ritueel builds what outsiders install: CA bundles, signed root lists, SSH CA key lists and the keyring packages of release keys (`.deb`, `.rpm`, plain files). The staff keyring is not one of them: a system that holds intermediates produces it ([0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/)). The user's own pipeline publishes them.
- **Ceremony records.** Every ceremony leaves a record of what was done, with which keys, on which store, and what outsiders see as a result.
- **Personal OpenPGP.** A person's primary (an existing one may be adopted first, [0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/)), a daily subkey born on a card, and keyring upkeep are in scope. Company-wide OpenPGP has its own record, [0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/); its first item is the delegation a company root makes, by a domain-scoped trust signature at a ritueel ceremony, to an online certifier such as the one sluis plans.
- **How a person uses it.** A ceremony is interactive, with a person present, and is one to three commands. Routine work is automated. ritueel has three faces of the one ceremony engine: the command line, a guided mode that asks line by line, and a read-only local page served by the same binary on localhost ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/), [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)). There is no full-screen terminal interface, and the program is not installed as a service.
- **A teaching product, first.** The purpose is a smooth and safe experience of managing a root, not the tools. The site teaches the logic of roots and intermediates, with one guide per procedure and drills on test keys, and the tools simplify the rituals ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)). The site is part of the product.
- **The whole life of a root.** Opinionated help for where the bundle lives, backup and restore, re-signing and rotating, revocation, and card loss and replacement ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)).
- **Language and stores.** A Go command-line tool with key stores behind one ceremony: `software` (an encrypted file, 1Password or the OS keyring), `piv`, `openpgp-card` and `aws-kms` first; Google Cloud KMS, Azure Key Vault and Nitrokey are planned ([0003](/decisions/0003-key-stores-and-the-card-layer/)).
- **Generic, with no hard dependency.** ritueel and sluis depend on neither each other nor shared code. They exchange standard formats (PKCS#10, X.509, OpenPGP packets, attestation certificates) through the versioned [hand-off contract](/reference/hand-off-contract/), so either side can be replaced by another system that speaks it.
- **The floor is PKCS#10 in, X.509 out.** A system that holds intermediates meets a root through a PKCS#10 request and gets back a certificate in a stated profile, which any certificate authority can issue ([the floor](/reference/hand-off-contract/#the-floor-pkcs10-in-x509-out)). ritueel's contract adds the proof of where the key lives, the result file, the reason codes and the signed root list with its trust sequence. On the floor, the requester's anchors are the CA certificates the operator installed, with no trust sequence and no rollback protection.
- **Out of scope.** Online signing, leaf certificates and secret storage. ritueel never keeps a private key outside the store that made it, except the one stated exception for a person's own key ([0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/)). It keeps no PIN or passphrase that a person types; the random secrets of a card that it makes (the management key, the PUK and the Admin PIN) are kept only sealed in the bundle ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/)).

## Consequences

- A system that holds intermediates gets smaller: it sends a request with proof of where its key lives, and installs what comes back. It never handles a root.
- The hand-off contract must be specified and tested from both sides, with versioning; it is the first backlog item, with test vectors.
- A system that holds intermediates can be certified and tested on the floor by any CA, before ritueel exists. The full contract, with the proof and the trust sequence, needs ritueel's software-root mode, which is therefore built first.
- A requester has two trust modes to test: the floor's installed anchors, and the signed root list.
- Four stores teach every transition shape: from a file, to a card, to a cloud service, and back. Other stores wait for their first real installation.
- The read-only local page, on localhost only, avoids a network service that holds ceremony state, and cannot be shared between machines.
- ritueel carries a security-critical code base by itself: key handling, signing and revocation need review, tests on real test devices, and the rules in `GOVERNANCE.md`.

## Roads not taken

- **Root ceremonies inside the system that holds intermediates.** One product to install, but root custody sits next to the busiest code and the boundary between rare and daily keys disappears.
- **A shared library or a private protocol between the products.** Less to specify, but neither product works without the other and other issuing systems are locked out.
- **No floor: the full contract or nothing.** One trust mode, rollback protection everywhere, but ritueel's own formats would become a requirement on every CA, and a system that holds intermediates could not be tested without ritueel.
- **Two tools, one for X.509 and one for OpenPGP.** Smaller tools, but create, vouch, overlap, supersede and revoke are one model, and the teaching and records would be written twice.
- **A hosted service that holds the roots.** No workstation ceremony, but it makes the roots online and needs someone trusted with every root.
- **More key stores in the first version.** Wider reach, but every store multiplies tests and guides; four already cover every transition shape. The others are planned ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)).
- **Company-wide OpenPGP from the start.** One tool for everything, but it brings people, roles and policy in before the single-person flows work.
- **A web wizard that listens on the network.** Shareable, but a network service that acts on root keys needs authentication and a larger attack surface.

## Follow-ups

None.
