---
title: Roadmap
description: The milestones of the first version of ritueel in the order they are built, the gate before the first signed release, and what comes after.
---

The plan is public and small. Each milestone delivers something a person can use, and each work item is an [issue](https://github.com/truvity/ritueel/issues) with a "done when". Dates are not promised; the order is.

**Status as of 2026-11-01:** design phase. The [decision records](/decisions/) are accepted, and every format that M1, M2 and M3 build is specified on the [reference pages](/reference/). The hand-off contract (with the SSH CA key request), the root list, the SSH CA key list and the CRLs have test vectors; the keyring package is a specification that its builder will check. No code exists yet. What is open lives in the issues and their milestones, not on this page.

## The first version

Four key stores behind one ceremony: software, PIV, the OpenPGP card and AWS KMS.

| Milestone | Delivers | Work items |
|---|---|---|
| **M1: Hand-off and software roots** | A system that holds intermediates gets a certified intermediate or a bound subkey from a software root, through the hand-off contract, and the signed root list and CA bundle it checks them with. | The Go module and CLI skeleton. The ceremony engine and its records: plan, confirm, reserve, sign, verify, record. The software store and software-root mode, passing the contract's vectors. The signed root list and the CA bundle, passing their vectors. |
| **M2: Hardware and cloud roots** | The same ceremonies with the roots on two cards or in an AWS KMS root account, with proof of where every key lives, and a way to revoke an intermediate certificate. | The `piv` store (both root keys in PIV slots, the slot map, the attestation bundle). The `aws-kms` store (the root account, the read-only role for other accounts). The ceremony commands, with the [CRL](/reference/crl/) each root signs and `intermediate revoke`. |
| **M3: Transitions and trust products** | A root can be replaced without breaking anyone, and outsiders get standard artifacts. Ends with **the real roots adopted and the adoption drill passed.** | Root add, retire and revoke, with the yearly root extension and renewal by re-signing. The [SSH CA key list](/reference/ssh-ca-key-list/), with the `ssh-ca-key` hand-off request and the break-glass SSH CA. The [keyring package](/reference/keyring-package/) builder. The release-key guide and its verifier tests. The lost-card drill. Root adoption on the two cards, and the adoption drill. |
| **M4: Wizards, personal OpenPGP and teaching** | Adopting ritueel is guided, and the teaching material is complete. | The CLI wizard and the localhost web wizard, both faces of the one ceremony engine ([ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)). The software backends 1Password ([issue #59](https://github.com/truvity/ritueel/issues/59)) and the OS keyring ([issue #60](https://github.com/truvity/ritueel/issues/60)). The `openpgp-card` store and personal OpenPGP: a daily subkey born on the card, bound by a software primary. One guide per ritual and transition. The remaining drills, with the backup and restore drill. |

### The gate before the first signed release

No release is signed until the real roots exist and a drill has shown they can be recovered: the adoption ceremony on the two root cards, with each root attested and its revocation signature stored apart, and the adoption drill ([issue #48](https://github.com/truvity/ritueel/issues/48), the end of M3). A company on a cloud key service also waits for its root account. The release-key tests of M3 come first, so the first signed release can follow the gate at once. A software root serves tests, drills and development, and never anchors a signed release ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)).

### Order and reasons

- M1 comes first because the first consumer needs a software root before anything else exists, and the contract is tested from both sides before either end is built.
- M2 follows because the real roots live on cards or in a cloud service, and the attestation checks hold the most surprises.
- M3 needs M2: a transition needs two stores, and the trust products beyond the root list and the CA bundle need real roots. Those two are in M1, because the first consumer reads the root list to fill a request and to check an answer. M3 ends with the gate, so nothing later depends on a root that was never drilled. Adoption waits for the end of M3 because it publishes the root list and the keyring, and its drill walks through `root revoke` and `root add`, all of which are built there.
- M4 comes last because the wizards drive commands that must exist first. The site and the concepts are written alongside, not after.

## After the first version

- Company-wide OpenPGP, with its own decision record. Its first item is the delegation a company root makes, by a domain-scoped trust signature at a ritueel ceremony, to an online certifier.
- More key stores, each arriving with its first real installation: Google Cloud KMS, Azure Key Vault and Nitrokey are planned, then other clouds, HSMs, TPMs and other cards. The site compares them and says which to buy for testing.
- A post-quantum root ([issue #32](https://github.com/truvity/ritueel/issues/32)).

None of these is planned in detail. Each starts as a decision proposal.

## How to follow

The milestones are GitHub milestones on the repository. The issues carry the labels `area:*` and `type:*`. A change to this plan is a pull request to this page.
