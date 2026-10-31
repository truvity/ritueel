---
title: Roadmap
description: The milestones of the first version of ritueel, in the order they are built, what each one delivers, and what comes after the first version.
---

The plan is public and small. Each milestone delivers something a person can use, and each work item is an [issue](https://github.com/truvity/ritueel/issues) with a "done when". Dates are not promised; the order is.

Status on 2026-11-01: design phase. The scope is decided in [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/), the [concepts](/concepts/) are written, and the site is being set up. No milestone is started.

## The first version

The first version supports three key stores: software, YubiKey and AWS KMS. It is built in four milestones.

| Milestone | Delivers | Work items |
|---|---|---|
| **M1: Hand-off and software roots** | A system that holds intermediates can get a certified intermediate or a bound subkey from a software root, using standard formats. Nothing else is needed to start. | The hand-off contract specification. Software-root mode: create a root, sign a CSR, bind a subkey. Ceremony records, first version. The Go module and CLI skeleton. |
| **M2: Hardware and cloud roots** | The same ceremonies with the root on a YubiKey or in AWS KMS, with proof of where intermediate keys live. | The YubiKey back end (PIV and OpenPGP applets, attestation chain to the maker's current root, the policy and serial extensions). The AWS KMS back end, with an MFA-gated role as the "touch". |
| **M3: Transitions and trust products** | A root can be replaced without breaking anyone, and outsiders get standard artifacts. | Vouch, overlap, supersede and revoke, including revocation certificates made in advance and designated revokers. The trust bundle and the signed root list. The keyring builder for `.deb`, `.rpm` and plain files. |
| **M4: Wizards, personal GPG and teaching** | Adopting ritueel is guided, and the teaching material is complete. | The CLI wizard. The localhost web wizard. Personal GPG flows. The guides, one per transition. The drills. |

### Order and reasons

- M1 comes first because the first consumer needs a software root before anything else exists. It is also the cheapest store to teach with.
- The hand-off contract is the first item in M1: it is specified once and tested from both sides, so that the two ends can be built independently.
- M2 follows because the real roots live on hardware or in a cloud service. The attestation checks are the part with the most surprises, so they get a milestone of their own.
- M3 needs M2 to be meaningful: a transition between stores needs two stores.
- M4 comes last because the wizards drive commands that must exist first. The site and the concepts are not waiting for it; they are written alongside.

## After the first version

- Company-wide GPG management, with its own decision record.
- More key stores, each with a record: other clouds, HSMs, TPMs and other cards.

None of these is planned in detail. Each starts as a decision proposal.

## How to follow

The milestones are GitHub milestones on the repository. The issues carry the labels `area:*` and `type:*`. A change to this plan is a pull request to this page.
