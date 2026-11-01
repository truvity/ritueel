---
title: Roadmap
description: The milestones of the first version of ritueel, in the order they are built, what each one delivers, and what comes after the first version.
---

The plan is public and small. Each milestone delivers something a person can use, and each work item is an [issue](https://github.com/truvity/ritueel/issues) with a "done when". Dates are not promised; the order is.

Status as of 2026-11-01: design phase. There is no code yet, and no milestone is started. The site is live at [ritueel.id](https://ritueel.id), on Worker custom domains with DNSSEC.

What is done, as of 2026-11-01:

- The scope is decided in [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/), and the [concepts](/concepts/) are written.
- The hand-off contract, version 1, is specified.
- [ADR 0003](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) and [ADR 0004](/decisions/0006-release-keys-and-the-keyring-package/) are written, with the root decisions.
- The card spike is done. Its findings: the card is driven as OpenPGP v4.
- The token key of a system that holds intermediates is certified by its intermediate.
- A ceremony makes one request for every active primary. A read-only role covers KMS keys in other accounts. A compromised subkey is dropped from the keyring. The commands are `intermediate add`, `replace` and `revoke`. A company KMS root is one root with a replica. There are four pluggable key stores. The Issuer Key ID subpacket is used. Renewing means re-signing. SSH CA key lists are in scope.

Still open, as of 2026-11-01:

- [#46](https://github.com/truvity/ritueel/issues/46): regenerate the test vectors for the decisions of 2026-11-01.
- [#28](https://github.com/truvity/ritueel/issues/28): research on publication channels.
- [#15](https://github.com/truvity/ritueel/issues/15): the keyring builder, including older `rpm` versions and archives.
- [#24](https://github.com/truvity/ritueel/issues/24): the requirements catalogue.
- The touch-policy test on the card.

ADR 0003 and ADR 0004 stay `Proposed` until these are done. The code starts with the CLI skeleton ([#10](https://github.com/truvity/ritueel/issues/10)) and the software-root mode ([#8](https://github.com/truvity/ritueel/issues/8)).

## The first version

The first version supports four key stores behind one ceremony: software, PIV, the OpenPGP card and AWS KMS. It is built in four milestones.

| Milestone | Delivers | Work items |
|---|---|---|
| **M1: Hand-off and software roots** | A system that holds intermediates can get a certified intermediate or a bound subkey from a software root, using standard formats. Nothing else is needed to start. | The hand-off contract specification. Software-root mode: create a root, sign a CSR, bind a subkey. Ceremony records, first version. The Go module and CLI skeleton. |
| **M2: Hardware and cloud roots** | The same ceremonies with the root on a YubiKey or in AWS KMS, with proof of where intermediate keys live. | The YubiKey back end (both root keys in PIV slots through piv-go, with ritueel building the OpenPGP packets; attestation chain verified against the maker's current root and its full intermediate bundle, with a documented refresh step; the policy and serial extensions). The AWS KMS back end, with an MFA-gated role as the "touch". |
| **M3: Transitions and trust products** | A root can be replaced without breaking anyone, and outsiders get standard artifacts. | Vouch, overlap, supersede and revoke, including revocation signatures made in advance and stored apart from the card, the yearly extension of each root's validity, and the yearly renewal of intermediates by re-signing. The trust bundle and the signed root list. The keyring builder for `.deb`, `.rpm` and plain files. |
| **M4: Wizards, personal GPG and teaching** | Adopting ritueel is guided, and the teaching material is complete. | The CLI wizard. The localhost web wizard. The OpenPGP-card store (a vendored, patched fork of the card library behind a small interface) and the personal GPG flows: a daily subkey born on the card and bound by a software primary. The guides, one per transition. The drills. |

### Before the first signed release

No release is signed until the card roots exist. The order is: the first root ceremony on the two cards, then a drill, then the first signed release ([ADR 0004](/decisions/0006-release-keys-and-the-keyring-package/)). A software root serves tests, drills and development; it never anchors a signed release, and there is no provisional primary.

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
