---
title: Roadmap
description: The milestones of ritueel from M0 to M7 in the order they are built, the gate before the first signed release, and what comes after.
---

The plan is public and small. Each milestone delivers something a person can use, and each work item is an [issue](https://github.com/truvity/ritueel/issues) with a "done when". Dates are not promised; the order is.

**Status as of 2026-11-11:** design phase. M0, the written design, is done: ten [decision records](https://github.com/truvity/ritueel/tree/main/docs/decisions) are accepted and [the design in brief](/design/) states them, and every format that M2 to M6 build is specified on the [reference pages](/reference/). The hand-off contract (with the SSH CA key request), the root list, the SSH CA key list and the CRLs have test vectors; the keyring package is a specification that its builder will check. The program has no code yet. The local page exists as code and as a demo (`ui/`, `proto/`). What is open lives in the issues and their milestones, not on this page. The GitHub milestones carry the older names until a maintainer script renames them.

**Design: 10 decision records, 16 reference pages. Code: 0 lines.** Counted on 2026-11-11, in Go only; the page in `ui/` is TypeScript and is counted apart. The home page counts them at each build, and the [project status](/status/) page adds the issues closed in each milestone.

## The first version

Three stores behind one ceremony: a software key in an encrypted file, a pair of root cards, and one cloud key service with a replica. The cards are built after the first signed release, so the first release does not wait for them.

| Milestone | Delivers | Work items |
|---|---|---|
| **Learn (now)** | The teaching is the first deliverable. Done when every Learn page has been read end to end by someone new to PKI, their questions are answered on the page, and the [comparison page](/learn/compared/) exists. | The [Learn pages](/learn/), the comparison page, the beginner's path on [Where a key lives](/learn/key-stores/#which-path-is-yours). The comparison page exists; the reading by someone new to PKI does not yet. |
| **M0: Records** | The design round is written down once: the decision records, the reference pages, the glossary and the teaching pages say the same thing. | The ten decision records of `docs/decisions/` written from the checked list of decisions, [the design in brief](/design/), the [glossary](/glossary/) and this plan; the reference pages and the teaching pages follow in the next pull request. |
| **M1: Proofs on a rehearsal card** | The decided-but-unproven points are tried on a rehearsal card before anything is built on them. | The passkey proof ([record 0002](decisions/0002-where-a-key-lives.md)): a passkey secret with PIN and touch over USB from a static binary, and the offline system reaching the card's passkey side. The card proofs ([record 0003](decisions/0003-root-cards.md)): deleting one slot, placeholder certificates seen by other tools, the read-only check, a factory-value report that spends no PIN try, and touch always across several signatures. Two new tests on hardware ([record 0005](decisions/0005-a-ceremony-and-where-it-runs.md)): that AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it; and the touch test for the workstation rule, a touch for every signature. |
| **M2: Release candidate** | A tagged, unsigned build that a system holding intermediates can pin and test against: a software root and a cloud root, the history, and a read-only page. | The Go module and CLI skeleton. The ceremony engine, the [history and records](/reference/ceremony-record/): plan, confirm, reserve, sign, verify, record. The software store with [key files](/reference/software-store/), passing the contract's vectors. The hand-off contract checks (`handoff check`), `status` and the records commands. The signed root list and the CA bundle, passing their vectors. [Revocation signatures](/reference/revocation-material/) for every OpenPGP primary key, made at birth. The packet writer and the signer. The `aws-kms` store that adopts a key ([the cloud root](/reference/kms-root/): its key policy and checks, the read-only role for other accounts). The [card inventory](/reference/cards/) files. The program side of the local page: the ConnectRPC server over the API of `proto/`, the embedded build of `ui/`, the profile of the [wizard reference](/reference/wizard/), and the one process behind the commands (started on demand by the first command, on one fixed loopback port). |
| **M3: A person's key, stage one** | A person adopts an existing OpenPGP primary, with its history, and gets day-to-day subkeys. | The `openpgp-card` store and [personal OpenPGP](/reference/personal-openpgp/), stage one of [record 0008](decisions/0008-a-persons-own-key.md): the adopted primary with an expiry, a signing and an authentication subkey born on each day-to-day card, and an encryption subkey made in software with a wrapped backup. |
| **M4: A company's cloud root** | A company's cloud root is adopted and drilled, and a root can be replaced without breaking anyone. Ends with **the adoption drill passed.** | Root adoption on the cloud root ([issue #48](https://github.com/truvity/ritueel/issues/48)) and the adoption drill. Root add, retire and revoke ([the rules](/reference/transitions/): states, vouch, overlap, checks), which the drill walks through, with `intermediate replace` and `intermediate revoke`, the [CRL](/reference/crl/) each root signs, the [SSH CA key list](/reference/ssh-ca-key-list/) with the `ssh-ca-key` hand-off request, and the [restore check](/reference/drill/). The binding of the temporary release subkey that [record 0009](decisions/0009-release-keys-and-the-keyring.md) describes. |
| **M5: First signed release** | The first release whose proof is a signature: a checksum file signed by a release subkey that the project's root binds, with a keyless signature beside it. | The release workflow and the signer ([issue #10](https://github.com/truvity/ritueel/issues/10)), the release-key tests ([issue #25](https://github.com/truvity/ritueel/issues/25)), the keyring file that ritueel makes (the release pipeline packages it, see [the keyring package](/reference/keyring-package/)), and publication of the root's key in more than one place. |
| **M6: A company's card roots** | A root can live on a pair of cards, several bundles to a pair, and a person's primary can be born on the cards. | The `piv` store (the rows of [record 0003](decisions/0003-root-cards.md), the [card inventory and checks](/reference/cards/), the attestation bundle), card adoption with the sealed secrets of [record 0003](decisions/0003-root-cards.md), the break-glass SSH CA on cards, and the lost-card drill. A card root joins the set as a transition built in M4. Then stage two of record 0008: two card-born primaries in the personal bundle's row. |
| **M7: Afterwards** | Everything that is designed and waits for a consumer. | The guided mode, the remaining [drills](/reference/drill/), the software backends 1Password ([issue #59](https://github.com/truvity/ritueel/issues/59)) and the OS keyring ([issue #60](https://github.com/truvity/ritueel/issues/60)), one guide per ritual and transition, `renew` for a cloud root. |

### The gate before the first signed release

The first signed release (M5) follows the adoption of the project's root and its drill (M4): the root adopted, attested or read, its revocation signatures stored apart, and the adoption drill passed ([issue #48](https://github.com/truvity/ritueel/issues/48), the end of M4). Card roots are added after it (M6), as a transition that [the keyring package](decisions/0009-release-keys-and-the-keyring.md) already carries. The release-key tests come first, so the first signed release can follow the gate at once. A software root serves tests, drills and development, and never anchors a signed release ([record 0009](decisions/0009-release-keys-and-the-keyring.md)).

### Order and reasons

- M1 comes first because the default way to open a key file rests on a passkey that has not been tried, and the card rows rest on a deletion that has not been tried. If a proof fails, the fallback of its record applies and nothing else changes.
- M2 follows because everything later needs the engine, the history and the stores a release candidate carries. The `aws-kms` store that adopts a key is in it, because the cloud root is the recommended path for a team with a cloud account ([which path is yours](/learn/key-stores/#which-path-is-yours)) and it has no card to alternate. The first consumer needs a build it can pin; a tagged, unsigned candidate gives it one.
- M3 needs the key files and the engine of M2. It comes before the roots of a company because a person's key is the smaller case.
- M4 needs M2: the drill walks through the cloud store and the records, and through `root revoke` and `root add`, so the transitions are built in M4 with it. M4 ends with the gate, so nothing later depends on a root that was never drilled.
- M5 follows M4 because the release subkey is bound by the project's root, and because the root's key is published in the keyring package, which the release pipeline builds in M5.
- M6 follows M5 because card roots need the card proofs of M1, the inventory of M2 and the transitions of M4 (a card root joins the set by `root add`), and the first release does not need them.
- M7 is last: each item arrives with its first real installation or caller (principle 8).

## After the first version

None of these is planned in detail. Each starts as a decision proposal. The decisions behind them are the sections "Not yet proven or only proposed" of the [records](https://github.com/truvity/ritueel/tree/main/docs/decisions), and [the design in brief](/design/) lists them.

- A post-quantum root ([issue #32](https://github.com/truvity/ritueel/issues/32)).
- More key stores, each arriving with its first real installation: Google Cloud KMS, Azure Key Vault ([issue #67](https://github.com/truvity/ritueel/issues/67)) and Nitrokey ([issue #66](https://github.com/truvity/ritueel/issues/66)) are planned, then other clouds, HSMs, TPMs and other cards. A new store passes an admission test first: a dated research page that measures P-384 over SHA-384, the evidence the store gives, access from a second process, and a replica or backup. The site compares the stores and says which to buy for testing.
- A fallback driver for the `openpgp-card` store.
- References and test vectors of the trust files, by milestone (M2, M4), and files for a key on one's own domain (WKD) and the DNS record text, as a later output with a guide.
- The oldest rpm that imports per-primary key files, and a Go library for infrastructure code made from the same policy package.
- Stage two of a person's key (two card-born primaries) and the build list of stage one (the M3 row).
- How the first replica of a cloud root is made under the key policy, and renewing a cloud root without a person (M7).
- The build and test list of the cards (the M6 row), and packing single-key roots into one card row.
- The format of the wrapped key, fixed by the M1 proof.
- The build of revocation make and check, the restore check, the drill scripts and the adoption drill; root add, retire and revoke with their vectors; an advisory review asked for in the plan (all in the M4 and M7 rows).
- The guided mode and the program side of the page (the M2 and M7 rows).
- Three teaching pages wait: user IDs, checking your cards, and renewing a delegated key.

### What is delivered

- One statically linked executable for Linux.
- A small release signer program for CI, used by the release workflow until the requester system signs natively ([record 0009](decisions/0009-release-keys-and-the-keyring.md)).
- Later, a Go library for infrastructure code. It creates the cloud keys and their policies from the same policy package that the program uses to check a key.

## How to follow

The milestones are GitHub milestones on the repository, and the [project status](/status/) page shows how many issues each has closed. The issues carry the labels `area:*` and `type:*`. A change to this plan is a pull request to this page.
