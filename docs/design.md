---
title: The design in brief
description: What ritueel decides, by area, in short sentences, with what is not yet proven and what is only proposed marked; each part links its record.
---

The program is not built. This page is the design as decided on 2026-11-11, and it marks the main points that are not yet proven or only proposed; each record lists all of its own under Not yet proven or only proposed.

## The five core ideas

1. One set of ceremonies over three kinds of store: a key file, a pair of root cards, a cloud key service. Their guarantees differ, and ritueel says how.
2. Prefer a key that cannot be copied. A root on cards or in the cloud cannot be copied, and it avoids the reboot into the offline system.
3. One bundle keeps the roots of a PKI and of OpenPGP together, with what is known about the cards.
4. Requests in, answers out. Other systems connect through files, and plans can travel.
5. An opinionated, automated workflow: what is due, then plan, confirm, reserve, sign, verify, record.

Decided in [0001](decisions/0001-what-ritueel-is.md) and [0010](decisions/0010-the-engine-the-process-and-the-page.md). [How it works](/how-it-works/) draws the five.

## What ritueel is

- A tool for the root keys of a company or of one person: an X.509 CA root or an OpenPGP primary, in one model.
- A teaching product first: each procedure has a Learn page, a guide and a drill.
- Kept apart from systems that issue certificates every day. They exchange standard formats through the [hand-off contract](/reference/hand-off-contract/).
- Out of scope: online signing, leaf certificates, secret storage and staff keys.

Decided in [0001](decisions/0001-what-ritueel-is.md) and [0010](decisions/0010-the-engine-the-process-and-the-page.md).

## A ceremony

- Six steps for every store: plan, confirm, reserve, sign, verify, record.
- The plan fixes every byte to sign except the new keys. The person confirms by typing the first eight characters of its digest.
- Plans and requests are detachable: they travel by any channel, run elsewhere, and the answer returns.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md).

## The bundle and its parts

- A bundle is a directory of plain files for one trust domain. A root is written with the bundle name, such as acme/A.
- `ritueel.yaml` is the one file a person writes.
- `history/` is write-once, one folder per ceremony. `trust/<number>/` holds the root list, CA bundle, revocation lists, SSH CA key list and public OpenPGP keyring. `requests/<name>/` holds a request and its answer.
- A bundle never holds a private key in the clear, a PIN or a passphrase.

Decided in [0006](decisions/0006-bundle-history-and-trust-files.md).

## Where a root lives

- A key is born in its store and never leaves it. The default algorithm is P-384.
- Backup means two independent cards or a replica. A copyable key is replaced within three years.
- The accepted limit: whoever holds a root card and its PIN, or the cloud role, can sign until the root is revoked.

Decided in [0002](decisions/0002-where-a-key-lives.md).

## Cards

- Two independent root cards: redundancy, not two-person control.
- Six rows of four slots. Row 1 is the card's own jobs; rows 2 to 6 hold one root each. One row stays free.
- One pair serves up to four bundles. A second bundle gets its sealed copy of the card secrets by a request to the first. An occupied row nobody declared is a finding.
- Root keys need the PIN and a touch, set at birth.

Decided in [0003](decisions/0003-root-cards.md).

## Opening a key file

- An age file with an unlock key and a recovery key for each bundle.
- The default unlock is a passkey on each root card. If that cannot be used, a key in slot 9d is the fallback. A holder without cards may use a passphrase.

Decided in [0002](decisions/0002-where-a-key-lives.md).

## Where a root is used

- A copyable key is used only in the offline system.
- A key that cannot be copied may be used on the workstation, with four conditions: a touch for every signature; the count stated in the plan; no retry of a failed touch; and a check against the plan on a second device. The touch is for a root on cards only: a cloud key has no touch, and for a cloud root the typed digest and the role session stand; the other three conditions apply to both kinds.
- Every record says where the ceremony ran.
- The limit: a card has no screen, so one tricked touch gives one signature that no card logs.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md).

## The stick

- The offline system is vanilla AirgapOS plus one partition that ritueel lays out, holding programs, bundles, and key files beside the bundles, never inside one.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md).

## The process and the page

- One process, started by the first command, serves the command line and the local page on one fixed loopback port.
- It ends after 15 minutes idle, never mid-ceremony, and keeps no PIN between calls.
- The page never confirms or runs a ceremony.

Decided in [0010](decisions/0010-the-engine-the-process-and-the-page.md).

## A person's key

- Everyone uses OpenPGP as their own key. ritueel has no staff keys.
- Stage one adopts an existing primary as a software key with an expiry. Card-born primaries come later.

Decided in [0008](decisions/0008-a-persons-own-key.md).

## A company's roots and a cloud root

- A root changes by add, overlap, retire and revoke. A compromise is answered by revocation, never a second copy.
- A cloud root is one dedicated account with three keys, each replicated to a second Region. ritueel creates or adopts them.
- The operator supplies the roles; ritueel writes no hardware-key rule.

Decided in [0007](decisions/0007-changing-and-losing-a-root.md), [0006](decisions/0006-bundle-history-and-trust-files.md) and [0004](decisions/0004-the-cloud-root.md).

## Test roots and the yearly rhythm

- A test root is born with `init --test-root`, as a key file with no passphrase or on a rehearsal card; its records are marked as test.
- A root is valid about three years; an intermediate about 13 months, renewed by re-signing.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md) and [0007](decisions/0007-changing-and-losing-a-root.md).

## More that is decided

- Refusals come before anything is written, such as a wrong card or a default PIN.
- Each OpenPGP primary gets revocation signatures at birth, kept apart. A drill is due yearly.
- A host refuses a lower sequence, a bad signature and an expired list.
- The site publishes only a small target (`site/published.txt`).

Decided in [0001](decisions/0001-what-ritueel-is.md), [0003](decisions/0003-root-cards.md), [0006](decisions/0006-bundle-history-and-trust-files.md) and [0007](decisions/0007-changing-and-losing-a-root.md).

## Releases

- The release primaries are the root primaries. A release is proved by a checksum file signed by a release subkey, with a keyless signature beside it.
- ritueel makes the keyring file; a pipeline packages it.

Decided in [0009](decisions/0009-release-keys-and-the-keyring.md).

## Decided, but not yet proven

- The passkey unlock on a root card ([0002](decisions/0002-where-a-key-lives.md#not-yet-proven-or-only-proposed)).
- Deleting one card slot, and touch always across several signatures ([0003](decisions/0003-root-cards.md#not-yet-proven-or-only-proposed)).
- That AirgapOS boots from the stick and runs a program from its partition ([0005](decisions/0005-a-ceremony-and-where-it-runs.md#not-yet-proven-or-only-proposed)).
- Adopting an existing cloud key against a real account ([0004](decisions/0004-the-cloud-root.md#not-yet-proven-or-only-proposed)).

## Proposed or open

- The port number 7488 ([0010](decisions/0010-the-engine-the-process-and-the-page.md#not-yet-proven-or-only-proposed)) and the exact file names in a bundle ([0006](decisions/0006-bundle-history-and-trust-files.md#not-yet-proven-or-only-proposed)).
- Which conditions the program enforces ([0005](decisions/0005-a-ceremony-and-where-it-runs.md#not-yet-proven-or-only-proposed)).
- One passkey credential for each bundle on a shared card ([0002](decisions/0002-where-a-key-lives.md#not-yet-proven-or-only-proposed)).

## What comes later

More stores, a person's card-born primaries (stage two), a post-quantum root and a Go library.

Listed in [the roadmap](/roadmap/#after-the-first-version).
