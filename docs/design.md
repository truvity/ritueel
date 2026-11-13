---
title: The design in brief
description: What ritueel decides, by area, in short sentences, with what is not yet proven and what is only proposed marked; each part links its record.
flow: rows
---

Only `version` is built. This page is the design as decided on 2026-11-11 and 2026-11-12, and it marks the main points that are not yet proven or only proposed; each record lists all of its own.

## The five core ideas

1. One set of ceremonies over three kinds of store: a key file, a pair of root cards, a cloud key service. Their guarantees differ, and ritueel says how.
2. Prefer a key that cannot be copied. A root on cards or in the cloud cannot be copied, and it avoids the reboot into the offline system.
3. One bundle keeps the roots of a PKI and of OpenPGP together, with what is known about the cards.
4. Requests in, answers out. Other systems connect through files, and plans can travel.
5. An opinionated, automated workflow: say what is wanted, read the plan of what is not applied yet, and apply it.

Decided in [0001](decisions/0001-what-ritueel-is.md) and [0005](decisions/0005-a-ceremony-and-where-it-runs.md). [How it works](/how-it-works/) draws the key and the ceremony.

## What ritueel is

- A tool for the roots of a company or of one person: an X.509 trust anchor, an OpenPGP identity or an SSH CA, in one model.
- A teaching product first: each procedure has a Learn page, a guide and a drill.
- Kept apart from systems that issue certificates every day. They exchange standard formats through the [hand-off contract](/reference/hand-off-contract/).
- Out of scope: online signing, leaf certificates, secret storage and staff keys.
- Changes only your bundle. The one thing it may send out is your public OpenPGP key, to the keyservers you list. For everything else it prints what to do.

Decided in [0001](decisions/0001-what-ritueel-is.md) and [0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md).

## A ceremony

- One act, `apply`, for every store, with the same checks and ceremony records.
- A person writes what is wanted. ritueel finds what is not applied yet each time, and `apply` plans it.
- The plan fixes every byte to sign except the new keys. The person confirms by typing the first eight characters of its digest. The page makes no plan: `apply` makes it in the terminal, and the page shows that command as text.
- Plans and requests are detachable: they travel by any channel, run elsewhere, and the answer returns; coming back from the stick is a `join`.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md) and [0010](decisions/0010-the-engine-the-process-and-the-page.md).

## After a ceremony

- After a ceremony ritueel prints what to do. For an OpenPGP key the optional last step is to publish it.
- Publishing is a separate command, run after a ceremony and never inside one, in a process that never opens a card and is left out of the offline build.
- A web site, a JSON Web Key Set and the key file of your software get content and links only.
- cert-manager in a company's clusters gets its certificates from the system that issues every day.

Decided in [0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md).

## The bundle and its parts

- A bundle is a directory of plain files for one trust domain. A root key is written with the bundle name, such as acme/A.
- A person writes only wanted files: `ritueel.yaml` and one file for each card, root, delegation and the user IDs.
- `history/` is write-once, one ceremony folder for each ceremony. A numbered trust set holds the root list, CA bundle, revocation lists, SSH CA key list and public OpenPGP keyring. `requests/<name>/` holds a request and its answer.
- A bundle never holds a private key in the clear, a PIN or a passphrase.

Decided in [0006](decisions/0006-bundle-history-and-trust-files.md).

## Where a root lives

- A key is born in its store and never leaves it. The default algorithm is P-384.
- Backup means two independent cards or a replica. A copyable key is replaced within three years.
- The accepted limit: whoever holds a root card and its PIN, or the cloud role, can sign until that root key is revoked.

Decided in [0002](decisions/0002-where-a-key-lives.md).

## Cards

- Two independent root cards: redundancy, not two-person control.
- Six rows of four slots. Row 1 is the card's own jobs; rows 2 to 6 hold one bundle's keys each. One row stays free.
- One pair serves up to four bundles. A second bundle gets its sealed copy of the card secrets by a request to the first. An occupied row nobody declared is a finding.
- Root keys need the PIN and a touch, set at birth.

Decided in [0003](decisions/0003-root-cards.md).

## Opening a key file

- An age file with an unlock key and a recovery key for each bundle.
- The default unlock is a passkey on each card named as a way to open the file (the root cards). If that cannot be used, a key in slot 9d is the fallback. A holder without cards may use a passphrase. The recovery passphrase is the break-glass and may live in a password manager.

Decided in [0002](decisions/0002-where-a-key-lives.md).

## Where a root is used

- A copyable key is used only in the offline system. A cloud root always runs on the workstation, because the offline system has no network.
- A key that cannot be copied may be used on the workstation, with four conditions: a touch for every signature; the count stated in the plan; no retry of a failed touch; and a check against the plan on a second device. A cloud key has no touch; the typed digest and the role session stand in its place.
- Every ceremony record says where it ran.
- The limit: a card has no screen, so one tricked touch gives one signature that no card logs.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md).

## The stick

- The offline system is vanilla AirgapOS plus one partition that ritueel lays out, holding programs, bundles, and key files beside the bundles, never inside one. The bundles on the stick carry no wanted files.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md).

## The process and the page

- One process, started by the first command, serves the command line and the local page on one fixed loopback port, 7488.
- It ends after 15 minutes idle, never mid-ceremony, and keeps no PIN between calls.
- The page has four entries: To do, Inventory, History and Trust set. It never confirms or runs a ceremony; `ritueel apply` and the keyserver upload are shown as text and done in the terminal after a typed confirmation. Its one write, built later, is an inert proposal that a person accepts in the terminal with eight characters.

Decided in [0010](decisions/0010-the-engine-the-process-and-the-page.md).

## A person's key

- Everyone uses OpenPGP as their own key. ritueel has no staff keys.
- Stage one adopts an existing primary as a software key with an expiry. Card-born primaries come later.
- Changing a name or address is a ceremony: a person edits the user IDs, and `apply` certifies the new one and revokes the old one as no longer valid; the key and its trust stay. For a person's own key it is part of M3.

Decided in [0008](decisions/0008-a-persons-own-key.md).

## A company's roots and a cloud root

- A root changes by adding, overlapping, retiring and revoking its keys. A compromise is answered by revocation, never a second copy.
- The cloud keys live in the holder's account, each replicated to a second Region. ritueel creates or adopts them.
- The holder supplies the roles; ritueel writes no hardware-key rule.
- An X.509 root key is not renamed: its name is inside its certificate and every intermediate names it as issuer. A new name is a new key (add, overlap, retire).

Decided in [0007](decisions/0007-changing-and-losing-a-root.md), [0006](decisions/0006-bundle-history-and-trust-files.md) and [0004](decisions/0004-the-cloud-root.md).

## Test roots and the yearly rhythm

- A test root is marked at birth, as a key file with no passphrase or on a rehearsal card; its ceremony records are marked as test.
- A root key is valid about three years; an intermediate about 13 months, renewed by re-signing.

Decided in [0005](decisions/0005-a-ceremony-and-where-it-runs.md) and [0007](decisions/0007-changing-and-losing-a-root.md).

## More that is decided

- Refusals come before anything is written, such as a wrong card or a default PIN.
- Each OpenPGP primary gets revocation signatures at birth, kept apart. A drill is due yearly.
- A host refuses a lower sequence, a bad signature and an expired list.
- The site publishes only a small target (`site/published.txt`).

Decided in [0001](decisions/0001-what-ritueel-is.md), [0003](decisions/0003-root-cards.md), [0005](decisions/0005-a-ceremony-and-where-it-runs.md), [0006](decisions/0006-bundle-history-and-trust-files.md) and [0007](decisions/0007-changing-and-losing-a-root.md).

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

- How a cloud key takes its turn beside card keys ([0004](decisions/0004-the-cloud-root.md#not-yet-proven-or-only-proposed), [0007](decisions/0007-changing-and-losing-a-root.md#not-yet-proven-or-only-proposed), [0009](decisions/0009-release-keys-and-the-keyring.md#not-yet-proven-or-only-proposed)), and what a proposal from the page may hold ([0010](decisions/0010-the-engine-the-process-and-the-page.md#not-yet-proven-or-only-proposed)).
- The exact file names in a bundle and the repair of a fork ([0006](decisions/0006-bundle-history-and-trust-files.md#not-yet-proven-or-only-proposed)).
- Which conditions the program enforces, the age of a plan and a flag for scripts ([0005](decisions/0005-a-ceremony-and-where-it-runs.md#not-yet-proven-or-only-proposed)); revoke while a ceremony runs ([0007](decisions/0007-changing-and-losing-a-root.md#not-yet-proven-or-only-proposed)); the ceremony record of an adoption ([0003](decisions/0003-root-cards.md#not-yet-proven-or-only-proposed)).
- One passkey credential for each bundle on a shared card ([0002](decisions/0002-where-a-key-lives.md#not-yet-proven-or-only-proposed)).
- What the publish step shows and refuses, where the keyserver list lives, and the flag and form names of the new commands ([0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md#not-yet-proven-or-only-proposed)).
- Whether keys.openpgp.org accepts a certify-only primary ([0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md#not-yet-proven-or-only-proposed)), and whether Maven Central accepts a signing subkey under one ([0009](decisions/0009-release-keys-and-the-keyring.md#not-yet-proven-or-only-proposed)).

## What comes later

More stores, a person's card-born primaries (stage two), a post-quantum root and a Go library. Recipes for consumers that need a change of the hand-off contract, a check of the local trust store, and calling a code host's own tool.

Listed in [the roadmap](/roadmap/#after-the-first-version).
