# 0010 — Readiness is made at birth and proved by a drill

**Status:** Accepted
**Date:** 2026-11-02

## Context

[0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-procedures-ritueel-will-cover) commits ritueel to revocation made in advance and to backup and restore drills, and [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#revocation-readiness) says a revocation signature is made for each primary when it is born. Three things are not yet decided, for [issue #69](https://github.com/truvity/ritueel/issues/69), [issue #68](https://github.com/truvity/ritueel/issues/68) and [issue #20](https://github.com/truvity/ritueel/issues/20):

- **Which revocation signature.** One signature has one reason, and the reason decides what verifiers do with everything the key signed before. The event is unknown at birth, and the [Revoke](/learn/revoke/#reasons-matter) page already teaches one for each likely reason, while the design had one.
- **Where it may be written.** It destroys the standing of a key for anyone who holds it, so a place that a ledger commit or a backup could sweep up is the wrong place.
- **What a drill is.** The command of issue 68 reads the real state; the lost-card drill of issue 20 changes state. They are not the same kind of thing, and neither may need a real key.

## Decision

### Revocation material

- **At birth, ritueel makes a revocation signature for each of two reasons, `compromised` and `superseded`, for every OpenPGP master key it creates:** the primary of each root and a person's own primary. The holder may add `retired` or `no reason`. The two default reasons cover the two events a holder meets: a card that is stolen with its PIN, and a card that is lost or replaced and was safe.
- **It is written only where the holder names, outside the ledger.** The directory is a command argument, ritueel refuses one inside the ledger or inside the repository that holds it, never overwrites a file, never prints a signature, and does not record the path. The ledger keeps the digest of each signature and its reason, and nothing else.
- **It can be made again while the primary and its PIN exist,** by a ceremony of its own, and checked at any time by a command that prints only a verdict. Both are in [the reference](/reference/revocation-material/).
- **A revocation signature is not a revocation.** For apt users the new keyring package is the revocation ([0006](/decisions/0006-release-keys-and-the-keyring-package/#revocation)); the signature serves `gpg` and Sequoia users, and the guides say so.

### Drills

- **A drill is a practice on test keys with a known start and end,** in two kinds: a **restore check**, `ritueel drill restore`, that reads the real ledger and its holders, signs nothing and reports each check as passed, failed or not run; and **walk-throughs**, scripts beside the guides that run ceremonies on test roots and time them.
- **The restore check exits 0 only when every check ran and passed.** A check that cannot run on this machine is accepted by name, in the report, or the drill is incomplete (principle 4).
- **Signed commits are checked against the holder's own signers file** and never against a key in the ledger: a ledger that vouches for its own history proves nothing. Without the file the check is not run.
- **The walk-throughs call only public commands,** so the guide, the script and CI cannot drift apart: CI runs every one on test roots, and the holder runs the lost-card walk-through once on test cards.
- **A drill never needs a real key or account.** The scripts refuse a card that is not named as a test card, and use `--test-root` otherwise.
- **A drill is due once a year,** with the yearly ceremony. `status` raises a notice when the newest report is older than 13 months. The rhythm is ritueel's policy; ritueel teaches it and does not enforce it.

## Consequences

- A root has two files to store apart, not one, and a card ceremony takes one more touch per reason. At `init` that is two more touches on each card.
- The reason can be chosen at the event, honestly, which is the teaching of [Revoke](/learn/revoke/).
- A holder who loses both files for a reason can still make another while the card and PIN exist; one who loses the card and the files can no longer revoke that primary, which [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#consequences) already says.
- The restore check needs the revocation files in reach, so a drill is also the yearly proof that they are where the holder thinks.
- Drill reports are files the holder commits; they are not records and do not enter the hash chain.
- The software root's key-file names in [the directory](/reference/directory/#the-software-roots-key-files) change, and `root.json` holds `revocations` instead of `revocation_sha256`. Nothing has been released that reads either.

## Roads not taken

- **One revocation signature, with the reason chosen at birth.** One file fewer, but the reason is a guess about a future event, and a wrong guess is either a thief's backdated signatures believed or every release distrusted.
- **A signature made at the event, from the card.** The right reason every time, but a lost card cannot sign, which is the case the signature exists for.
- **Write the signatures into the ledger, encrypted.** Backed up with it, but the ledger is cloned and pushed to places a revocation should never be, and its backups are the wrong audience.
- **Print a signature on the terminal for the holder to copy.** No file to guard, but the terminal scrolls into logs and a transcript, and a secret that is shown once is shown to everything that records the screen.
- **A designated revoker.** Revocation with no stored file, but RFC 9580 forbids generating one and it widens what a stolen card can do ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)).
- **A drill that replays real ceremonies on the real cards.** The truest test, but it spends touches and risks the real roots, and a practice should fail safely.
- **Verify the ledger's commits against keys in the ledger.** Nothing for the holder to supply, but an attacker who rewrites history rewrites the signers too.
- **A drill that passes when a check could not run.** Friendly in CI, but it is the green check that tests nothing; the accepted-by-name exception keeps the exception visible.
- **A sign-off per drill in the hash chain.** One history, but a drill signs nothing and the chain is for what was signed.

## Follow-ups

- The revocation signatures, their files, `revocation make` and `check` ([issue #69](https://github.com/truvity/ritueel/issues/69)).
- The restore check and its report ([issue #68](https://github.com/truvity/ritueel/issues/68)).
- The drill scripts, the CI job and the lost-card drill ([issue #20](https://github.com/truvity/ritueel/issues/20)).
- The adoption drill, with both reasons stored apart ([issue #48](https://github.com/truvity/ritueel/issues/48)).
