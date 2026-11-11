# 0007 — A root changes by add, overlap, retire and revoke; revocation material and a drill prove the way back

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. ritueel supports six actions on a root: create; vouch by an existing root for a new one; overlap old and new; supersede the old; revoke, with revocation material made in advance; expire, extended at each use.
2. A compromise is answered by revocation and a transition, in either setup, never by a second copy.
3. A root is active, retired or revoked. An overlap is a period with both roots active, not a state. The new root's `root.json` says which root it replaces and until when.
4. The holder says how long the overlap lasts; ritueel invents no default. `root add --replaces LABEL` needs `--overlap-until DATE`. `root retire` is refused before that day unless `--now REASON` is given and recorded.
5. The target is the number of active roots the holder intends. `init` sets it; `root add` without `--replaces` and `root retire` without a replacement need `--target N`. `status` alerts while the set is short of its target and notes a running overlap (findings root-set and root-overlap, exit codes 10 to 12). Every root record gains `roots_target`.
6. An active root vouches at `root add`: an X.509 cross-certificate for the new root's key, and an OpenPGP certification of the new primary. The cross-certificate is no trust anchor and is in no CA bundle. It lasts 13 months and is made again at each yearly ceremony while an overlap lasts; a longer overlap is the holder's choice, with a ceremony each year. The OpenPGP vouch is published in `vouches/`, not inside the keyring package.
7. `root retire` checks that every registered intermediate has a certificate or binding from another active root over the same key, valid for 30 more days, and lists what is missing (finding `still-needed`). The fix is a yearly ceremony (`ritueel due`, `ritueel run`) with fresh requests over the same keys.
8. `root revoke` waits for nothing but the stored revocation material (revocation signature, and removal authorisation when needed). It checks both against bundle digests and publishes the trust files without the root. What only that root had certified is critical in `status` until a yearly ceremony certifies it again.
9. Revoking a root means a new root list without it, signed by the surviving roots and carrying its removal authorisation, with new trust files beside it.
10. A transition never moves a key, whatever the stores. The five transitions are one command with the new store's own checks, and the new store must give evidence for a root.
11. A stolen intermediate is a small event: revoke it and certify a new key with the root of the year. Revoking it needs the card of each root that issued one of its unexpired certificates; if that card is lost, the root is revoked as a whole, with all it issued.
12. Adding a root is a two-card ceremony with two cards; the yearly ceremony stays one-card.
13. A root is valid for about three years and each use extends it. The signing card extends its own root: a new OpenPGP self-signature and an X.509 root certificate issued again over the same key and subject. Every ceremony using a card includes this as one more planned, recorded signature. A dead or lost card shows itself by not extending.
14. The cards alternate by year. The root of the year is the active root whose last signing is the oldest, ties to the lowest label; after a replacement the new root signs next; `--root` overrides it with a reason recorded.
15. An intermediate lasts about 13 months and is renewed by re-signing: a new certificate over the same key and a new binding extending the same subkey. No key is made at a yearly ceremony.
16. The yearly ceremony is held in month 12 of the 13. `status` warns about an intermediate at 60, 30 and 14 days and about a root at 6 months, 3 months and 30 days, with exit codes 10, 11 and 12 for notice, alert and critical.
17. The renewal plan needs a request for every registered intermediate and stops when one is missing, unless `--allow-missing NAME` is given to `due` and recorded.
18. At every yearly ceremony the holder reviews the advisories for the devices, services and algorithms in use, and the record says so. It is a step, not a habit.
19. A key is re-signed yearly (same key, new validity) and rotated to a new key on an event; a key in software is also rotated after at most three years.
20. At birth ritueel makes a revocation signature for each of two reasons, compromised and superseded, for every OpenPGP primary it creates (each root's and a person's own); the holder may add retired or no reason. It is stored apart from the card. There is no designated revoker. The signature is not a revocation: for apt users the new keyring package is; the signature serves gpg and Sequoia users.
21. At birth every root also makes a removal authorisation: its X.509 root key signs a statement over its own pin, so the root can leave the root set when it can no longer sign. It is kept like revocation material. Each signature and the authorisation take one more touch at a card ceremony: at `init`, three more on each card.
22. Revocation material is written only where the holder names, and ritueel refuses a place inside the bundle or its repository. It never overwrites a revocation file, never prints a signature and does not record the path; the bundle keeps the digest and the reason only. It can be made again while the primary and its PIN exist, by a ceremony of its own, and checked at any time by a command that prints only a verdict. The holder keeps it apart from the cards, in at least two places.
23. A drill is a practice on test keys with a known start and end. The restore check (`ritueel drill restore`) reads the real bundle and holders, signs nothing, and reports passed, failed or not run; it exits 0 only when every check ran and passed, and a check that cannot run is accepted by name or the drill is incomplete. Walk-throughs are scripts beside the guides that run ceremonies on test roots and time them; they call only public commands, CI runs every one, and the holder runs the lost-card one once on rehearsal cards. A drill never needs a real key or account: scripts refuse a card not registered as a rehearsal card and use `--test-root` otherwise.
24. Signed commits are checked against the holder's own signers file, never a key in the bundle; without the file the check is not run.
25. A drill is due once a year with the yearly ceremony; `status` notes a newest report older than 13 months. ritueel teaches the rhythm and does not enforce it. Cards are checked every six months (card check, read-only comparison, proof of life), per bundle for its own rows; the restore drill stays yearly. Drill reports are files the holder commits, not records, and stay out of the hash chain.
26. `root.json` holds `revocations` instead of `revocation_sha256`. A software root's key files sit beside the bundles on the stick partition, not in the bundle.
27. ritueel covers backup and restore drills (rebuild the state on a clean machine from the bundle and the password manager, compare it with the cards), revocation (OpenPGP certificates made in advance and kept apart; CRLs and root lists for X.509), and card loss and replacement.

## Why

A root must change, and may be lost, without the trust files failing. So each change is a planned step with a checked end, and the way back is made at birth. A signature never tried is a hope, so a drill tries it.

## What it costs

- The holder chooses the overlap length, the target and each early step.
- A longer overlap costs a ceremony each year.
- Revocation material costs extra touches.
- A lost revocation signature cannot be replaced once the card and PIN are gone.

## Roads not taken

- **Overlap as a command.** A visible step, but nothing to do during an overlap, so it would only set a flag.
- **An overlap of a fixed length.** One fewer thing to decide, but the right length is the slowest client's and a default is wrong silently.
- **Retire by the clock at the end of the overlap.** Nothing to forget, but a root could leave while an intermediate still hung from it alone.
- **Vouch with X.509 only.** One profile fewer, but a gpg user would have no path to the old key.
- **List the cross-certificate in the CA bundle.** Old clients would find the path, but a non-anchor would be trusted as one.
- **A cross-certificate with no end, or the root's 36 months.** Nothing to make again, but it outlives the overlap and vouches for a retired root.
- **Put the OpenPGP vouch in the keyring package.** One file for users, but it breaks the package's rule of its own packets only.
- **Make `root revoke` wait for re-certification.** Tidier, but an hour of re-certifying is an hour a stolen root still signs.
- **Re-run `init` to replace a root.** Fewer commands, but it drops the old root and its history in one stroke and gives no overlap.
- **A fixed ten-year root, or no expiry.** No yearly change, but a dead card stays silent for years.
- **Replace every intermediate key every year.** Short-lived keys, but a key ceremony per holder per year moves a sound key for no gain.
- **Each intermediate certified by both roots.** Survives either loss, but some path builders skip the second certificate and every renewal needs both cards.
- **One OpenPGP subkey bound under both primaries.** Verifies under either, but rotation needs both cards and a revocation must be made twice.
- **A designated revoker, each root for the other.** Revocation without the stored signature, but RFC 9580 deprecates it and it widens what one stolen card can do.
- **One revocation signature, reason chosen at birth.** Simpler, but a wrong guess either believes a thief's backdated signatures or distrusts every release.
- **A signature made at the event, from the card.** Right reason, but a lost card cannot sign.
- **No removal authorisation; a lost root removed from each host by hand.** Nothing more to make, but every host's pins need replacing out of band.
- **Write the signatures into the bundle, encrypted.** Backed up with it, but the bundle is cloned and pushed where a revocation should never be.
- **Print a signature on the terminal to copy.** Easy to copy, but the terminal scrolls into logs and transcripts.
- **A drill that passes when a check could not run.** Friendly in CI, but a green check that tests nothing.
- **A drill that replays real ceremonies on the real cards.** The truest test, but it spends touches and risks the real roots.
- **Verify the bundle's commits against keys in the bundle.** No extra file, but an attacker who rewrites history rewrites the signers too.
- **A card check only at the yearly ceremony.** One rhythm, but a dead card shows only at the next ceremony, up to a year later.
- **A sign-off per drill in the hash chain.** One history, but a drill signs nothing and the chain is for what was signed.

## Not yet proven or only proposed

- **Not yet proven.** The first proofs on a rehearsal card, before the stores are built: the passkey secret with PIN and touch over USB from a static binary; the offline system reaching the card's passkey side; deleting one slot; placeholder certificates seen by other tools; the read-only check; a factory-value report that spends no PIN try; and that AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it. If a proof fails, the fallback of its record applies and nothing else changes ([#8](https://github.com/truvity/ritueel/issues/8), [#11](https://github.com/truvity/ritueel/issues/11)).

## Replaces

0001, 0002, 0004, 0005, 0007, 0009, 0010, and in part 0015 and 0016 (read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee).
