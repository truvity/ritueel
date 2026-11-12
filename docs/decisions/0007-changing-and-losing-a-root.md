# 0007 — A root changes by add, overlap, retire and revoke; revocation material and a drill prove the way back

**Status:** Accepted
**Date:** 2026-11-12

## Decision

1. ritueel supports six actions on a root key: create; vouch by an existing key for a new one; overlap old and new; supersede the old; revoke, with revocation material made in advance; expire, extended at each use.
2. A compromise is answered by revocation and a transition, in either setup, never by a second copy.
3. A root key is active, retired or revoked, never "lost". An overlap is a period with both keys active, not a state. The wanted root file says what a new key replaces and until when.
4. The holder says how long the overlap lasts, as a wanted end date; ritueel invents no default. A key is retired earlier only if the holder moves the date and records a reason.
5. The target is the number of root keys the holder wants, which is the number in the wanted root file; a deleted key line removes no key (0005 rule 30). `status` alerts while the set is short of it and notes a running overlap (findings root-set and root-overlap, exit codes 10 to 12).
6. An active root key vouches for an added key: an X.509 cross-certificate for it, and an OpenPGP certification of the new primary. The cross-certificate is no trust anchor and is in no CA bundle. It lasts 13 months and is made again at each yearly ceremony while an overlap lasts; a longer overlap is the holder's choice, with a ceremony each year. The OpenPGP vouch is published in `vouches/`, not inside the keyring package.
7. ritueel leaves a key's retirement out of the plan until every declared delegation has a certificate or binding from another active key over the same key, valid for 30 more days, and lists what is missing (finding `still-needed`). The fix is the next `apply` with fresh requests over the same keys.
8. `revoke` is an act of its own, outside `apply`. It waits for nothing but the stored revocation material, checks it against bundle digests and writes the trust set without the key. What only that key had certified is critical in `status` until a ceremony certifies it again.
9. Revoking a root key means a new root list without it, signed by the surviving keys and carrying its removal authorisation, with a new trust set beside it.
10. A transition never moves a key, whatever the stores. Every transition is one change of the wanted root file with the new store's own checks; the new store must give evidence for a root.
11. A stolen intermediate is a small event: revoke it and certify a new key with the card of the year. Revoking it needs the card of each root key that issued one of its unexpired certificates; if that card is lost, that root key is revoked, with all it issued.
12. Adding a root key is a two-card ceremony with two cards; the yearly ceremony stays one-card. A change of the root keys runs alone, never with renewals of delegations or of the root list.
13. A root key is valid for about three years and each use extends it. The signing card extends its own key: a new OpenPGP self-signature and an X.509 root certificate issued again over the same key and subject. Every ceremony using a card includes this as one more planned, recorded signature. A dead or lost card shows itself by not extending.
14. The cards alternate by year. The card of the year signed longest ago, ties to the lowest key label; after a replacement the new card signs next. A person may name another card, and must when the card of the year is absent; the reason is recorded.
15. An intermediate lasts about 13 months and is renewed by re-signing: a new certificate over the same key and a new binding extending the same subkey. No key is made at a yearly ceremony.
16. The yearly ceremony is held in month 12 of the 13. `status` warns about an intermediate at 60, 30 and 14 days and about a root key at 6 months, 3 months and 30 days, with exit codes 10, 11 and 12 for notice, alert and critical.
17. The renewal plan needs a request for every declared delegation and stops when one is missing, unless the holder allows a missing request by name and it is recorded.
18. At every yearly ceremony the holder reviews the advisories for the devices, services and algorithms in use, and the ceremony record says so. It is a step, not a habit.
19. A key is re-signed yearly (same key, new validity) and rotated to a new key on an event; a key in software is also rotated after at most three years.
20. At birth ritueel makes a revocation signature for each of two reasons, compromised and superseded, for every OpenPGP primary it creates (a root key's and a person's own); the holder may add retired or no reason in the wanted root file. It is stored apart from the card. There is no designated revoker. The signature is not a revocation: for apt users the new keyring package is; the signature serves gpg and Sequoia users.
21. At birth every root key also makes a removal authorisation: its X.509 root key signs a statement over its own pin, so the key can leave the set when it can no longer sign. It is kept like revocation material. Each signature and the authorisation take one more touch at a card ceremony: three more on each card.
22. Revocation material is written only where the holder names, and ritueel refuses a place inside the bundle or its repository. It never overwrites a revocation file, never prints a signature and does not record the path; the bundle keeps the digest and the reason only. It can be made again while the primary and its PIN exist, by `apply` for the reasons in the wanted root file, and checked at any time by a command that prints only a verdict. The holder keeps it apart from the cards, in at least two places.
23. A drill is a practice on test keys with a known start and end. The restore check reads the real bundle and holders, signs nothing, and reports passed, failed or not run; it exits 0 only when every check ran and passed, and a check that cannot run is accepted by name or the drill is incomplete. Walk-throughs are scripts beside the guides that run ceremonies on test roots and time them; they call only public commands, CI runs every one, and the holder runs the lost-card one once on rehearsal cards. A drill never needs a real key or account: scripts refuse a card not registered as a rehearsal card and use a test root otherwise.
24. Signed commits are checked against the holder's own signers file, never a key in the bundle; without the file the check is not run.
25. A drill is due once a year with the yearly ceremony; `status` notes a newest report older than 13 months. ritueel teaches the rhythm and does not enforce it. Cards are checked every six months (a read-only check of the cards, proof of life), per bundle for its own rows; the restore drill stays yearly. Drill reports are files the holder commits, not records, and stay out of the hash chain.
26. The bundle keeps a root key's revocations as digest and reason (rule 22). A software key's files sit beside the bundles on the stick partition, not in the bundle.
27. ritueel covers backup and restore drills (rebuild the state on a clean machine from the bundle and the password manager, compare it with the cards), revocation (OpenPGP certificates made in advance and kept apart; CRLs and root lists for X.509), and card loss and replacement.
28. An X.509 root key is not renamed: its name is inside the certificate and every intermediate names it as issuer. A new name is a new key, by add, overlap and retire, and the command line and the page say so.

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
- **Make `revoke` wait for re-certification.** Tidier, but an hour of re-certifying is an hour a stolen root still signs.
- **Run `new` again to replace a root.** Fewer commands, but it drops the old root and its history in one stroke and gives no overlap.
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
- **Rename an X.509 root in place.** One step, but the name is signed into the certificate and into every intermediate below it, so a rename would break every chain.
- **The target as a stored number.** Explicit, but it says again what the wanted root file says; the target is the number of wanted keys.
- **The overlap date as a flag of a command.** One step, but the date would live only in a ceremony record and would not be wanted; it is a wanted date with a reason.
- **A fourth key state, "lost".** It names what a person sees, but a lost key cannot be told from a stolen one and both are answered by `revoke`; three states stay.
- **The program chooses the card when the card of the year is absent.** No stop for a missing card, but a person would not see which card signs; a person names the card and the reason is recorded.
- **Revocation as a line in a wanted file.** One way for everything, but a revocation would wait for a plan; `revoke` is an act of its own.
- **A change of the root keys together with renewals in one ceremony.** One sitting, but a failed touch could leave the set half changed beside renewals nobody planned; it runs alone.

## Not yet proven or only proposed

- **Not yet proven.** The first proofs on a rehearsal card, before the stores are built: the passkey secret with PIN and touch over USB from a static binary; the offline system reaching the card's passkey side; deleting one slot; placeholder certificates seen by other tools; the read-only check; a factory-value report that spends no PIN try; and that AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it. If a proof fails, the fallback of its record applies and nothing else changes ([#8](https://github.com/truvity/ritueel/issues/8), [#11](https://github.com/truvity/ritueel/issues/11)).
- **Proposed.** Revoke and a ceremony that runs on the same machine: whether `revoke` stops it (with `stop`) or waits for it, and whether `revoke` leaves a ceremony record and prints the end of the history like any ceremony. Two writers on one bundle could fork the history ([#141](https://github.com/truvity/ritueel/issues/141)).
- **Proposed.** How the card of the year is found when one root has a key on a card and a key in the cloud ([#137](https://github.com/truvity/ritueel/issues/137)).

## Replaces

0001, 0002, 0004, 0005, 0007, 0009, 0010, and in part 0015 and 0016 (read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee).
