# 0009 — Root transitions: vouch, overlap, retire and revoke

**Status:** Accepted
**Date:** 2026-11-02

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) names the verbs of a transition (create, vouch, overlap, supersede, revoke) and [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) says that redundancy answers loss and revocation answers compromise. [0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/) and [0006](/decisions/0006-release-keys-and-the-keyring-package/) say what each product shows. The commands `root add`, `root retire` and `root revoke` ([issue #13](https://github.com/truvity/ritueel/issues/13)) still lack the rules that a builder needs:

- what state a root has, and what "overlap" is, when the command table says it is "a state and not a command";
- how long an overlap lasts, who decides, and what stops a root being retired while something still hangs from it;
- what the vouch is as a file, for X.509 and for OpenPGP, given that [0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package) keeps third-party certifications out of the keyring package;
- what a set of one root means after a card is lost, and which root signs next.

## Decision

- **A root is `active`, `retired` or `revoked`; the overlap is a period, not a state.** It is the time in which a root and the root that replaces it are both active. The new root's `root.json` says which root it replaces and until when. What each state does to each trust product is a table in [the transitions page](/reference/transitions/#what-each-state-does-to-the-trust-products).
- **The holder says how long the overlap lasts, and ritueel invents no default.** `root add --replaces LABEL` needs `--overlap-until DATE`: the time the slowest client takes to update is the holder's fact, not ritueel's. `root retire` is refused before that day, unless `--now REASON` is given and recorded.
- **Growing or shrinking the set is a decision.** The **target** is the number of active roots the holder intends. `init` sets it; `root add` without `--replaces` and `root retire` without a replacement need `--target N`. `status` raises an alert while the set is short of its target, which is the state between `root revoke` and the replacement, and a notice while an overlap runs.
- **A vouch is made by an active root at the ceremony of `root add`:** an X.509 cross-certificate for the new root's key, and an OpenPGP certification of the new primary by the vouching primary. The profiles are in [the transitions page](/reference/transitions/#the-vouch). The cross-certificate lets a client that trusts only the old root build a path to the new one. It is not a trust anchor and is in no bundle.
- **The OpenPGP vouch is published beside the keyring package, not in it.** [0006](/decisions/0006-release-keys-and-the-keyring-package/) keeps third-party certifications out so that every verifier sees the same few packets; a file in `vouches/` serves the people who follow certifications, and the package, signed by an old key, is what apt and rpm act on.
- **`root retire` checks that nothing hangs from the root alone.** Every registered intermediate must have a certificate, or a binding, from another active root over the same key, valid for 30 more days. It lists what is missing (`still-needed`). The fix is a `yearly` ceremony with fresh requests over the same keys.
- **`root revoke` waits for nothing but the stored revocation signature.** It checks the signature against the digest in the ledger and publishes the products without the root. What only that root had certified shows as critical in `status` until a `yearly` ceremony re-certifies it. An emergency exit that waits for tidying is not one.
- **The root of the year is the active root whose last signing is the oldest,** ties to the lowest label. With two cards that is the alternation of [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#who-signs-and-when); after a replacement the new root signs next.
- **A transition never moves a key,** whatever the stores: the five transitions of the key-stores page are one command with the new store's own checks, and the new store must give evidence for a root ([0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold)).

## Consequences

- A replaced root is never dropped by the clock: the overlap ends when the holder says and the checks pass, and a forgotten overlap is an alert, not a silent state.
- A lost card leaves a one-root set that `status` calls short, so the unsafe state cannot be forgotten.
- The cross-certificate lasts 13 months and is made again at each `yearly` ceremony while an overlap lasts. An overlap longer than that is the holder's choice, with a ceremony of its own each year.
- `root retire` can send the holder to a `yearly` ceremony first, and an OpenPGP subkey requested before the new primary existed has to be requested again with a back-signature for it ([the contract](/reference/hand-off-contract/#the-request-1)).
- Two more files per transition, in `vouches/`, to publish or to ignore.
- The `status` findings `root-set` and `root-overlap` add to the exit codes 10 to 12, and `roots_target` to every root record.

## Roads not taken

- **An overlap of a fixed length.** One fewer thing to decide, but the right length is the slowest client's, and a default would be wrong for someone and wrong silently.
- **Retire by the clock at the end of the overlap.** Nothing to forget, but a root would leave while an intermediate still hung from it alone; a root list that drops a root is not undone.
- **Overlap as a command.** A visible step, but there is nothing to do during an overlap, so a command would set a flag for the sake of having one; the dates carry the state.
- **Vouch with X.509 only.** One profile fewer, but 0001 and the lost-card guide promise both, and a `gpg` user with a path to the old key has none otherwise.
- **Put the OpenPGP vouch in the keyring package.** One file for users, but it breaks the package's rule of its own packets only, which the builder checks, for a certification that `gpgv`, `sqv` and apt never read.
- **Make `root revoke` wait for re-certification.** A tidier end state, but revocation is the emergency exit, and an hour spent re-certifying is an hour in which a stolen root still signs.
- **A cross-certificate with no end, or the root's 36 months.** Nothing to make again, but it would outlive the overlap by years and vouch for a root that has been retired.
- **List the cross-certificate in the CA bundle.** Clients with the old bundle would find the path by themselves, but the bundle is a list of anchors, and a certificate that is not one would be trusted as one.
- **Re-run `init` to replace a root.** Fewer commands, but it would drop the old root and its history with one stroke and give no overlap.

## Follow-ups

- Build `root add`, `root retire` and `root revoke`, the checks and the vectors of [the transitions page](/reference/transitions/#test-vectors) ([issue #13](https://github.com/truvity/ritueel/issues/13)).
- Run the lost-card walk-through as a drill ([issue #20](https://github.com/truvity/ritueel/issues/20)).
