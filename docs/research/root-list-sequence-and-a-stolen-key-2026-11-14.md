---
title: TUF takes only the next root version and recovers a raised counter by rotating keys; for the root list a way back for key-removing lists fits best (read, 2026-11-14)
description: Reading note on how TUF, Sigstore, CT, Go's checksum database and apt treat a version one key can raise, and seven options for the root list's sequence.
sidebar:
  order: 20
---

## Question

One stolen root key can sign a root list that keeps the same root keys and carries the highest sequence the format allows. A host that takes it then refuses every honest list, also the list that revokes the stolen key. What do other update systems do about a version number that one signer can raise, and which option fits the [root list](../reference/root-list.md)?

Terms used below. A **host** is a system that reads the root list to learn which root keys are active. A **root key** is one of the keys that sign the list. The **held list** is the last good list a host has accepted. The **sequence** is the number in the list; it grows by one at each change. A **removal authorisation** is a statement that each root key signs over its own pin when it is born, so that the key can be removed without its signature ([the page](../reference/root-list.md#the-removal-authorisation)). A **freeze** is when a client is kept on old data. A **rollback** is when a client is made to take older data than it knew. A **fast-forward** is when a signer sets a version number so high that later honest versions look old (TUF's own words are in section 2). A **threshold** is the number of keys that must sign. A **signed tree head (STH)** is the signed size and hash of a transparency log. A **Release file** is the signed index of a Debian archive.

## When

Read on 2026-11-14. The ritueel pages are those of `origin/main` at commit `69ff9df` (2026-11-13). Nothing was run: this note compares documents and source code. Code was read at the versions in the table, not executed.

## Verdict

**Other systems answer in three ways.** TUF takes the next root version only (N+1), asks both the old and the new key set to sign each step, and asks the repository to publish every version. For the version numbers of its other roles, which a signer can fast-forward, TUF does not limit the jump: it rotates those roles' keys through the root and then tells clients to delete their saved copies. Go's checksum database and Certificate Transparency (CT) bind a larger tree to the smaller one by a hash proof; there a fork is a fatal error and the way back is by hand. apt orders a Release file by its signed date, refuses a date in the future and ignores an older file. **Conclusion:** the root list already asks for every other key, or the leaving key's stored authorisation, when a key leaves. A list that clears that bar may also reset the host's sequence, which is a rule of the same kind as TUF's recovery from a fast-forward. A limit on the number alone (the next sequence only) stops a thief who can add one file, not a thief who answers every request of a host.

The recommendation, with the one fact that decides it, is in section 5. Which options a maintainer chooses is the maintainer's decision.

## What was read

| What | Version or date | Read on |
|---|---|---|
| The Update Framework specification | 1.0.37, "Last modified: 8 October 2026" | 2026-11-14 |
| Mercury paper (fast-forward attack and its recovery) | USENIX ATC '17, July 2017 | 2026-11-14 |
| Sigstore `root-signing`: README (commit `cf46563`, 2026-10-13), `metadata/root.json` (commit `a180c17`, 2026-10-16, root version 16), `metadata/root_history` | as dated | 2026-11-14 |
| RFC 9162, Certificate Transparency Version 2.0 | December 2021, Experimental | 2026-11-14 |
| Go checksum database design note ("Last updated: April 24, 2019"); "Transparent Logs for Skeptical Clients" (2019-03-01); `golang.org/x/mod/sumdb/client.go` (`master`; last commit touching it `2b553c8`, 2026-11-12) | as dated | 2026-11-14 |
| Debian wiki "DebianRepository/Format" (last modified 2026-01-18); apt `acquire-item.cc` (`main`, last commit touching it `b635ddd`, 2026-07-20) and `deb/debmetaindex.cc` (`5c6be0c`, 2026-10-23); `apt.conf(5)` of Debian testing | as dated | 2026-11-14 |
| ritueel: [root list](../reference/root-list.md), [record 0006](../decisions/0006-bundle-history-and-trust-files.md) (rules 14, 18, 20 to 22 and "Roads not taken"), [record 0007](../decisions/0007-changing-and-losing-a-root.md) ("Roads not taken"), [transitions](../reference/transitions.md), [ceremony record](../reference/ceremony-record.md) ("The hash chain"), [bundle](../reference/bundle.md) | commit `69ff9df`, 2026-11-13 | 2026-11-14 |
| A security reader's report on the root list, with probes it ran against the code, and the maintainer's decisions on two points (section 1) | internal, 2026-11 | 2026-11-14 |

The addresses are in the last section. Each statement below that comes from a source names it. A sentence that starts "Conclusion" is the author's.

## 1. The rules today and the weakness

- The list has a `sequence`: "an integer of at least 1 that grows by one whenever any trust file changes" (root list, table of members; record 0006, rule 14). An integer is at most 9007199254740991 (root list, "The list").
- A list with the same root keys carries one signature, by any active root key. A list that changes the root keys carries, for every current root key, its signature or its stored removal authorisation, and every added key signs it (root list, "Who signs"; record 0006, rule 18).
- Check 6: "`sequence` is not lower than the `sequence` of the list the host holds. Initial pins have no sequence." Refusal code `rollback`. Check 7: at the same sequence the bytes must be the same, or `sequence-conflict`. Check 11: the host's clock is before `expires_at`.
- A host that missed a list "takes the lists in between, in order, from where the holder publishes them. ritueel keeps every list in its numbered trust set, so every list can be published" (root list). A trust set is named with its number, for example `trust/13-3fa9c1d2/` (bundle page; the spelling is marked Proposed there).
- When the held list expires and no newer one has come, the host "keeps the list, goes on trusting its root keys, and raises a warning" (root list; record 0006, rule 21). Failing closed is a road not taken (record 0006).
- Until the first release, version 1 of the list is "rewritten in place"; after it, a change that can turn an accepted list into a refused one is a new version (root list, "Versioning").
- The security reader's probe: a host holds sequence 8 with root keys A and B; A alone signs sequence 9007199254740991; the host takes it; the honest list that revokes A is then refused, `rollback` at a lower sequence and `sequence-conflict` at the same one. The report says this was shown by probe.
- The same report shows a second case that no option below changes: with root key A, B's stored removal authorisation and a new key X, the list {A, X} signed by A and X, with B in `removals`, is accepted, and "the whole root set is replaced".
- Two points were decided by the maintainer after the commit that was read, and are now in [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 49 and 51, and on the root list page: a host refuses a list whose `expires_at` is not exactly 13 calendar months after `signed_at`, and a list whose `signed_at` is later than its clock; and an operator may give a lowest sequence beside the initial pins.

**What a thief's list can change.** A list with the same root keys has the same entries of `roots` (root list, "Who signs") and no `removals`. Conclusion: the thief's list differs from the honest one in the sequence, the two dates and the record digest, and the page does not make the host check the record digest after the first list (the report lists it as not enforced). The harm is not a wrong set of keys. It is that the host's number is out of reach of the honest holder, so a later list that changes the keys is refused. With the two date rules, such a list also expires at the latest 13 months after the thief's `signed_at`; the host then warns and keeps trusting the stolen key.

## 2. What other systems do

### The Update Framework (TUF)

Specification 1.0.37, read 2026-11-14. TUF's "root metadata" is the file that names the keys of every role. It is the closest thing to the root list.

| Question | What the specification says | Where |
|---|---|---|
| Is the version a counter that must rise? | "Clients MUST NOT replace a metadata file with a version number less than the one currently trusted." | 4.3, VERSION |
| May the root version jump? | No. "The version number of the new root metadata (version N+1) MUST be exactly the version in the trusted root metadata (version N) incremented by one, that is precisely N+1." Otherwise "discard it, abort the update cycle, and report the rollback attack." | 5.3 |
| May the version of other roles jump? | Yes. The timestamp version must be higher than the trusted one; an equal one is discarded "and it shouldn't raise any error"; the snapshot's entries for targets must be "less than or equal to" the new ones. | 5.4, 5.5 |
| Who signs a root step? | "(1) a THRESHOLD of keys specified in the trusted root metadata file (version N), and (2) a THRESHOLD of keys specified in the new root metadata file being validated (version N+1)." | 5.3 |
| How does a client catch up? | "The client MUST download intermediate root metadata files, until the latest available one is reached", with the file name `VERSION_NUMBER.FILENAME.EXT` (for example `42.root.json`), "up to" a number Y of files per cycle ("Y may be 2^10"). "All released versions of root metadata files MUST always be provided so that outdated clients can update to the latest available root." | 5.3, 6.2.1 |
| What about the expiry of the files in between? | "the expiration of the new (intermediate) root metadata file does not matter yet, because we will check for it in step 5.3.10." The check at the end: the trusted root's expiry must be later than the fixed start time of the update; if not, "abort the update cycle, report the potential freeze attack." Time is fixed once, at the start. | 5.1, 5.3 |
| Where does a client start? | "We assume that a good, trusted copy of this file was shipped with the package manager or software updater using an out-of-band process." The file is the root metadata, which has a `version` member. | 5.2, 4.3 |
| What are the attacks, in its words? | Fast-forward: "An attacker cannot arbitrarily increase the version numbers of metadata files … and thus tricking a software update system into thinking any subsequent updates are trying to rollback the package to a previous, out-of-date version." Rollback: "trick clients into installing software that is older than that which the client previously knew to be available." Indefinite freeze: "respond to client requests with the same, outdated metadata without the client being aware of the problem." | 1.5.2 |
| What does it promise about key compromise? | "An attacker, who is able to compromise a single key or less than a given threshold of keys, cannot compromise clients." | 1.5.2 |
| Recovery, root keys below the threshold | "revoke trust on the compromised keys … a normal rotation of root keys"; "When replacing root keys, an application will sign the new root.json file with both the new and old root keys." | 2.1.1, 6.1 |
| Recovery, root keys at the threshold | "the Root keys should be updated out-of-band, however, the threshold should be chosen so that this is extremely unlikely." | 2.1.1 |
| Recovery from a fast-forward | "If the timestamp and / or snapshot keys have been rotated, then delete the trusted timestamp and snapshot metadata files. This is done in order to recover from fast-forward attacks after the repository has been compromised and recovered." | 5.3 |
| What a freeze by withholding can do | An attacker who controls the repository "can launch freeze attacks by withholding new root metadata … these freeze attacks are limited by the expiration time of the latest root metadata available to the client." | 6.1 |

The Mercury paper (USENIX ATC '17, section 5) is the source the specification names for the fast-forward attack. It says fast-forward attacks "are not nearly as severe a threat as rollback attacks because they simply block a package from being installed", and "do not present a major threat so long as it is possible to recover from them securely". Its recovery: the online keys that sign the snapshot "can be revoked and replaced with new keys", and root metadata signed "using a quorum of offline keys" gives "a seamless and automatic recovery from fast-forward attacks after a repository compromise".

**Conclusion.** TUF has two tools. For its root it forbids the jump (N+1) and asks that every version be published. For the roles whose version a signer can raise, it allows the jump and recovers by a higher authority (the root keys) rotating the signer's keys, after which the client forgets its saved counter. TUF's own answer to "the keys that sign the root are compromised at the threshold" is out-of-band recovery, and it asks for a threshold high enough that this is "extremely unlikely". The root list asks for one key when the keys stay the same (record 0006, rule 18); a TUF root with a threshold of one would be in the same place. A higher threshold for every list would need both cards every year, which record 0006 says the alternation exists to avoid (the CRL road not taken). TUF's rule for root is the model for option A below, and TUF's rule for a fast-forward is the model for option E.

### Sigstore's trust root

Sigstore delivers its trust root through TUF (README of `root-signing`). It adds three facts. Its root metadata is version 16 on 2026-10-16, with 16 files `1.root.json` to `16.root.json` in `metadata/root_history`: every old root is kept and can be fetched by number. Its root role has threshold 3 of 5 keys (so does its targets role; snapshot and timestamp are 1 of 1). The README lists "a change to repository configuration (current keyholders, signature thresholds, etc)" as a reason for a signing event, with the keyholders signing "with their personal hardware keys". **Conclusion:** a live use of the same design keeps every root file by number and does not let one key sign a root version. Nothing else of Sigstore was read, so what its clients do after a bad version is the TUF rules above and no more.

### Certificate Transparency, signed tree heads

Only as far as it is the same problem. RFC 9162 (December 2021, Experimental).

- A log's signed tree head holds a `timestamp` and a `tree_size`, "the number of entries currently in the log's Merkle Tree" (4.9). "Each subsequent timestamp MUST be more recent than the timestamp of the previous update" (4.10).
- A consistency proof shows that the first m entries of a tree "are equal in both trees" (2.1.4). The log's endpoint refuses a request in which the second size "is smaller than first" (5.3). A TLS client "SHOULD also verify consistency between the provided STH and an STH it knows about" (8.1.5).
- Detecting a log that breaks the append-only rule is left to "gossip", which "is an active area of research and not defined here" (11.3).
- The text was searched for a sentence that says what a client does with a smaller tree size than the one it holds: none was found.

**Conclusion.** CT does not limit how far the number may jump. It binds a later tree to an earlier one by a proof, so that a log that signs two incompatible trees is shown to have done so. The part that is the same problem is option D below.

### Go's checksum database

The design note (2019) and the client code.

- The client keeps the latest signed tree size and hash. "No `go` command (only a manual `rm -rf $GOPATH/pkg`) will wipe out the memory of the latest observed tree size and hash. If the `go` command ever does observe a pair of inconsistent signed tree sizes and hashes, it will complain loudly on standard error and fail the build." (design note)
- "The client updates its cached N, T to those of the latest log, but only after verifying that the latest log includes everything from the current cached log." (tlog article) A server that lies to one client "must keep up the lie, forever serving an alternate log containing the lie." (tlog article)
- In `mergeLatestMem` (x/mod, master of 2026-11-14): a head with a size at or below the held one is checked against the held timeline, and if it is smaller the result is `msgPast` and nothing changes; a head with a larger size is first checked with `checkTrees(latest, …, tree, …)` and then installed. The comment on `checkTrees` says that on evidence of misbehaviour "it prepares a detailed message and calls log.Fatal."

**Conclusion.** A smaller signed head that fits the held timeline is the past, not an error. A larger one is taken only if it contains what the client saw. A head that does not fit is a fork: it stops the build, and the client's memory is removed only by hand. The way back for a client that holds a bad head is an operator's act, which is option F below. The sources read do not say how a client treats a signed head with an absurdly large size; this was not tried.

### Debian apt and the Release file

- A Release file has a `Date` and an optional `Valid-Until`. "Clients updating a local on-disk cache should ignore a Release file with an earlier date than the date in the already stored Release file." "Client behaviour on expired Release files is unspecified." (wiki)
- apt's code: a Release file whose `Date` is older than the held one is ignored and the held one is kept, "a prevention of downgrading us to older (still valid) files" (`acquire-item.cc`). A file is "not valid yet" before `Date − Max-FutureTime`, default 10 seconds, and "expired" after `Valid-Until`, and updates "will not be applied" in both cases (`debmetaindex.cc`, `acquire-item.cc`, `apt.conf(5)`). `Max-ValidTime`, if set, caps the validity after `Date`: "the earlier date of the two is used as the expiration date" (`apt.conf(5)`). The setting `Check-Date` is documented as the one that checks "that the Date field of a release file is not in the future".
- A Release file may name the keys that must sign the next one: `Signed-By`, "a client should only accept future updates to the repository that are signed with keys listed in the field" (wiki). The wiki does not say what recovers a client after a wrong value.

**Conclusion.** apt has no counter. Its order is the signed time, bounded by the clock (10 seconds ahead by default), so a signer cannot place its file ahead of every later honest file. The two date rules the maintainer has decided are of the same kind as the two apt applies (`Max-ValidTime` and `Max-FutureTime`). The signed time as the order is option G below.

### The systems side by side

| System | Is the version a counter that must rise? | May it jump? | Who signs for a jump | What brings a client back after a bad version |
|---|---|---|---|---|
| TUF root | Yes (4.3) | No, N+1 only (5.3) | Not applicable; each step needs a threshold of the old and of the new keys (5.3) | Rotation of root keys by both sets; at the threshold, out-of-band (2.1.1, 6.1) |
| TUF timestamp, snapshot, targets | Yes (5.4, 5.5) | Yes (5.4, 5.5) | The role's own threshold (5.4, 5.5) | Rotate the role's keys through the root, and delete the saved files (5.3) |
| Sigstore | As TUF | As TUF | Root: 3 of 5 | As TUF; nothing more was read |
| CT tree head | Not stated for the client; the log's timestamps rise (4.10) | Not limited; a proof binds new to old (2.1.4) | The log's one key | Not defined; gossip is not defined (11.3) |
| Go checksum database | A larger head must contain the held one; a smaller one that fits the held timeline is the past (client.go) | Yes, if the larger head contains the held one (client.go) | The log's one key | By hand (design note) |
| apt Release | No counter; the `Date` is the order, not in the future, an older one is ignored (wiki, code) | Not by a number; the `Date` is bounded by the clock (code) | The archive key | A later `Date`; no other rule was read |

## 3. The options for the root list

All options assume that the thief can put its list in front of the host first, as the report's probe does. **Conclusion:** a thief that answers every request of a host can also withhold honest lists; TUF says the same (6.1: a freeze by withholding is "limited by the expiration time"). With the two date rules decided, such a freeze lasts at most 13 months from the thief's `signed_at`, and then the host warns.

Reference case: a host holds list n with root keys A and B. The thief holds key A. "One key and one authorisation" means A and B's stored removal authorisation. The words "the page" mean the root list page.

### A. Take only the next sequence, or the same list again

- **The rule.** Check 6 becomes: the sequence is the held one or the held one plus one. This is TUF's N+1 for root (5.3). It is the security reader's first fix.
- **What it needs.** Every list reachable by its number where the holder publishes them. The page says ritueel keeps every list in a numbered trust set and leaves the published names to the holder. A rule on names would have to be written, as TUF does with `VERSION_NUMBER.FILENAME.EXT` (5.3, 6.2.1). Sigstore keeps 16 root files by number (section 2).
- **A host behind by several lists.** It asks for n+1, n+2, … until none is there, as TUF does, with a limit of files per run (TUF's Y; its example is 2^10). Each step is checked against the list before it (checks 2, 8 and 10 already read the held list).
- **The lists in between and their expiry.** Today check 11 applies to every list a host takes, so a host cannot take an expired list, even if a later list is valid. Conclusion: with the next-only rule that is a stop. Lists are signed at least yearly and expire after 13 months, so a host that has not fetched for more than 13 months after the list that follows its held one was signed cannot take that list, and so cannot take any later one. Today the host compares the newest list with its held one and does not need the lists in between, except when the keys changed. TUF's rule would remove the stop: check the expiry only on the newest list at the end of the walk, with the clock fixed at the start (5.1, 5.3). Here that means moving check 11 to the end. The two date rules that the maintainer has decided are not expiry checks and could stay on every list.
- **A host with only initial pins.** It has no sequence (check 6). With a lowest sequence N beside the pins, its first list may be any number from N on; a first list at the highest number is still taken, because the report shows a first list accepted on one signature. Conclusion: option A does not protect a host at its first list. TUF starts from a shipped root file, which carries its version (5.2, 4.3). The page already lets the command start from a held list instead of pins (`--held FILE`); an operator who installs the list, and not only the pins, gives the host a sequence to step from.
- **A thief with one key.** It can sign n+1 with the same keys, and nothing higher in one step, so the highest-number freeze is gone. If the honest holder's n+1 changes the keys (revokes A) and a host took the thief's n+1 first, the honest n+1 is refused with `sequence-conflict`; the holder must make a list n+2. A thief that answers every request of the host can serve its own n+1, n+2, … one signature each, and the host takes them all, because each step is valid. Conclusion: A limits a thief that adds one file, not one that serves the whole walk.
- **A thief with one key and one authorisation.** It can still replace the set at n+1. No option here changes that.
- **Host, holder, vectors.** The host needs the walk, a new refusal code for a gap, and the clock rule above. The holder publishes every list by number. The vectors need cases for n+1, n+2, the same list again, a gap after a long walk, and an expired list in the middle.
- **Fit with "full TUF is not used".** It takes one rule of TUF, N+1 for root. It adds no roles and no thresholds. It fits.

### B. Take a list at most a fixed distance ahead

- **A host behind, pins, expiry.** No walk is needed for a gap within the distance. The rest is as in A.
- **A thief with one key.** It signs n+D. The honest list n+1 is then `rollback`, so the freeze is back, shorter by D lists. Conclusion: the honest list n+1 is still lower than the thief's n+D, so the holder needs D more lists to catch up, and the sequence grows by one at each change (at least once a year). A distance of 1 is option A.
- **One key and one authorisation.** As in A.
- **Host, holder, vectors.** A new number in the rules; no rule on names; vectors for the edge.
- **Fit.** A number that TUF does not have; the Mercury paper does not give one. It does not recover.

### C. A jump of more than one needs every current root key

- **The rule.** As A for a step of one. A larger step must carry the signature of every current root key, like a change of keys.
- **A thief with one key.** As in A.
- **One key and one authorisation.** If a stored authorisation counts for a jump, as it does for a change of keys, the thief signs {A}, with B in `removals`, at the highest number, and holds both the set and the number. If only signatures count, the thief can step by one and replace the set at n+1, as in A.
- **Host, holder.** A host far behind still walks, unless the holder spends a ceremony with every card to make a list that lets it jump. Record 0006 says that needing both cards every year is what the alternation exists to avoid (the CRL road not taken).
- **Vectors.** Cases for a jump with and without all signatures.
- **Fit.** It reuses the page's rule for a change of keys and TUF's idea that a step needs the old keys. It adds little over A.

### D. Bind the list to the digest of the list before it

- **The rule.** A new member names the digest of the previous list's `root-list.json`, so the lists form a chain, as the ceremony records do (`prev_record_sha256`; ceremony record page, "The hash chain"). The existing `last_record_sha256` anchors the ceremony records, not the lists. A host checks the link to the held list.
- **A host that missed lists.** It must have every list between to check each link, so it walks as in A. The chain adds nothing to the walk.
- **A thief with one key.** The previous list is a public file, so the thief can name its digest; the chain stops a jump only by making the thief produce every list in between, one signature each, as in A. A fork is new here: if a host took the thief's n+1, the honest n+2 names the honest n+1 and is refused until a list names the thief's n+1. Conclusion: a chain detects a fork and does not heal it, which is what the Go design note says of its own timeline ("it will complain loudly … and fail the build"; only a hand act clears it). The holder would have to name a list it did not write.
- **One key and one authorisation.** As in A.
- **Host, holder, vectors.** A member and a refusal code; the list's bytes in the plan; vectors for a broken link and a fork.
- **Fit.** It is closer to CT and the Go checksum database than to TUF. It does not need roles or thresholds.

### E. A way back signed by every other current root key

- **The rule.** A list that removes at least one root key of the held list is not refused for its sequence (checks 6 and 7), if it passes checks 8 to 10 as they are: every root key of the held list has signed it or, if the list removes it, has its authorisation in `removals`; every added key signs it. The list then becomes the held list, with its own sequence. This is the shape the page already gives to `revoke`: "signed by the other root keys and carrying its removal authorisation" (transitions page). It is a rule of the same kind as TUF's recovery from a fast-forward: after the keys are rotated, the client deletes its saved counter (5.3).
- **What stops it from being a rollback tool.** Conclusion, not tried: an old list cannot remove a key of the held list unless that key signed it or has its authorisation in it. A key added after the old list cannot have an authorisation in it. A removed key is not on the held list, unless a removed key can be added again. The page says "a label … is never reused" (root list) but does not say whether a removed key's pin can be added again; this is to be checked.
- **A host behind by several lists.** No change: a list that changes the keys still needs the held list's keys to have signed it (checks 8 and 10).
- **A host with only initial pins.** The host takes a first list from the pins; if that was the thief's, the same way back applies to it. The pins need no lowest sequence for this.
- **A thief with one key.** It can still set the number and freeze the host against a list that keeps the same keys. It cannot stop a list that removes its own key: that list needs the other keys and the stolen key's stored authorisation, not the stolen key. The freeze is visible: with the two date rules the held list expires within 13 months and the host warns.
- **A thief with one key and one authorisation.** It can replace the set, with any sequence. This was true before, at a sequence at or above the held one. If the thief adds its own key X, the holder cannot remove X without X's signature or authorisation, so the host needs its pins again. The option does not change this.
- **Host, holder, vectors.** The host: the sequence check moves after the signer checks for such lists. The page's reason for its order of checks ("a replayed or conflicting list is refused for what it is before its signers are weighed", "Choices made") must be reconsidered for them. The holder: nothing new at a ceremony, because `revoke` and retire already write this list. The vectors: the freeze and the way back; every old list against every held list; a list that removes nothing at a lower sequence (refused); a missing authorisation (refused).
- **Fit.** One TUF rule (rotation resets the saved counter); no roles, no thresholds above what the page has.

### F. Leave it, and write the way back for the operator

- **The rule.** None in the list. The page would say the way back: the operator gives the host pins again, without the stolen key, and removes its held list. Today the page names the channel for a host with no list; it does not say how a host with a list is reset.
- **A thief with one key.** It freezes the host until the operator acts; the stolen key's pin is left out of the new pins, so its list is refused (check 2). With the two date rules the held list expires within 13 months and the host warns, but keeps trusting the stolen key until reset (record 0006, rule 21).
- **One key and one authorisation.** As in every option: the operator's pins are the only way back.
- **Host, holder, vectors.** The host: a manual step per host. The holder: nothing. Vectors: none. Record 0007 lists "a lost root removed from each host by hand" as a road not taken: "every host's pins need replacing out of band". The Go design note takes the same road ("only a manual `rm -rf $GOPATH/pkg`").
- **Fit.** TUF's rule for a threshold of root keys compromised (out-of-band, 2.1.1). It fits TUF. Record 0007 has already declined the same road for a lost root key.

### G. The order is the signed time, as in apt (the author's reading of apt)

- **The rule.** The host takes a list whose `signed_at` is later than the held one's (and the same list again), and the sequence stops being the order. With the decided rule that `signed_at` is not later than the clock, the thief cannot pick a later time than the host's clock. This is apt's rule: ignore an older `Date`, refuse a `Date` in the future.
- **A host behind, pins.** No walk. A host with pins takes a first list at once.
- **A thief with one key.** It signs with `signed_at` equal to the host's clock and the host takes it; an honest list signed earlier is refused, and the holder must sign again later. Conclusion: this is the same race as in A, without a number to run away with, and without a walk. A host whose clock is ahead of the true time gives the thief the same lead.
- **One key and one authorisation.** As in A.
- **Host, holder, vectors.** Record 0006, rule 14, says that a hand-off answer names its sequence and that the requester "holds a root list at least that recent before it installs", so the order of lists reaches the contract; the contract was not read for this note, so what changes there is open. The vectors: all cases of order turn from the sequence to the time.
- **Fit.** It is not TUF. It uses the clock the host already must have for the two date rules.

### The options by what a thief can still do

| Option | A thief with one key | A thief with one key and one stored authorisation |
|---|---|---|
| Today, with the two date rules | Freezes the host at the highest number; no honest list can follow; host warns after at most 13 months and keeps trusting the key | Replaces the set, any number; pins needed |
| A. Next sequence only | One step only. A thief that serves the whole walk freezes it again | Replaces the set at n+1; pins needed |
| B. Fixed distance | Sets n+D; freeze for D lists | As A |
| C. Jump needs every key | As A. | If authorisations count for a jump: set and number; if not, as A |
| D. Chain | As A, and a fork the holder cannot heal alone | As A |
| E. Way back | Freezes same-key lists only; cannot stop a list that removes its own key | Replaces the set, any number; pins needed |
| F. Leave it | Freezes until the operator resets the host | Pins needed |
| G. Order by signed time | Beats an earlier honest list once per host, until the holder signs later | As A |

## 4. What each option does to the project's own rules

| Option | Host | Holder at a ceremony | Test vectors | Fit with "full TUF is not used" |
|---|---|---|---|---|
| A | Walk by number; clock check moves to the end; new code | Publishes every list by number | Gap, step, same again, expired in the middle | Yes: one rule |
| B | One number | Nothing | Edge of the distance | Yes, but no source |
| C | As A | May spend every card to let hosts jump | Jump with and without all signatures | Yes |
| D | As A, plus a link check | The previous digest into the plan | Broken link, fork | Yes, but not TUF |
| E | Order of checks changes for key-removing lists | Nothing new | Freeze then way back; replay matrix | Yes: TUF's recovery rule only |
| F | Manual reset, page text | Nothing | None | Yes: TUF's out-of-band rule |
| G | Time decides; hand-off check to read | Nothing | Order turns to time | Not TUF; apt's rule |

## 5. What this means for the project

**Recommendation: option E, as the way back for a stolen root key; and the page says F for the case E cannot reach.** Options B, C and D add a rule and do not recover; A and G limit a thief that adds one file but do not recover from a freeze, and A costs a numbered publishing rule and a walk.

**The one deciding fact.** To remove a root key the page already asks for every other key's signature, or the removed key's stored authorisation (root list, "Who signs"; transitions, `revoke`). One stolen key cannot do that. A list that clears this bar may therefore also reset the host's counter. TUF does the same where its root keys rotate a role's keys and the client deletes its saved counter (5.3). The other options try to stop the thief from raising the number, which the page cannot do while one key signs a renewal; E makes the number harmless to the one list that matters, the one that removes the key.

What this does not fix, and the page should say:

- one stolen key plus one stored authorisation replaces the root set under every option; the report asks the page to say that the protection is only as strong as the secrecy of the authorisations;
- a freeze against lists that keep the same keys, until the holder removes the stolen key;
- a host that only has initial pins takes its first list on one signature; that is outside this question, and an operator who installs the held list and not only the pins avoids it (TUF ships the root file, 5.2).

## 6. What must be tried before E is relied on

1. A replay matrix: build a history of many ceremonies (add, retire, revoke, same keys) with three or more root keys, and offer every list in it against every held list of it, with initial pins too. No list older than the held one may pass except an honest list that removes a key. Check also whether a removed key's pin can be added again; if it can, the argument in E fails for that case.
2. The report's probe as a vector: A signs the highest sequence; the honest revoke list (signed by B, A's authorisation in `removals`) must be accepted; the same from initial pins.
3. A list at a lower sequence that removes nothing must stay `rollback`; a key-removing list with a missing or wrong authorisation must stay `insufficient-signers` or `removal-invalid`.
4. The thief with one key and one authorisation must not gain more than the page's takeover case, now at any sequence.
5. The order of the checks: which code a key-removing list gets when two checks fail; the page's reason for the order must be rewritten.
6. What a requester of the hand-off contract does when the sequence of the held list goes down after a way back. This note did not read the contract.
7. If A is also wanted: a host that walks 20 lists with an expired one in the middle, with the clock fixed at the start.

## What this does not show

- Nothing was run. No host, no list and no probe was tried by the author; the report's probes are the report's.
- Option E's safety against replay is an argument from the page's rules, not a test (section 6).
- The Chromium CRLSet header says "the monotonic sequence number of this CRL set"; the rule a browser applies to a lower one was not found in the files read. Mozilla's CRLite and Remote Settings were not read.
- Sigstore's client rules and the code of any TUF client (python-tuf, go-tuf) were not read; TUF is read at its specification.
- For CT only RFC 9162 was read, not the browser policies or the gossip drafts; no sentence on a client facing a smaller tree head was found.
- The Go client was read at `master`, not at a release; the design note is from 2019.
- apt's behaviour was read in source and the manual page, not run.
- Records 0001 to 0005 and 0008 to 0011 and the hand-off contract of ritueel were not read for this note.
- The report's two proposed fixes were read in the report and compared with the sources; the report's numbers were not repeated.
- The time a thief needs, and the cost of a ceremony, were not measured.

## Changes made

None.

## Sources read on 2026-11-14

| What | Address |
|---|---|
| TUF specification 1.0.37 | <https://theupdateframework.github.io/specification/latest/> |
| Mercury paper, USENIX ATC '17 | <https://www.usenix.org/system/files/conference/atc17/atc17-kuppusamy.pdf> |
| Sigstore root-signing | <https://github.com/sigstore/root-signing> (`README.md`, `metadata/root.json`, `metadata/root_history/`) |
| RFC 9162 | <https://www.rfc-editor.org/rfc/rfc9162> |
| Go checksum database design note; tlog article; client code | <https://go.googlesource.com/proposal/+/master/design/25530-sumdb.md>, <https://research.swtch.com/tlog>, <https://github.com/golang/mod/blob/master/sumdb/client.go> |
| Debian wiki, apt source, apt.conf(5) | <https://wiki.debian.org/DebianRepository/Format>, <https://salsa.debian.org/apt-team/apt/-/blob/main/apt-pkg/acquire-item.cc>, <https://salsa.debian.org/apt-team/apt/-/blob/main/apt-pkg/deb/debmetaindex.cc>, <https://manpages.debian.org/testing/apt/apt.conf.5.en.html> |
| Chromium CRLSet format comment | <https://chromium.googlesource.com/chromium/src/+/main/net/cert/crl_set.cc> |
