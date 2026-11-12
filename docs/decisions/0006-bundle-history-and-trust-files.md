# 0006 — A bundle is one trust domain; a person writes only wanted files, its history is write-once and its trust files are numbered sets

**Status:** Accepted
**Date:** 2026-11-12

## Decision

1. A bundle is a directory of plain files with a fixed structure. It holds all that ritueel knows about one trust domain: the wanted files, the root keys' certificates, public keys and attestations, digests of the revocation signatures, the trust files, the sealed card secrets and the wrapped backup of a person's encryption subkey. It never holds a private key in clear, a PIN the holder types, a passphrase, or a revocation signature itself. It is no longer public material only.
2. One bundle is one trust domain, with its own history and hash chain, trust sequence, root list and one root of each kind it uses. The keys of a root are labelled A and B, then the next letter. A holder with a personal key and a company keeps two bundles, with nothing of the person in the company's files.
3. Across bundles a root key is written with the bundle's name (`acme/A`); inside a bundle it is `A`. A bundle is named by its directory; the flag stays `--dir`.
4. The word "bundle" always means the directory. The trust file is always "the CA bundle". On the site, in the pages and in contract names, "directory" or "folder" in that sense becomes "bundle".
5. The history is the write-once part of the bundle: the folder `history/`, with one ceremony folder per ceremony. It holds the plan, copies of the wanted files used, the attempt, the journals, the transcript and the ceremony record, which names the one before it. ritueel needs no git. A sealed single-file form for backups that reveals nothing comes later.
6. A ceremony record is a JSON file, written last in its ceremony folder, with the time in UTC, the command, the plan digest, the wanted files and the artifacts with their digests, the keys and stores, the evidence checked, the policy applied, the slot map version and the confirmation; it holds no secret. Ceremony records form a hash chain checked by the history check. A root does not sign them. The digest of the end of the history goes into the next signed root list, which anchors the chain without another use of the root.
7. The transcript is what ritueel printed, written by ritueel, never a capture of the terminal. A saved plan is written by the running process inside the bundle at `history/<ceremony>/plan.json` (with `--plan-only`), not in a pending area and not as a loose file.
8. ritueel stores the OpenPGP creation time of every key it makes or binds: for a KMS key as a key tag and in every published certificate, for an adopted key only in the bundle and the certificate.
9. After every ceremony and every join ritueel prints the end of the history: eight characters and the count of ceremony records. Advice to the holder, not enforced: keep the bundle in a git repository of its own, with signed commits and review before a change lands; back it up to a second remote on another provider; keep that print apart from the repository. The bundle is part of every key's identity, as it holds the OpenPGP creation times. Losing it is a loss, and the backup is practised.
10. Requests and answers sit together in `requests/<name>/`: the request and, once given, its answer.
11. A person writes only wanted files, only on the workstation: `ritueel.yaml` and one strict YAML file for each object. Everything the program writes is JSON or a standard format. A card's files are named by a name the holder gives, not by its serial.
12. The trust files are written as numbered trust sets, one per change. A set holds the root list, the CA bundle, the CRLs, the SSH CA key list and the public OpenPGP keyring (the public certificates of the root keys and their subkeys). A personal bundle has no root list or CA bundle, so its set is just the person's public certificate.
13. ritueel builds the trust files outsiders install: CA bundles, signed root lists, SSH CA key lists and the keyring file of release keys, which the release pipeline packages. The user's own pipeline publishes them. ritueel changes only your bundle. The one thing it may send out is your public OpenPGP key, to the keyservers you list. For everything else it prints what to do ([0011](0011-publishing-and-what-to-do-after-a-ceremony.md)). No certificate carries a CRL distribution point.
14. The trust sequence is one integer per bundle that grows by one whenever any trust file changes. Every trust file carries it: root list and SSH CA key list as their sequence member, CA bundle in a comment line, a CRL as its CRL number, the keyring package in its version. There is no second counter. A hand-off answer names its sequence, and the requester holds a root list at least that recent before it installs.
15. The root list holds the active root keys, each pinned by the SHA-256 of its SubjectPublicKeyInfo and, for OpenPGP, the primary's fingerprint; the sequence; the signing time; the expiry; the digest of the end of the history. Its members keep the names `roots` and `label`. It pins keys, never certificates. It and the SSH CA key list are signed with an X.509 root key, because their audience, lifetime, revocation and callers are those of the root.
16. A list with the same root keys is signed by any one active root key, the one used at that ceremony. A list that changes the root keys carries, for every active root key of the list it replaces, that key's signature or its stored removal authorisation, and every key it adds signs it. Adding, retiring and revoking a root key all change them.
17. The removal authorisation is a statement each root key signs over its own pin when it is born, kept with the revocation material. A root key that can no longer sign leaves the set with it.
18. The root list is re-signed at every yearly ceremony and every transition, so at least once a year. It expires 13 months after signing; status warns at 60, 30 and 14 days before. A missed yearly ceremony is visible to every host after 13 months, not only to the holder.
19. A host refuses a list with a lower sequence than the one it holds; a list with the same sequence whose content differs (only the same list again is accepted); a bad signature; a list no active root key of the held list has signed; a change of root keys lacking every current root key's signature or removal authorisation; and an expired list. When the held list expires and no newer one arrived, the host keeps the last good list and raises a warning. It does not drop its roots.
20. Full TUF, with separate roles and thresholds, is not used.
21. Hosts trust a signed, versioned list of SSH CA public keys. The SSH CA keys of a system that holds delegations stay with that system, as an SSH CA key is an anchor, not a chain. The break-glass SSH CA is ritueel's own root of the kind SSH CA, held offline like the other root keys.
22. The SSH CA key list holds those system keys and the break-glass SSH CA keys of the root keys that keep one. It carries the trust sequence, has the same expiry and host rules as the root list, takes ECDSA P-384 keys only, and nobody edits it.
23. A system's SSH CA key enters by a third hand-off request type, `ssh-ca-key`: the public key as an OpenSSH line, an SSH signature as proof of possession, the same proof file of where the key lives. ritueel checks it, a person confirms it, and the key, a delegated key, is listed under a delegation the operator declared with that type. The answer says the key is listed (nothing to certify).
24. Each SSH CA key has a use, user or host, asked in the request and fixed by the operator's declaration, so a host never trusts a user CA as a host CA or the reverse.
25. A break-glass SSH CA key is made by ritueel in the store of its root key when that key is born, and leaves the list with it. An SSH CA key is withdrawn by the next list. There is no revocation signature for it, and the list may be empty.
26. An intermediate certificate is revoked by a CRL, one per issuing root key. A root key signs its CRL at every ceremony in which it signs, and when it is born (empty if nothing is revoked); the CRL of every other active root key is copied unchanged beside it. A CRL is valid for 25 months, and its CRL number is the trust sequence. An entry lasts until the certificate it names expires (at most 13 months). OpenPGP is not covered by CRLs.
27. The CA bundle is the certificates of the active X.509 root keys in one PEM file, with the trust sequence in a comment line. The same keys in the same order give the same bytes.
28. The exact members, encoding and signature format of each trust file are reference pages with test vectors. They follow this design and cannot change it.
29. A ceremony only adds files, each named by its identity (a digest or a time) and written whole or not at all: under a temporary name, then one rename ([steps](/reference/bundle/)). A listed file that fails its digest is an error, never absent.
30. Coming back from the stick is a join: ritueel adds the missing files and never merges text. Two ends of the history are a fork, a critical finding. Two answers to one request stop the join.

## Why

A holder must prove what was done, and outsiders must check the roots. One bundle per trust domain keeps a person's files apart from a company's. A write-once history shows a rewritten ceremony. One trust sequence and an expiry on every list let a host tell a current set from a stale one.

## What it costs

- The bundle holds sealed secrets, so it must be guarded and backed up.
- A change of the root set needs more signatures than a renewal.
- The root list must be re-signed once a year.
- The word "bundle" must be renamed across the site, pages and contract names.

## Roads not taken

- **Several trust domains in one bundle.** One set of card files, but it needs a layer between bundle and root, renames the keys A and B, and mixes a person's files with a company's.
- **The bundle name is the root name.** Shorter, but a host pins A and B one by one, so `acme/A` names the root exactly.
- **Keep the word "directory".** No rename, but key, revocation and working directories are directories too.
- **Another word (dossier, vault, book, home, realm).** No clash with the CA bundle, but the maintainer chose "bundle" and accepted the cost.
- **A hosted history.** Nothing to back up, but a service every ceremony trusts, and ritueel has none.
- **The older name for the history.** Unclear to the maintainer; `history/` is clear.
- **Sign each record with the root.** A third party could check a record, but it is a third use of the root and one more touch.
- **Capture the terminal as the transcript.** Complete and free, but it can hold what was typed.
- **The word "products" and a folder of that name.** Unclear to the maintainer.
- **Requests and answers in separate places.** The maintainer wants answered and waiting requests seen in one place.
- **A counter per trust file.** Each moves alone, but a requester would need three numbers to tell whether it is current.
- **Pin root certificates.** Easier to compare, but the yearly re-issue would break every pin.
- **A separate key for the list and the SSH CA keys.** Separates their signer, but costs a slot and a touch for a key with the same audience, lifetime and revocation.
- **Any one active root changes the root set, as it renews the list.** One signature for every list, but the trusted set would rest on one root.
- **Every current root signs a change of the set, with no stored authorisation.** Simplest strict rule, but a lost root could never leave the set by a signature and every host would need its pins replaced by hand.
- **A separate key for changes of the root set.** Keeps renewals and changes apart, but one more slot and touch per root for a key with the same audience.
- **A root list with no expiry.** Nothing to renew, but a list that stopped being signed cannot be told from a current one.
- **Accept any list at an equal sequence.** Simpler, but two different root sets could carry one sequence.
- **Fail closed when the list expires.** Stronger on paper, but a missed ceremony would cut every host off its roots at once.
- **Full TUF.** Mature freeze and rollback protection, but standard verifiers cannot count signatures and one holder cannot staff separate roles.
- **The operator edits the SSH CA key list.** No request to write, but a key would be trusted that nothing checked and the list would have a second author.
- **Version 2 of the hand-off contract, or a contract of its own, for the SSH CA key type.** Keeps version 1 as written, but nothing is released so no receiver is surprised, and a second version costs every reader a second code path.
- **A key that does both user and host certificates.** One key fewer, but its holder can vouch for hosts as well as users.
- **OCSP for an intermediate.** Live status, but it needs a responder that signs online, which ritueel never holds, and a certificate that names it.
- **A CRL distribution point in the intermediate's certificate.** Clients could fetch alone, but the certificate would name a host that outlives it and TLS libraries do not fetch it by default.
- **One CRL for both roots, signed by the root of the year.** One file, but standard clients take a CRL from the issuer only and indirect CRLs are poorly supported.
- **Both roots sign their CRL at every ceremony.** A 13-month CRL like the root list, but it needs both cards every year, which the alternation exists to avoid.
- **Revoked intermediates in the root list.** One signed file, but the list pins keys and would grow with every renewal.
- **One wanted file for everything.** The fewest files, but every edit touches the one file, so any edit makes every saved plan stale, and a proposed change would have to change the middle of a text; one file for each object was chosen.
- **One folder for each object.** A file listing would be the inventory, but certificates and sealed secrets would exist twice and deleting a folder would delete its history; one file for each object and the history folders were chosen.
- **The history in one append-only file, such as a tar archive or a log.** One thing to carry, but an append that was cut off must be repaired by editing a write-once file, and plans and certificates would stay files anyway; one ceremony folder for each ceremony stays (rule 5).
- **A Merkle tree over the history.** A short proof for one entry, but it helps only when someone outside remembers an earlier tree, and ritueel has no such party (a hosted history is a road above); every checker holds the whole history. It can be built later from the stored ceremony records.
- **A storage engine (an LSM store, a B-tree file or SQLite) as the source of truth.** Made for speed and size, but a company bundle gets a few ceremony records a year, and an engine breaks "a directory of plain files" (rule 1) and a join that only adds files.
- **Git as the way back from the stick.** Nothing to build, but "ritueel needs no git" (rule 5) and a holder without git would have no way back; the join (rule 30) does it.
- **A store of every old text of a wanted file, now.** Undo without git, but about eight more commands; the exact copies in each ceremony folder (rule 5) and git (rule 9) cover the need until it is built. It is later, not refused.
- **Merge the text of two copies at the join.** One result, but a merge of a signed answer or of a history would decide which one is true; the join adds files only and shows a fork (rule 30).
- **A name that does not carry its identity.** Short names such as a plain counter, but two copies could hold two contents under one name and the join would no longer be a union; every name carries its identity (rule 29).

## Not yet proven or only proposed

- **Proposed.** The exact member names inside the folders (plan, copies of the wanted files, attempt, birth journal, journal of signatures, transcript, ceremony record, card files, card maps, sealed card files) and the names of the wanted files and their folders are fixed with the code and the card proofs. No file stores the bundle's name; `name` in `ritueel.yaml` is the name in the root keys' subjects, and whether it must differ between bundles is open ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** Each bundle's card files list the cards for its own rows; the list of rows may be empty, and a card used only for the passkey is listed with applications `[fido2]` ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** The rules a request is checked against are split: store, firmware, PIN and validity in policy; name constraints and KMS read roles in each declared delegation's wanted file ([#9](https://github.com/truvity/ritueel/issues/9)).
- **Proposed.** The repair of a fork: one ceremony record that names every end, a root list signed only when the history has one end, and a result from the stick that counts only after a join has checked it ([#138](https://github.com/truvity/ritueel/issues/138)). What a host does when it is several root lists behind is not said either ([#139](https://github.com/truvity/ritueel/issues/139)).
- **Proposed.** What `acme/A` names when one letter labels the keys of several roots in a bundle ([#137](https://github.com/truvity/ritueel/issues/137)).

## Replaces

Parts of 0001, 0003, 0004, 0005, 0006, 0007, 0009, 0010, 0015, 0016 and 0018, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
