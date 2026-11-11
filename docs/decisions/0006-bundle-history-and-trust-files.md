# 0006 — A bundle is one trust domain; its history is write-once and its trust files are numbered sets

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. A bundle is a directory of plain files with a fixed structure. It holds all that ritueel knows about one trust domain: configuration, the card inventory, the roots' certificates and public keys with attestations, digests of the revocation signatures, the trust files, the card secrets sealed to the holder's recipients, and the wrapped backup of a person's encryption subkey. It never holds a private key in clear, a PIN the holder types, a passphrase, or a revocation signature itself. It is no longer public material only.
2. One bundle is one trust domain, with its own history and hash chain, trust sequence, root list and roots. Roots are labelled A and B, then the next letter. A holder with a personal key and a company keeps two bundles, and nothing of the person is in the company's files.
3. Across bundles a root is written with the bundle's name (`acme/A`); inside a bundle it is `A`. A bundle is named by its directory; the flag stays `--dir`.
4. The word "bundle" always means the directory. The trust file is always "the CA bundle", and its command is `ca-bundle build`. On the site, in the pages and in contract names, "directory" or "folder" in that sense becomes "bundle".
5. The history is the write-once part of the bundle: the folder `history/`, with one sub-folder per ceremony holding the plan, attempt, record, transcript and birth journal, each naming the one before it. ritueel needs no git. A sealed single-file form for backups that reveals nothing comes later.
6. A record is a JSON file in the ceremony's sub-folder of `history/`, with the time in UTC, the command, the plan digest, the keys and stores, the evidence checked, the policy applied, the artifacts with their digests, the slot map version and the confirmation; it holds no secret. Records form a hash chain checked by `records verify`. A root does not sign them. The digest of the last record goes into the next signed root list, which anchors the chain without another use of the root.
7. The transcript is what ritueel printed, written by ritueel, never a capture of the terminal. A saved plan is written by the running process inside the bundle at `history/<ceremony>/plan.json` (with `--plan-only`), not in a pending area and not as a loose file.
8. ritueel stores the OpenPGP creation time of every key it makes or binds: for a KMS key as a key tag and in every published certificate, for an adopted key only in the bundle and the certificate.
9. Advice to the holder, not enforced: keep the bundle in a git repository of its own, with signed commits and review before a change lands; back it up to a second remote on another provider; keep the digest of the last record apart from the repository. The bundle is part of every key's identity, as it holds the OpenPGP creation times. Losing it is a loss, and the backup is practised.
10. Requests and answers sit together in `requests/<name>/`: the request and, once given, its answer.
11. One file is written by a person: `ritueel.yaml`. Everything the program writes is JSON or a standard format. A card's files are named by a name the holder gives, not by its serial.
12. The trust files are written to `trust/<number>/`, one numbered set per change: the root list, the CA bundle, the CRLs, the SSH CA key list and the public OpenPGP keyring (the public certificates of the roots and their subkeys). A personal bundle has no root list or CA bundle, so its trust set is just the person's public certificate.
13. ritueel builds the trust files outsiders install: CA bundles, signed root lists, SSH CA key lists and the keyring file of release keys, which the release pipeline packages. The user's own pipeline publishes them. ritueel publishes nothing, and no certificate carries a CRL distribution point.
14. The trust sequence is one integer per bundle that grows by one whenever any trust file changes. Every trust file carries it: root list and SSH CA key list as their sequence member, CA bundle in a comment line, a CRL as its CRL number, the keyring package in its version. There is no second counter. A hand-off answer names its sequence, and the requester holds a root list at least that recent before it installs.
15. The root list holds the active roots, each pinned by the SHA-256 of its SubjectPublicKeyInfo and, for OpenPGP, the primary's fingerprint; the sequence; the signing time; the expiry; the digest of the last ceremony record. It pins keys, never certificates. It and the SSH CA key list are signed with an X.509 root key, because their audience, lifetime, revocation and callers are those of the root.
16. A list with the same roots is signed by any one active root, the one used at that ceremony. A list that changes the root set carries, for every active root of the list it replaces, that root's signature or its stored removal authorisation, and every root it adds signs it. `root add`, `root retire` and `root revoke` all change the root set.
17. The removal authorisation is a statement each root signs over its own pin when it is born, kept with the revocation material. A root that can no longer sign leaves the set with it.
18. The root list is re-signed at every yearly ceremony and every transition, so at least once a year. It expires 13 months after signing; status warns at 60, 30 and 14 days before. A missed yearly ceremony is visible to every host after 13 months, not only to the holder.
19. A host refuses a list with a lower sequence than the one it holds; a list with the same sequence whose content differs (only the same list again is accepted); a bad signature; a list no active root of the held list has signed; a root-set change lacking every current root's signature or removal authorisation; and an expired list. When the held list expires and no newer one arrived, the host keeps the last good list and raises a warning. It does not drop its roots.
20. Full TUF, with separate roles and thresholds, is not used.
21. Hosts trust a signed, versioned list of SSH CA public keys. The SSH CA keys of a system that holds intermediates stay with that system, as an SSH CA key is an anchor, not a chain. The break-glass SSH CA is ritueel's own key, held offline like a root.
22. The SSH CA key list holds those system keys and the break-glass SSH CA of each root card or the cloud root account. It carries the trust sequence, has the same expiry and host rules as the root list, takes ECDSA P-384 keys only, and nobody edits it.
23. A system's SSH CA key enters by a third hand-off request type, `ssh-ca-key`: the public key as an OpenSSH line, an SSH signature as proof of possession, the same proof file of where the key lives. ritueel checks it, a person confirms it, and the key is listed under the name of an intermediate the operator declared with that type. The answer says the key is listed (nothing to certify).
24. Each SSH CA key has a use, user or host, asked in the request and fixed by the operator's declaration, so a host never trusts a user CA as a host CA or the reverse.
25. A break-glass SSH CA key is made by ritueel in the store of its root when the root is made, and leaves the list with its root. An SSH CA key is withdrawn by the next list. There is no revocation signature for it, and the list may be empty.
26. An intermediate certificate is revoked by a CRL, one per issuing root. A root signs its CRL at every ceremony in which it signs, and when it is made (empty if nothing is revoked); the CRL of every other active root is copied unchanged beside it. A CRL is valid for 25 months, and its CRL number is the trust sequence. An entry lasts until the certificate it names expires (at most 13 months). OpenPGP is not covered by CRLs.
27. The CA bundle is the root certificates of the active roots in one PEM file, with the trust sequence in a comment line. The same roots in the same order give the same bytes.
28. The exact members, encoding and signature format of each trust file are reference pages with test vectors. They follow this design and cannot change it.

## Why

A holder must prove what was done, and outsiders must check the roots. One bundle per trust domain keeps a person's files apart from a company's. A write-once history shows a rewritten ceremony. One trust sequence and an expiry on every list let a host tell a current set from a stale one.

## What it costs

- The bundle holds sealed secrets, so it must be guarded and backed up.
- A change of the root set needs more signatures than a renewal.
- The root list must be re-signed once a year.
- The word "bundle" must be renamed across the site, pages and contract names.

## Roads not taken

- **Several trust domains in one bundle.** One card inventory, but it needs a layer between bundle and root, renames A and B, and mixes a person's files with a company's.
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

## Not yet proven or only proposed

- **Proposed.** The exact member names inside the folders (plan, attempt, record, transcript, birth journal, card inventory, per-card files, sealed card files, the "adopted" member of the root file) are fixed with the code and the card proofs. No file stores the bundle's name; `name` in `ritueel.yaml` is the name in the roots' subjects, and whether it must differ between bundles is open ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** Each bundle's card inventory lists the card for its own rows; `roots` may be empty, and a card used only for the passkey is listed with applications `[fido2]` ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** The rules a request is checked against are split: store, firmware, PIN and validity in policy; name constraints and KMS read roles in each intermediate's entry. ritueel never rewrites `ritueel.yaml`, and `intermediate add` registers an intermediate by its record ([#9](https://github.com/truvity/ritueel/issues/9)).

## Replaces

Parts of 0001, 0003, 0004, 0005, 0006, 0007, 0009, 0010, 0015, 0016 and 0018, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
