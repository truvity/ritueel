---
title: Signed root list and CA bundle, version 1
description: The format of the signed root list and the CA bundle that ritueel builds, how a host reads them, the reason codes, and the test vectors.
sidebar:
  order: 4
---

*Not built yet. The arguments of `ritueel verify root-list` are decided on this page and in [the command reference](/reference/cli/#the-first-versions-commands); the command is not built, and nor is the writing of a list ([issue #14](https://github.com/truvity/ritueel/issues/14), in M2). This is version 1 of the format that [record 0006](../decisions/0006-bundle-history-and-trust-files.md) leaves to a reference page. Its [test vectors](/reference/root-list/#test-vectors) follow this page, and the README of the set lists the rules that have no vector yet. The SSH CA key list follows the same shape in M4 ([its page](/reference/ssh-ca-key-list/)), and the CRLs of the root keys are on [their page](/reference/crl/).*

A system that updates its own trust, such as a system that holds delegated keys, needs to know which root keys are active today. The **signed root list** tells it: the active root keys, pinned by their public keys, with the [trust sequence](../decisions/0006-bundle-history-and-trust-files.md), signed by one active root key when the root keys stay the same, and by every current root key or its stored removal authorisation when they change ([who signs](/reference/root-list/#who-signs)). The **CA bundle** carries the same root keys' certificates, for a TLS client and for chain building. A requester of the [hand-off contract](/reference/hand-off-contract/) reads the root list to fill `primaries` and to check an answer's issuer and `trust_sequence`.

## Files

| File | Content |
|---|---|
| `root-list.json` | The list: one JSON object, in canonical form. |
| `root-list.jws` | Its signatures: a detached JSON Web Signature over the bytes of `root-list.json`, with one signature for each root key that signs it. |
| `ca-bundle.pem` | The certificates of the root keys on the list, in its order, with the trust sequence in the first line. |

ritueel writes the three files together, in a numbered trust set of [the bundle](/reference/bundle/#the-layout). Publishing them is the holder's pipeline; the names a host fetches them under are the holder's choice.

## Versioning

- `root-list.json` has the member `version`, an integer. This page is version `1`.
- A reader that does not know the version refuses the list with `version-unsupported`.
- A change to a member, a rule or a reason code that can turn an accepted list into a refused one, or the reverse, is a new version. The vectors are versioned with it (`testdata/root-list/v1/`), and a change to a vector that flips its outcome is a new version.
- While no reader of the list has been released, version 1 is rewritten in place, as the hand-off contract is. From the first release, the rule above holds without exception.

## The list

The root list holds the active root keys, each pinned by the SHA-256 of its SubjectPublicKeyInfo and, for OpenPGP, the primary's fingerprint, with the sequence, the signing time, the expiry and the digest of the end of the history. Its members keep the names `roots` and `label` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 16).

`root-list.json` is one UTF-8 object with no byte order mark and no more than 256 KiB. A member name appears once; a member this page does not define is an error. Numbers are integers. An integer is between −9007199254740991 and 9007199254740991, the range that the canonical form of RFC 8785 holds exactly. A time is `YYYY-MM-DDThh:mm:ssZ` in UTC (RFC 3339, whole seconds). A digest is SHA-256 in lower-case hexadecimal. The writer serialises it in the canonical form of RFC 8785, with no trailing newline, so the same bundle gives the same bytes.

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | `1`. |
| `sequence` | yes | The trust sequence of this set of trust files: an integer of at least 1 that grows by one whenever any trust file changes. |
| `signed_at` | yes | When the list was signed: the time of the ceremony. A host refuses a list whose `signed_at` is later than its own clock (`malformed`). |
| `expires_at` | yes | 13 calendar months after `signed_at`: the same day and time of the month, or the last day of the month if it has none, as for an intermediate. A host refuses a list whose `expires_at` is not exactly so (`malformed`). |
| `roots` | yes | The active root keys, one or more, in a fixed order: the order in which a hand-off request lists `primaries`. Each is an object below. |
| `last_record_sha256` | yes, except in the first list | The SHA-256 of the end of the history when the ceremony's plan was made: the newest [ceremony record](/reference/ceremony-record/) in the bundle. It anchors the hash chain of the ceremony records up to the ceremony before this one; the ceremony record of this ceremony is anchored by the next list. The first list, made by the first `apply`, has no ceremony record before it, and leaves the member out. |
| `removals` | only in a list that removes a root key that does not sign it | One entry for each such root key, in label order: `label`, `x509_spki_sha256` and `authorisation`, the root key's [removal authorisation](/reference/root-list/#the-removal-authorisation) as a string. Absent when there is none. |

Each member of `roots`:

| Member | Required | Meaning |
|---|---|---|
| `label` | yes | The label of the key, as in its certificate's subject: one of the letters `A` to `Z`, in ASCII. The keys of a root are labelled `A` and `B`, then the next letter ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 2), whatever the key store. A label names a key, never its store, and is never reused. It is the key's label inside its bundle (`acme/A` across bundles); the list carries no bundle name. |
| `x509_spki_sha256` | yes | The SHA-256 of the DER `SubjectPublicKeyInfo` of the X.509 root key: the pin. It is the `issuer` member of a hand-off answer for X.509. |
| `openpgp_fingerprint` | when the bundle has an OpenPGP root | The fingerprint of the OpenPGP primary, 40 hexadecimal digits (version 4). It is a member of `primaries` in a hand-off request. |

**What an entry means.** An entry of `roots` is one key label with its pins. It is not a root in the sense of [record 0001](../decisions/0001-what-ritueel-is.md), rules 28 to 31: there a root is one thing of one kind, built from keys, and a bundle has one root of each kind it uses ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 2). Each entry pins the key of the X.509 root and, when the bundle has an OpenPGP root, the primary of that root with the same label, for example the two keys of one row of a card ([record 0003](../decisions/0003-root-cards.md), rule 3). The SSH CA keys are in [the SSH CA key list](/reference/ssh-ca-key-list/). A host installs each `x509_spki_sha256` as a trust anchor, so a host installs one anchor for each key. The members keep the names `roots` and `label` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 16). On this page, "root key" is written in full wherever one key is meant.

A bundle that has no OpenPGP root writes entries without `openpgp_fingerprint` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 17). A host takes such an entry as a key with no OpenPGP primary, and check 5 below does not refuse it. No test vector has such an entry yet.

The list pins keys, never certificates: a root certificate re-issued over the same key keeps its pin ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). A list never mixes test roots and real roots.

An example, wrapped here for reading; the file is one line:

```json
{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"<sha256>",
 "roots":[{"label":"A","openpgp_fingerprint":"<fingerprint>","x509_spki_sha256":"<sha256>"},
          {"label":"B","openpgp_fingerprint":"<fingerprint>","x509_spki_sha256":"<sha256>"}],
 "sequence":7,"signed_at":"2026-11-15T12:00:00Z","version":1}
```

## The signature

`root-list.jws` is a JSON Web Signature (RFC 7515) in the **general JSON serialisation** (section 7.2.1) with a **detached payload** (appendix F): one JSON object whose only member is `signatures`, a list of one or more objects, each with exactly the members `protected` and `signature`, both Base64url-encoded without padding. There is no `payload` member and no unprotected `header`. The object is in the canonical form of RFC 8785, with no trailing newline, and its signatures are in the order of the signers' labels. The payload is the bytes of `root-list.json`, exactly as stored. Each signature is computed over `protected || "." || BASE64URL(those bytes)`. The JSON rules of [the list](/reference/root-list/#the-list) (one UTF-8 object, no byte order mark, no repeated member, the range of the integers) and its limit of 256 KiB hold for `root-list.jws` too.

Each protected header has exactly these members:

| Member | Value |
|---|---|
| `alg` | `ES384`: ECDSA on P-384 with SHA-384 (RFC 7518, section 3.4), the signature as the 96 bytes of `r` and `s`. |
| `kid` | The `x509_spki_sha256` of the signing root key. Two signatures never have the same `kid`. |
| `x5c` | A list of one: the signing root key's certificate, Base64 DER. It carries the public key; it is never trusted as a certificate. |
| `typ` | `root-list+json`, so that a signature by the same key over another kind of document is not taken for a root list (RFC 8725, section 3.11). |

### Who signs

Each root key signs with its X.509 key: in the PIV slot that [record 0003](../decisions/0003-root-cards.md) gives it on a card, through the cloud key service, or from the root key's file in software mode.

- **A list with the same root keys as the list it replaces** carries one signature, by any active root key: the root key used at that ceremony. This is every yearly ceremony and every ceremony that changes only another trust file.
- **A list that changes the root keys** carries, for every active root key of the list it replaces, either that root key's signature or its stored removal authorisation in `removals`; and every root key it adds signs it. Changing the root keys therefore requires every current root key, or a root key's stored removal authorisation.

Two lists have the same root keys when they hold the same entries of `roots` (label, pin and fingerprint), in any order.

### The removal authorisation

Each root key makes one when it is born, beside the revocation signatures of its OpenPGP primary, and the holder stores it with them ([revocation material](/reference/revocation-material/#the-removal-authorisation)). It lets a root key leave the set by a signature that already exists, when the key itself can no longer sign.

It is a JWS in **compact serialisation with the payload attached**: `<header>.<payload>.<signature>`, Base64url without padding, ASCII, no trailing newline. The payload is the canonical JSON `{"version":1,"x509_spki_sha256":"<pin>"}` with the root key's own pin. The protected header has the four members of the table above, with `typ` `root-removal+json`, and `kid` the same pin. It carries no sequence and no expiry: it says "this root key may be removed" and nothing else, so it stays valid for as long as the root key exists, and it means nothing once the root key is gone.

It is a permission for whoever holds it. With one stolen root key, the stored authorisation of another root key and a new key, the whole set of root keys can be replaced: this is by design. The protection against a takeover with one key is only as strong as the secrecy of the stored authorisations.

### When

A ceremony that changes any trust file writes a new list with the next sequence, signed in the same ceremony. The yearly ceremony and every transition always do, so the list is re-signed at least once a year ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)); so does any other ceremony that signs with a root key, because each use re-issues that root key's certificate and so changes the CA bundle ([record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 15). The list's bytes are fixed in the ceremony's plan, so each signature is one of the plan's signatures and its touch is counted. `status` warns 60, 30 and 14 days before the newest list expires ([commands](/reference/cli/#exit-codes)).

**Adding or retiring a root key** is a ceremony, and `revoke` is an act of its own. All three change the root keys ([root transitions](/reference/transitions/#the-commands)). A revoked root key, or a key that can no longer sign, is left out of the new list, with its removal authorisation attached when it cannot sign, and with a CA bundle and a keyring without it beside it, and its break-glass SSH CA key off the SSH CA key list. The root key stops publishing its [CRL](/reference/crl/).

## How a host reads it

A host holds one list: the last good one. Before its first list it holds **initial pins**, the `x509_spki_sha256` of the root keys it was installed to trust, which the host's operator gives it by a channel of its own. It checks a new list in this order; the first check that fails gives the reason code, and the host keeps the list it holds.

| # | Check | Code |
|---|---|---|
| 1 | `root-list.jws` is a detached JWS in the general JSON serialisation as above: one or more signatures, each protected header with exactly the members above, `alg` `ES384` and `typ` `root-list+json`, `x5c` one certificate whose `SubjectPublicKeyInfo` has the SHA-256 `kid`, and no `kid` twice. | `malformed` |
| 2 | At least one `kid` is the pin of an active root key of the list the host holds, or one of its initial pins. A revoked root key is not on the list, so a list that it alone signs is refused here. | `unknown-signer` |
| 3 | Every signature verifies with the key in its `x5c` over the bytes of `root-list.json` as read. The key is ECDSA on P-384: a signature with another key is refused here. | `signature-invalid` |
| 4 | `version` is known. | `version-unsupported` |
| 5 | `root-list.json` follows the JSON rules and members above: no unknown or repeated member, `roots` not empty, each entry of `removals` with its three members, and the further refusals listed after this table. `expires_at` is exactly 13 calendar months after `signed_at`, and `signed_at` is not later than the host's clock. | `malformed` |
| 6 | `sequence` is not lower than the `sequence` of the list the host holds, and not lower than the lowest sequence given with its initial pins (`--min-sequence`). Initial pins alone have no sequence. | `rollback` |
| 7 | When `sequence` equals the held list's, `root-list.json` is byte for byte the held list's `root-list.json`. | `sequence-conflict` |
| 8 | Every `kid` is the pin of a root key of the list the host holds (or an initial pin) or of a root key on this list. | `unknown-signer` |
| 9 | Every entry of `removals` is a valid removal authorisation of the root key it names: the format above, `kid`, the key in `x5c` and the payload's pin all equal to the entry's `x509_spki_sha256`, the signature verifying, and the root key on the list the host holds and not on this list. | `removal-invalid` |
| 10 | When this list's root keys are not the held list's: every root key of the held list has signed it or has its authorisation in `removals`, and every root key this list adds has signed it. Against initial pins, the root keys are compared by their pins. | `insufficient-signers` |
| 11 | The host's clock is before `expires_at`. | `expired` |

The host verifies the bytes it received and does not re-serialise them. When every check passes, the new list replaces the one it holds, and its root keys are the host's pins from then on.

**The held list again.** Receiving the list the host holds again is not an error. A list at the same sequence whose `root-list.json` is byte for byte the held one passes without checks 8 to 10, because it brings nothing new. It still needs a signature by a root key of the held list (check 2), every signature must verify (check 3), and the other checks run, the expiry included: the same list after `expires_at` is refused with `expired`. A list at the same sequence whose content differs is refused with `sequence-conflict`, because one sequence names one set of root keys. A signer need not be on the new list: a root key that retires signs the list that removes it, because checks 2, 8 and 10 read the list the host held.

The held list again brings nothing new: a host installs nothing and keeps the files it holds, also its `.jws`. A script sees it by the digest of `root-list.json` in the output, which equals the digest of the file it holds. The `.jws` of a list that comes again is not evidence of who signed the list. When the list is the held one again, the output says so: the JSON object has the member `again` with the value `true` (absent otherwise), and the text output has one line for it. When the list comes again after its `expires_at`, `ritueel verify root-list` prints both the warning `held-expired` and the refusal `expired`, with exit code 3 (probed on the command, 2026-11-14).

**The host's clock.** The clock of the host is an input of trust. Check 5 allows no tolerance: a list signed after the host's clock is refused. A `malformed` that comes with every fresh list means that the clock of the host is behind. A host whose clock is set back takes a list that has expired, because check 11 reads the same clock, and, with no lowest sequence, an older list. The window in which a list is taken is then the list's own time from its `signed_at` to its `expires_at`.

**What check 5 also refuses.** A list is `malformed` when it has a label or a pin twice in `roots`, or a pin twice in `removals`; an `openpgp_fingerprint` that is not 40 lower-case hexadecimal digits; a `last_record_sha256` that is not 64 lower-case hexadecimal digits; an empty authorisation in a removal; or a `sequence` below 1. These are the smallest refusals that keep the list a set. A signature file of more than 256 KiB is refused with `malformed` (check 1), and a CA bundle of more than 256 KiB with `ca-bundle-mismatch`.

**What the host does not enforce.** It does not check the canonical form (RFC 8785) of `root-list.json` or of `root-list.jws` (the signature covers the bytes, so a signed list that is not canonical is accepted), that `last_record_sha256` is there when `sequence` is above 1, the order of `roots` and of `removals`, a removal entry's `label` against the held label, or a limit on the number of signatures; an empty `removals` list is accepted. The signature file of the list the host holds is not read: no check uses it, and the signers of a held list may no longer be on it.

**A host that missed a list** compares the next one it receives with the list it holds, not with the one before it. A change of the root keys it has not seen may then be refused (`unknown-signer` or `insufficient-signers`); it takes the lists in between, in order, from where the holder publishes them. ritueel keeps every list in its numbered trust set, so every list can be published.

**A host that holds only initial pins** is protected less than a host that holds a list, in two ways. First, it takes a first list on one signature for everything the list says besides the pins: the labels, the OpenPGP fingerprints, the sequence and the expiry. With a held list, changing a label or a fingerprint needs every held root key. Second, it takes an old list that is validly signed and not expired, also one that still holds a root key that was revoked since: against a held list at sequence 8 the same list is refused with `rollback`. The operator who gives the pins may give with them the lowest sequence to accept (`--min-sequence N`), on the same channel. A list below it is refused with `rollback`, so the old list cannot come back ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 51). The operator chooses `N` at least as high as the sequence of the newest list that removed a root key; `ritueel verify root-list` prints the sequence of a list it accepts, so the operator reads it there. The lowest sequence does not help against a root key that was revoked and is still among the pins the operator gives: the operator gives the pins of the current list.

:::caution[Open]
One stolen root key can sign a list with the same root keys and a far higher sequence, because such a list needs one signature. A host that takes it refuses every honest list afterwards, the list that revokes the stolen key included, and, while the thief signs a new list before each expiry, the warning of an expired list does not come either. This is decided before the first release ([issue #228](https://github.com/truvity/ritueel/issues/228); [what other systems do](/research/root-list-sequence-and-a-stolen-key-2026-11-14/)).

The way back today is the operator's. (1) Remove the list the host holds. (2) Give the host the pins of the honest root keys again. (3) Run `ritueel verify root-list` with `--pin` and with `--min-sequence` set to the sequence of the honest list that removed the stolen key. The command takes `--held` or `--pin`, not both.
:::

**When the list a host holds expires** and no newer one has arrived, it keeps the list, goes on trusting its root keys, and raises a warning. It does not drop its root keys ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). `ritueel verify root-list` reports it as the warning `held-expired` in the member `warnings` of its JSON output and prints it on standard error; the exit code does not change ([the output](/reference/cli/#machine-readable-output)).

These codes belong to the host and are not sent anywhere. The vectors fix the outcome and the code, not the wording of a message.

**The command.** `ritueel verify root-list FILE (--held FILE | --pin SHA256... [--min-sequence N]) [--ca-bundle FILE]` runs these checks.

- `FILE` is the list to check, its `root-list.json`. Its signature is the `.jws` file beside it: `FILE` ends in `.json`, and the signature file has the same name with `.jws` in place of `.json`. A `FILE` with another ending is a usage error (exit code 2).
- `--held FILE` is the list the host holds now. Its `.jws` is not read.
- `--pin SHA256...` are the pins of the root keys, for a host that holds no list yet: one `--pin` for each pin. `--min-sequence N` is given only together with `--pin`, and `N` is an integer of at least 1.
- `--ca-bundle FILE` also checks a CA bundle against the list ([the CA bundle](/reference/root-list/#the-ca-bundle)).

It signs and writes nothing, and it reads no bundle: `--dir` is accepted and not read ([Commands](/reference/cli/#the-first-versions-commands)).

*How it reads a file.* The command reads up to four files: `FILE`, its `.jws`, `--held` and `--ca-bundle`. It reads them with the strict reader that ritueel also uses for the files of a bundle ([the reader](/reference/bundle/#the-root-folder-of-the-writer)). That reader follows no link at the file, takes a file name of only ASCII letters, digits, dot, hyphen and underscore, refuses a link, a FIFO, a device and a folder without opening or waiting on them, and never reads past 8 MiB. A file behind a link is copied first, for example with `cp -L`, and its copy gets a name of that kind.

*What a fault of a file gives.* One rule holds for the two files of the candidate (`FILE` and its `.jws`): a file that is not there, or that cannot be read, gives exit code 1, "could not check"; a file that is there and is not acceptable gives exit code 3 with `malformed`. So a script that retries on 1 and raises an alarm on 3 does not take a link or a FIFO for a failed fetch. The table has every case.

| File | Fault | Exit code | Reason code |
|---|---|---|---|
| `FILE` or its `.jws` | Not there, no permission, an I/O error, a file name outside the rule above | 1 | none |
| `FILE` or its `.jws` | A link, a FIFO, a device, a folder, a file over 8 MiB | 3 | `malformed` |
| `FILE` or its `.jws` | A file between 256 KiB and 8 MiB | 3 | The code of the first check that fails, in the order of the checks: `malformed` (check 1 or 5), or `signature-invalid` (check 3) when the signature does not fit the bytes |
| `FILE` and its `.jws` | One is missing or unreadable and the other is not acceptable | 1 | none (exit code 1 wins) |
| `FILE` | Does not end in `.json` | 2 | none (a usage error) |
| `--held` | Any fault of the file | 1 | none |
| `--ca-bundle` | Not there, unreadable, not acceptable, or over 8 MiB | 1 | none |
| `--ca-bundle` | A file between 256 KiB and 8 MiB | 3 | `ca-bundle-mismatch` |
| Any of the four | A link as the last folder of the path (a link in a folder before it is followed) | 1 | none |

Every file is read before any check runs, so exit code 1 for an unreadable `--held` or `--ca-bundle` file also comes before a refusal of the candidate, and a held list over 256 KiB is exit code 1. A stripped `.jws` gives exit code 1, so a script cannot tell it from a failed download. An attacker on the channel can make a host retry that way, and never make it install ([the codes](/reference/cli/#exit-codes)).

*What it prints.* An accepted list is printed with the SHA-256 of the files that the command read ([the output](/reference/cli/#machine-readable-output)).

## The CA bundle

`ca-bundle.pem` is text, with LF line endings. It is the certificates of the active X.509 root keys in one PEM file, with the trust sequence in a comment line ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 23):

1. The first line is `# trust-sequence: <sequence>`, the sequence of the root list it was built with.
2. Then the current certificate of each root key on that list, in the order of `roots`, each PEM-armoured with the label `CERTIFICATE` (RFC 7468), Base64 in lines of 64 characters.
3. Nothing else.

It is deterministic (0006 rules 15 and 23): the same certificates in the same order give the same bytes. A PEM parser skips the text outside the armour (RFC 7468, section 2), so OpenSSL reads the file as a list of trust anchors (checked with OpenSSL 3.5.5 on 2026-11-01: `openssl verify -CAfile` with the vectors' CA bundles accepts the hand-off answers of the root keys in the CA bundle and refuses the others). The root certificates follow the [root profile](/reference/bundle/#the-root-certificate).

The CA bundle is not signed: a TLS client trusts the file it was given. A system that also holds the signed root list uses a certificate from the CA bundle as an anchor only when its key is on the list it holds, and its sequence is the list's.

**What `--ca-bundle` checks.** The list pins keys, so the check looks at the CA bundle in three ways. The first line names the list's `sequence`, and the bundle holds one certificate for each root of the list. The key of each certificate is the key of the root at its place in `roots`. And each certificate verifies with its own key (a root certificate signs itself) and is a CA certificate. So a certificate with this key is one that the root key signed, and nobody without the key can write one around it. The command does not judge the dates, the names or the serial number of a certificate: it accepts an older genuine certificate of the same key, and a person who holds the key can write a certificate with other names and limits. A bundle that fails in any way is refused with `ca-bundle-mismatch` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 52).

## Test vectors

The vectors are in [`testdata/root-list/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/root-list/v1). They are public material only, made by the same run of [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py) as the hand-off vectors, so the root keys are the same test root keys: A and B are active, C is a root key that a list adds, Z is on no list, and the list `seq7-a` is the root list of trust sequence 7, which the hand-off answers carry.

- `manifest.json` names each root key with its pins and files, the initial pins (A and B), the removal authorisation of A, B and C as the holder stores them (`removals/`), every list with its signers, every case and every CA bundle.
- A case gives the list the host holds (`held`, or `null` for the initial pins), the list it receives (`candidate`), the clock if it is not the manifest's `2026-11-15T12:00:00Z`, and the expected outcome: `accept`, `refuse` with a reason code, or `warn` with a warning.
- The record digests in the lists are made up.
- A case with `bundle` also checks that CA bundle against the candidate list (`--ca-bundle`). A case with `min_sequence` is a host that holds only its initial pins and the lowest sequence given with them (`--min-sequence`); it has no held list.

| Group | Cases |
|---|---|
| Accepted | A first list against the initial pins, the kind the first `apply` makes; an update with the same root keys, signed by one root key; an update signed by the other root key; a list without A, signed by B and carrying A's removal authorisation, which revokes A; a list without A signed by A and B, which retires A; a list that adds C, signed by A, B and C; the same list again, also after a revoke and after a retire, and with a second signature by a root key on no list beside a trusted one; lists signed on 31 January, on 30 January before a leap year and on a leap day, with the last day of the month as the expiry; a list at the lowest sequence that was given with the initial pins. |
| Refused | A lower sequence (`rollback`); another list at the same sequence (`sequence-conflict`); a list signed by the revoked root key A after it left the list, one signed by Z, and one with a second signature by Z (`unknown-signer`); a change of the root keys with one signature, a list without A that B signs with no authorisation for A, a list that adds C without C's signature, and one that adds C without B's (`insufficient-signers`); a list whose entry for A carries B's authorisation (`removal-invalid`); a list changed after signing (`signature-invalid`); an expired list (`expired`); version 2 (`version-unsupported`); an unknown member, an `expires_at` that is 13 calendar months and a second, or 12 months, after `signed_at`, the expiry that a plain month addition gives from the 31st or from the 30th, a `signed_at` later than the clock, a label or a pin twice, a pin twice in `removals`, an OpenPGP fingerprint in upper case, a digest one digit short, a `sequence` of 0 against initial pins, and an empty authorisation (`malformed`); a list below the lowest sequence that was given with the initial pins (`rollback`); the same list again after its `expires_at` (`expired`, with the warning `held-expired` beside it). |
| Warned | The held list expired and no newer one came. |
| CA bundles | Accepted: sequence 7 with A and B; sequence 8 with B only. Refused with `ca-bundle-mismatch`: a certificate with the key of A that the key of Z signed, and one with the key of A that is signed by it and is not a CA certificate, a bundle with a certificate too many, one with a certificate missing, one with the certificates in the wrong order, and one whose first line names another sequence. |

CI checks that the manifest names every file of the set, that the pins match the root files, that every list carries exactly the signatures of its signers and that each verifies except in the list a case expects to fail, that every removal authorisation is valid except the one a case expects to be refused, and that each CA bundle holds the root keys it names under its sequence (`just check-vectors`).

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| Signature | A detached JWS, ES384, by the X.509 root keys. | CMS (RFC 5652); an OpenPGP signature by the primary; minisign or an SSH signature. | The readers already parse JSON and JOSE, every language has a JWS library, and a card or a KMS key makes the raw `r` and `s` that ES384 carries. CMS needs an ASN.1 stack for a JSON file; an OpenPGP signature would need the primary, a second touch, for a list whose audience is the X.509 key's. |
| Who signs a change of the root keys | Every current root key, or its stored removal authorisation; and every added root key. | Any one active root key, as for a list with the same root keys; every current root key, with no stored authorisation; a separate key for changes of the set. | A change of the root keys does not rest on one root key, while a renewal stays a one-key ceremony. Without the stored authorisation a key that can no longer sign could never leave the set by a signature, and every host would need its pins replaced by hand. A separate key costs a slot and a touch for the same audience. ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)) |
| Serialisation | The general JSON serialisation, one signature for each signer, also when there is one. | Compact for one signer and JSON for several; one compact JWS file for each signer. | One format for every list, which a JWS library reads as it is. Two formats would be two code paths, and loose signature files could be separated from their list. |
| The removal authorisation | A compact JWS over the root key's own pin, made at its birth, attached to the list that removes it. | A signature over a future list; a revocation of the root key's certificate. | A future list's bytes cannot be known at birth. A certificate revocation would need a CRL that hosts of the root list do not read. |
| Where the verifier finds the key | The signing root key's certificate in `x5c`; the host trusts only its key, and only when its hash is a pin. | Only `kid`, with the key taken from the CA bundle; a `jwk` header. | The list verifies alone, and comparing the SHA-256 of a DER key with a pin is the same operation as for the hand-off's `issuer`. A `jwk` would need a conversion to compute the same hash. |
| Detached payload | The JSON in a file of its own, the signature beside it. | The payload inside the JWS. | A person can read the list without decoding it, and the bytes signed are the bytes on disk. |
| Canonical form | RFC 8785, verified as read. | Any JSON, signed as written; a reader that canonicalises. | The same bundle gives the same bytes, and a reader that never re-serialises cannot get canonicalisation wrong. sluis writes its records in the same form. |
| Order of the checks | A signer the host trusts and every signature before the version and the members; the checks that read the members (the signers, the removals, the root keys) after the sequence. | The version first, as the hand-off contract does; every authority check before the sequence. | Nothing in an unauthenticated list is acted on; the contract's messages have no signature of their own. A replayed or conflicting list is refused for what it is before its signers are weighed. |
| Explicit type | `typ` `root-list+json`. | No `typ`. | The same key signs the SSH CA key list; a type in the protected header keeps one from being read as the other. |
| How the command reads a file | The strict reader of the bundle: no link, a plain file name, a plain file of at most 8 MiB; the user copies a file behind a link first. | A second reader that follows a link, built with a descriptor that does not touch the target (`O_PATH`, `fstat`, then a reopen through `/proc/self/fd`). | One way to read, and nothing that a link points to is ever opened: a followed link may lead to a file that is not a plain file, and a second reader would have to check it before it opens it. The cost: a file that is a link cannot be read in place. A second reader can be decided later. |
| A fault of the candidate's files | One rule: not there is exit code 1, there and not acceptable is exit code 3. | Exit code 3 for every fault of the two files, a missing `.jws` too, and exit code 1 only for no permission and I/O errors. | A link, a FIFO or a file that is too large is never taken for a failed fetch. The cost: a stripped `.jws` looks like a failed fetch. |
| `FILE` that does not end in `.json` | A usage error. | Add `.jws` to any name. | No guess at the name of the signature file, and no second naming rule. |
| The bytes that were checked | The SHA-256 of the files that the command read, in the output. | Nothing. | A script can compare the digests after it has copied the files to their final place, so a file that changed between the check and the copy is found. The cost: more output, which [the command reference](/reference/cli/#machine-readable-output) names. |

## Follow-ups

- The code: writing, signing and reading the list and the CA bundle, with the host rules, and a test that the same inputs give the same bytes ([issue #14](https://github.com/truvity/ritueel/issues/14)).
- The SSH CA key list in the same shape, with its own `typ` and vectors, is specified on [its page](/reference/ssh-ca-key-list/) ([issue #55](https://github.com/truvity/ritueel/issues/55)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature: the general JSON serialisation (section 7.2.1) for the list, the compact serialisation for the removal authorisation, the detached payload (appendix F), `x5c`. |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | `ES384`. |
| [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) | Explicit typing with `typ`. |
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) | The canonical form of `root-list.json`. |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | `SubjectPublicKeyInfo`, the root certificates. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | Version 4 fingerprints. |
| [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PEM armour and the text outside it. |
| [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339), [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) | Times; Base64 and Base64url. |
