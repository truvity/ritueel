---
title: Signed root list and CA bundle, version 1
description: The format of the signed root list and the CA bundle that ritueel builds, how a host reads them, the reason codes, and the test vectors.
sidebar:
  order: 4
---

*Not built yet. This is version 1 of the format that [ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/) leaves to a reference page; the code is [issue #14](https://github.com/truvity/ritueel/issues/14), in M2, and its [test vectors](/reference/root-list/#test-vectors) match this page. The SSH CA key list follows the same shape in M7 ([its page](/reference/ssh-ca-key-list/)), and the CRLs of the roots are on [their page](/reference/crl/).*

A system that updates its own trust, such as a system that holds intermediates, needs to know which roots are active today. The **signed root list** tells it: the active roots, pinned by their public keys, with the [trust sequence](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#one-counter-the-trust-sequence), signed by one active root when the roots stay the same, and by every current root when they change ([who signs](/reference/root-list/#who-signs)). The **CA bundle** carries the same roots' certificates, for a TLS client and for chain building. A requester of the [hand-off contract](/reference/hand-off-contract/) reads the root list to fill `primaries` and to check an answer's issuer and `trust_sequence`.

## Files

| File | Content |
|---|---|
| `root-list.json` | The list: one JSON object, in canonical form. |
| `root-list.jws` | Its signatures: a detached JSON Web Signature over the bytes of `root-list.json`, with one signature for each root that signs it. |
| `ca-bundle.pem` | The certificates of the roots on the list, in its order, with the trust sequence in the first line. |

ritueel writes the three files together, under `products/<sequence>/` in [the bundle](/reference/bundle/#the-layout). Publishing them is the operator's pipeline; the names a host fetches them under are the operator's choice.

## Versioning

- `root-list.json` has the member `version`, an integer. This page is version `1`.
- A reader that does not know the version refuses the list with `version-unsupported`.
- A change to a member, a rule or a reason code that can turn an accepted list into a refused one, or the reverse, is a new version. The vectors are versioned with it (`testdata/root-list/v1/`), and a change to a vector that flips its outcome is a new version.
- While no reader of the list has been released, version 1 is rewritten in place, as the hand-off contract is: so it was on 2026-11-02, when a change of the root set came to need every current root. From the first release, the rule above holds without exception.

## The list

`root-list.json` is one UTF-8 object with no byte order mark and no more than 256 KiB. A member name appears once; a member this page does not define is an error. Numbers are integers. A time is `YYYY-MM-DDThh:mm:ssZ` in UTC (RFC 3339, whole seconds). A digest is SHA-256 in lower-case hexadecimal. The writer serialises it in the canonical form of RFC 8785, with no trailing newline, so the same bundle gives the same bytes.

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | `1`. |
| `sequence` | yes | The trust sequence of this set of trust products: an integer of at least 1 that grows by one whenever any trust product changes. |
| `signed_at` | yes | When the list was signed: the time of the ceremony. |
| `expires_at` | yes | 13 calendar months after `signed_at`: the same day and time of the month, or the last day of the month if it has none, as for an intermediate. |
| `roots` | yes | The active roots, one or more, in a fixed order: the order in which a hand-off request lists `primaries`. Each is an object below. |
| `last_record_sha256` | yes, except in the list `init` makes | The SHA-256 of the newest [ceremony record](/reference/ceremony-record/) in the bundle when the ceremony's plan was made. It anchors the hash chain of the records up to the ceremony before this one; the record of this ceremony is anchored by the next list. The list that `init` makes has no record before it, and leaves the member out. |
| `removals` | only in a list that removes a root that does not sign it | One entry for each such root, in label order: `label`, `x509_spki_sha256` and `authorisation`, the root's [removal authorisation](/reference/root-list/#the-removal-authorisation) as a string. Absent when there is none. |

Each member of `roots`:

| Member | Required | Meaning |
|---|---|---|
| `label` | yes | The root's label, as in its certificate's subject: one upper-case letter. `init` names its roots `A` and `B`, and `root add` takes the next free letter (`C`, `D`, and so on) whatever the key store. A label names a root, never its store, and is never reused. It is the root's label inside its bundle (`acme/A` across bundles); the list carries no bundle name. |
| `x509_spki_sha256` | yes | The SHA-256 of the DER `SubjectPublicKeyInfo` of the root's X.509 key: the pin. It is the `issuer` member of a hand-off answer for X.509. |
| `openpgp_fingerprint` | yes | The fingerprint of the root's OpenPGP primary, 40 hexadecimal digits (version 4). It is a member of `primaries` in a hand-off request. |

The list pins keys, never certificates: a root certificate re-issued over the same key keeps its pin ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)). A list never mixes test roots and real roots.

An example, wrapped here for reading; the file is one line:

```json
{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"<sha256>",
 "roots":[{"label":"A","openpgp_fingerprint":"<fingerprint>","x509_spki_sha256":"<sha256>"},
          {"label":"B","openpgp_fingerprint":"<fingerprint>","x509_spki_sha256":"<sha256>"}],
 "sequence":7,"signed_at":"2026-11-15T12:00:00Z","version":1}
```

## The signature

`root-list.jws` is a JSON Web Signature (RFC 7515) in the **general JSON serialisation** (section 7.2.1) with a **detached payload** (appendix F): one JSON object whose only member is `signatures`, a list of one or more objects, each with exactly the members `protected` and `signature`, both Base64url-encoded without padding. There is no `payload` member and no unprotected `header`. The object is in the canonical form of RFC 8785, with no trailing newline, and its signatures are in the order of the signers' labels. The payload is the bytes of `root-list.json`, exactly as stored. Each signature is computed over `protected || "." || BASE64URL(those bytes)`.

Each protected header has exactly these members:

| Member | Value |
|---|---|
| `alg` | `ES384`: ECDSA on P-384 with SHA-384 (RFC 7518, section 3.4), the signature as the 96 bytes of `r` and `s`. |
| `kid` | The `x509_spki_sha256` of the signing root. Two signatures never have the same `kid`. |
| `x5c` | A list of one: the signing root's certificate, Base64 DER. It carries the public key; it is never trusted as a certificate. |
| `typ` | `root-list+json`, so that a signature by the same key over another kind of document is not taken for a root list (RFC 8725, section 3.11). |

### Who signs

Each root signs with its X.509 root key: in the PIV slot that [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) gives it on a card, through the cloud key service, or from the root's file in software mode.

- **A list with the same roots as the list it replaces** carries one signature, by any active root: the root used at that ceremony. This is every yearly ceremony and every ceremony that changes only another trust product.
- **A list that changes the root set** carries, for every active root of the list it replaces, either that root's signature or its stored removal authorisation in `removals`; and every root it adds signs it. Changing the root set therefore requires every current root, or a root's stored removal authorisation.

Two lists have the same roots when they hold the same entries of `roots` (label, pin and fingerprint), in any order.

### The removal authorisation

Each root makes one when it is born, beside the revocation signatures of its OpenPGP primary, and the holder stores it with them ([revocation material](/reference/revocation-material/#the-removal-authorisation)). It lets a root leave the set by a signature that already exists, when the root itself can no longer sign.

It is a JWS in **compact serialisation with the payload attached**: `<header>.<payload>.<signature>`, Base64url without padding, ASCII, no trailing newline. The payload is the canonical JSON `{"version":1,"x509_spki_sha256":"<pin>"}` with the root's own pin. The protected header has the four members of the table above, with `typ` `root-removal+json`, and `kid` the same pin. It carries no sequence and no expiry: it says "this root may be removed" and nothing else, so it stays valid for as long as the root exists, and it means nothing once the root is gone.

### When

A ceremony that changes any trust product writes a new list with the next sequence, signed in the same ceremony. The yearly ceremony and every transition always do, so the list is re-signed at least once a year ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)); so does any other ceremony that signs with a root, because each use re-issues that root's certificate and so changes the CA bundle ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)). The list's bytes are fixed in the ceremony's plan, so each signature is one of the plan's signatures and its touch is counted. `status` warns 60, 30 and 14 days before the newest list expires ([commands](/reference/cli/#exit-codes)).

**Adding, retiring and revoking a root** are the ceremonies that change the root set ([root transitions](/reference/transitions/#the-commands)). A revoked or lost root is left out of the new list, with its removal authorisation attached when it cannot sign, and with a CA bundle and a keyring without it beside it, and its break-glass SSH CA key off the SSH CA key list. The root stops publishing its [CRL](/reference/crl/).

## How a host reads it

A host holds one list: the last good one. Before its first list it holds **initial pins**, the `x509_spki_sha256` of the roots it was installed to trust, which the operator gives it by a channel of its own. It checks a new list in this order; the first check that fails gives the reason code, and the host keeps the list it holds.

| # | Check | Code |
|---|---|---|
| 1 | `root-list.jws` is a detached JWS in the general JSON serialisation as above: one or more signatures, each protected header with exactly the members above, `alg` `ES384` and `typ` `root-list+json`, `x5c` one certificate whose `SubjectPublicKeyInfo` has the SHA-256 `kid`, and no `kid` twice. | `malformed` |
| 2 | At least one `kid` is the pin of an active root of the list the host holds, or one of its initial pins. A revoked root is not on the list, so a list that it alone signs is refused here. | `unknown-signer` |
| 3 | Every signature verifies with the key in its `x5c` over the bytes of `root-list.json` as read. | `signature-invalid` |
| 4 | `version` is known. | `version-unsupported` |
| 5 | `root-list.json` follows the JSON rules and members above: no unknown or repeated member, `roots` not empty, each entry of `removals` with its three members. | `malformed` |
| 6 | `sequence` is not lower than the `sequence` of the list the host holds. Initial pins have no sequence. | `rollback` |
| 7 | When `sequence` equals the held list's, `root-list.json` is byte for byte the held list's `root-list.json`. | `sequence-conflict` |
| 8 | Every `kid` is the pin of a root of the list the host holds (or an initial pin) or of a root on this list. | `unknown-signer` |
| 9 | Every entry of `removals` is a valid removal authorisation of the root it names: the format above, `kid`, the key in `x5c` and the payload's pin all equal to the entry's `x509_spki_sha256`, the signature verifying, and the root on the list the host holds and not on this list. | `removal-invalid` |
| 10 | When this list's roots are not the held list's: every root of the held list has signed it or has its authorisation in `removals`, and every root this list adds has signed it. Against initial pins, the roots are compared by their pins. | `insufficient-signers` |
| 11 | The host's clock is before `expires_at`. | `expired` |

The host verifies the bytes it received and does not re-serialise them. When every check passes, the new list replaces the one it holds, and its roots are the host's pins from then on. Receiving the current list again is not an error: a list at the same sequence passes when its `root-list.json` is byte-identical to the held one, whichever active root signed it, and is refused with `sequence-conflict` when its content differs, because one sequence names one set of roots. A signer need not be on the new list: a root that retires signs the list that removes it, because checks 2, 8 and 10 read the list the host held.

**A host that missed a list** compares the next one it receives with the list it holds, not with the one before it. A change of the root set it has not seen may then be refused (`unknown-signer` or `insufficient-signers`); it takes the lists in between, in order, from where the operator publishes them. ritueel keeps every list under `products/<sequence>/`, so the operator can publish them all.

**When the list a host holds expires** and no newer one has arrived, it keeps the list, goes on trusting its roots, and raises a warning. It does not drop its roots ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)).

These codes belong to the host and are not sent anywhere. The vectors fix the outcome and the code, not the wording of a message.

**The command.** `ritueel root-list verify FILE` runs these checks on the list `FILE` (its `root-list.json`; the signature is the `.jws` file beside it), against the list the host holds (`--held FILE`) or its initial pins (`--pin SHA256`, once for each). `--ca-bundle FILE` also checks a CA bundle against the list: its first line names the list's `sequence`, and its certificates are the keys of the list's `roots`, in that order, or it is refused with `ca-bundle-mismatch`. It signs and writes nothing ([Commands](/reference/cli/#the-first-versions-commands)).

## The CA bundle

`ca-bundle.pem` is text, with LF line endings:

1. The first line is `# trust-sequence: <sequence>`, the sequence of the root list it was built with.
2. Then the current certificate of each root on that list, in the order of `roots`, each PEM-armoured with the label `CERTIFICATE` (RFC 7468), Base64 in lines of 64 characters.
3. Nothing else.

It is deterministic: the same roots in the same order give the same bytes. A PEM parser skips the text outside the armour (RFC 7468, section 2), so OpenSSL reads the file as a list of trust anchors (checked with OpenSSL 3.5.5 on 2026-11-01: `openssl verify -CAfile` with the vectors' CA bundles accepts the hand-off answers of the roots in the CA bundle and refuses the others). The root certificates follow the [root profile](/reference/bundle/#the-root-certificate).

The CA bundle is not signed: a TLS client trusts the file it was given. A system that also holds the signed root list uses a certificate from the CA bundle as an anchor only when its key is on the list it holds, and its sequence is the list's.

## Test vectors

The vectors are in [`testdata/root-list/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/root-list/v1). They are public material only, made by the same run of [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py) as the hand-off vectors, so the roots are the same test roots: A and B are active, C is a root that a list adds, Z is on no list, and the list `seq7-a` is the root list of trust sequence 7, which the hand-off answers carry.

- `manifest.json` names each root with its pins and files, the initial pins (A and B), the removal authorisation of A, B and C as the holder stores them (`removals/`), every list with its signers, every case and every CA bundle.
- A case gives the list the host holds (`held`, or `null` for the initial pins), the list it receives (`candidate`), the clock if it is not the manifest's `2026-11-15T12:00:00Z`, and the expected outcome: `accept`, `refuse` with a reason code, or `warn` with a warning.
- The record digests in the lists are made up.

| Group | Cases |
|---|---|
| Accepted | A first list against the initial pins, and the list `init` makes; an update with the same roots, signed by one root; an update signed by the other root; a list without A, signed by B and carrying A's removal authorisation, which revokes A; a list without A signed by A and B, which retires A; a list that adds C, signed by A, B and C; the same list again. |
| Refused | A lower sequence (`rollback`); another list at the same sequence (`sequence-conflict`); a list signed by the revoked root A after it left the list, one signed by Z, and one with a second signature by Z (`unknown-signer`); a change of the root set with one signature, a list without A that B signs with no authorisation for A, a list that adds C without C's signature, and one that adds C without B's (`insufficient-signers`); a list whose entry for A carries B's authorisation (`removal-invalid`); a list changed after signing (`signature-invalid`); an expired list (`expired`); version 2 (`version-unsupported`); an unknown member (`malformed`). |
| Warned | The held list expired and no newer one came. |
| CA bundles | Sequence 7 with A and B; sequence 8 with B only. |

CI checks that the manifest names every file of the set, that the pins match the root files, that every list carries exactly the signatures of its signers and that each verifies except in the list a case expects to fail, that every removal authorisation is valid except the one a case expects to be refused, and that each CA bundle holds the roots it names under its sequence (`just check-vectors`).

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| Signature | A detached JWS, ES384, by the roots' X.509 keys. | CMS (RFC 5652); an OpenPGP signature by the primary; minisign or an SSH signature. | The readers already parse JSON and JOSE, every language has a JWS library, and a card or a KMS key makes the raw `r` and `s` that ES384 carries. CMS needs an ASN.1 stack for a JSON file; an OpenPGP signature would need the primary, a second touch, for a list whose audience is the X.509 key's. |
| Who signs a change of the root set | Every current root, or its stored removal authorisation; and every added root. | Any one active root, as for a list with the same roots; every current root, with no stored authorisation; a separate key for changes of the set. | The roots decide together who is trusted, while a renewal stays a one-root ceremony. Without the stored authorisation a lost root could never leave the set by a signature, and every host would need its pins replaced by hand. A separate key costs a slot and a touch for the same audience. ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)) |
| Serialisation | The general JSON serialisation, one signature for each signer, also when there is one. | Compact for one signer and JSON for several; one compact JWS file for each signer. | One format for every list, which a JWS library reads as it is. Two formats would be two code paths, and loose signature files could be separated from their list. |
| The removal authorisation | A compact JWS over the root's own pin, made at its birth, attached to the list that removes it. | A signature over a future list; a revocation of the root's certificate. | A future list's bytes cannot be known at birth. A certificate revocation would need a CRL that hosts of the root list do not read. |
| Where the verifier finds the key | The signing root's certificate in `x5c`; the host trusts only its key, and only when its hash is a pin. | Only `kid`, with the key taken from the CA bundle; a `jwk` header. | The list verifies alone, and comparing the SHA-256 of a DER key with a pin is the same operation as for the hand-off's `issuer`. A `jwk` would need a conversion to compute the same hash. |
| Detached payload | The JSON in a file of its own, the signature beside it. | The payload inside the JWS. | A person can read the list without decoding it, and the bytes signed are the bytes on disk. |
| Canonical form | RFC 8785, verified as read. | Any JSON, signed as written; a reader that canonicalises. | The same bundle gives the same bytes, and a reader that never re-serialises cannot get canonicalisation wrong. sluis writes its records in the same form. |
| Order of the checks | A signer the host trusts and every signature before the version and the members; the checks that read the members (the signers, the removals, the root set) after the sequence. | The version first, as the hand-off contract does; every authority check before the sequence. | Nothing in an unauthenticated list is acted on; the contract's messages have no signature of their own. A replayed or conflicting list is refused for what it is before its signers are weighed. |
| Explicit type | `typ` `root-list+json`. | No `typ`. | The same key signs the SSH CA key list; a type in the protected header keeps one from being read as the other. |

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
