---
title: Signed root list and CA bundle, version 1
description: The format of the signed root list and the CA bundle that ritueel builds, how a host reads them, the reason codes, and the test vectors.
sidebar:
  order: 4
---

*Not built yet. This is version 1 of the format that [ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/) leaves to a reference page; the code is [issue #14](https://github.com/truvity/ritueel/issues/14), in M1, and its [test vectors](/reference/root-list/#test-vectors) match this page. The SSH CA key list follows in M3 ([issue #55](https://github.com/truvity/ritueel/issues/55)).*

A system that updates its own trust, such as a system that holds intermediates, needs to know which roots are active today. The **signed root list** tells it: the active roots, pinned by their public keys, with the [trust sequence](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#one-counter-the-trust-sequence), signed by one active root. The **CA bundle** carries the same roots' certificates, for a TLS client and for chain building. A requester of the [hand-off contract](/reference/hand-off-contract/) reads the root list to fill `primaries` and to check an answer's issuer and `trust_sequence`.

## Files

| File | Content |
|---|---|
| `root-list.json` | The list: one JSON object, in canonical form. |
| `root-list.jws` | Its signature: a detached JSON Web Signature over the bytes of `root-list.json`. |
| `ca-bundle.pem` | The certificates of the roots on the list, in its order, with the trust sequence in the first line. |

ritueel writes the three files together, under `products/<sequence>/` in [the directory](/reference/directory/#the-layout). Publishing them is the operator's pipeline; the names a host fetches them under are the operator's choice.

## Versioning

- `root-list.json` has the member `version`, an integer. This page is version `1`.
- A reader that does not know the version refuses the list with `version-unsupported`.
- A change to a member, a rule or a reason code that can turn an accepted list into a refused one, or the reverse, is a new version. The vectors are versioned with it (`testdata/root-list/v1/`), and a change to a vector that flips its outcome is a new version.

## The list

`root-list.json` is one UTF-8 object with no byte order mark and no more than 256 KiB. A member name appears once; a member this page does not define is an error. Numbers are integers. A time is `YYYY-MM-DDThh:mm:ssZ` in UTC (RFC 3339, whole seconds). A digest is SHA-256 in lower-case hexadecimal. The writer serialises it in the canonical form of RFC 8785, with no trailing newline, so the same directory gives the same bytes.

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | `1`. |
| `sequence` | yes | The trust sequence of this set of trust products: an integer of at least 1 that grows by one whenever any trust product changes. |
| `signed_at` | yes | When the list was signed: the time of the ceremony. |
| `expires_at` | yes | 13 calendar months after `signed_at`: the same day and time of the month, or the last day of the month if it has none, as for an intermediate. |
| `roots` | yes | The active roots, one or more, in a fixed order: the order in which a hand-off request lists `primaries`. Each is an object below. |
| `last_record_sha256` | yes, except in the list `init` makes | The SHA-256 of the newest [ceremony record](/reference/ceremony-record/) in the directory when the ceremony's plan was made. It anchors the hash chain of the records up to the ceremony before this one; the record of this ceremony is anchored by the next list. The list that `init` makes has no record before it, and leaves the member out. |

Each member of `roots`:

| Member | Required | Meaning |
|---|---|---|
| `label` | yes | The root's label, as in its certificate's subject: `A` and `B` for the two roots `init` makes. 1 to 16 characters, upper-case letters and digits. |
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

`root-list.jws` is a JSON Web Signature (RFC 7515) in compact serialisation with a **detached payload** (RFC 7515, appendix F): `<header>..<signature>`, the two parts Base64url-encoded without padding, with nothing between the dots, and no trailing newline. The payload is the bytes of `root-list.json`, exactly as stored. The signature is computed over `BASE64URL(header) || "." || BASE64URL(those bytes)`.

The protected header has exactly these members:

| Member | Value |
|---|---|
| `alg` | `ES384`: ECDSA on P-384 with SHA-384 (RFC 7518, section 3.4), the signature as the 96 bytes of `r` and `s`. |
| `kid` | The `x509_spki_sha256` of the signing root. |
| `x5c` | A list of one: the signing root's certificate, Base64 DER. It carries the public key; it is never trusted as a certificate. |
| `typ` | `root-list+json`, so that a signature by the same key over another kind of document is not taken for a root list (RFC 8725, section 3.11). |

**Who signs.** One active root, with its X.509 root key: the root used at that ceremony, in the PIV slot that [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) gives it on a card, or the root's file in software mode. One signature, never two.

**When.** A ceremony that changes any trust product writes a new list with the next sequence, signed in the same ceremony. The yearly ceremony and every transition always do, so the list is re-signed at least once a year ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)); so does any other ceremony that signs with a root, because each use re-issues that root's certificate and so changes the CA bundle ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)). The list's bytes are fixed in the ceremony's plan, so the signature is one of the plan's signatures and its touch is counted. `status` warns 60, 30 and 14 days before the newest list expires ([commands](/reference/cli/#exit-codes)).

**Revoking a root** is a new list, signed by a surviving root, without the revoked one, with a CA bundle and a keyring without it beside it.

## How a host reads it

A host holds one list: the last good one. Before its first list it holds **initial pins**, the `x509_spki_sha256` of the roots it was installed to trust, which the operator gives it by a channel of its own. It checks a new list in this order; the first check that fails gives the reason code, and the host keeps the list it holds.

| # | Check | Code |
|---|---|---|
| 1 | `root-list.jws` is a detached compact JWS whose header has exactly the members above, with `alg` `ES384` and `typ` `root-list+json`, and `x5c` is one certificate whose `SubjectPublicKeyInfo` has the SHA-256 `kid`. | `malformed` |
| 2 | `kid` is the pin of an active root of the list the host holds, or one of its initial pins. A revoked root is not on the list, so a list it signs is refused here. | `unknown-signer` |
| 3 | The signature verifies with the key in `x5c` over the bytes of `root-list.json` as read. | `signature-invalid` |
| 4 | `version` is known. | `version-unsupported` |
| 5 | `root-list.json` follows the JSON rules and members above: no unknown or repeated member, `roots` not empty. | `malformed` |
| 6 | `sequence` is not lower than the `sequence` of the list the host holds. Initial pins have no sequence. | `rollback` |
| 7 | The host's clock is before `expires_at`. | `expired` |

The host verifies the bytes it received and does not re-serialise them. When every check passes, the new list replaces the one it holds, and its roots are the host's pins from then on. A list with the same sequence as the one held passes check 6: receiving the current list again is not an error. The signer need not be on the new list: a root that retires may sign the list that removes it, because check 2 reads the list the host held.

**When the list a host holds expires** and no newer one has arrived, it keeps the list, goes on trusting its roots, and raises a warning. It does not drop its roots ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/#the-signed-root-list)).

These codes belong to the host and are not sent anywhere. The vectors fix the outcome and the code, not the wording of a message.

## The CA bundle

`ca-bundle.pem` is text, with LF line endings:

1. The first line is `# trust-sequence: <sequence>`, the sequence of the root list it was built with.
2. Then the current certificate of each root on that list, in the order of `roots`, each PEM-armoured with the label `CERTIFICATE` (RFC 7468), Base64 in lines of 64 characters.
3. Nothing else.

It is deterministic: the same directory gives the same bytes. A PEM parser skips the text outside the armour (RFC 7468, section 2), so OpenSSL reads the file as a list of trust anchors (checked with OpenSSL 3.5.5 on 2026-11-01: `openssl verify -CAfile` with the vectors' bundles accepts the hand-off answers of the roots in the bundle and refuses the others). The root certificates follow the [root profile](/reference/directory/#the-root-certificate).

The bundle is not signed: a TLS client trusts the file it was given. A system that also holds the signed root list uses a certificate from the bundle as an anchor only when its key is on the list it holds, and its sequence is the list's.

## Test vectors

The vectors are in [`testdata/root-list/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/root-list/v1). They are public material only, made by the same run of [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py) as the hand-off vectors, so the roots are the same test roots: A and B are active, Z is on no list, and the list `seq7-a` is the root list of trust sequence 7, which the hand-off answers carry.

- `manifest.json` names each root with its pins and files, the initial pins (A and B), every list with its signer, every case and every bundle.
- A case gives the list the host holds (`held`, or `null` for the initial pins), the list it receives (`candidate`), the clock if it is not the manifest's `2026-11-15T12:00:00Z`, and the expected outcome: `accept`, `refuse` with a reason code, or `warn` with a warning.
- The record digests in the lists are made up.

| Group | Cases |
|---|---|
| Accepted | A first list against the initial pins, and the list `init` makes; an update; an update signed by the other root; a list signed by B without A, which revokes A; the same list again. |
| Refused | A lower sequence (`rollback`); a list signed by the revoked root A after it left the list, and one signed by Z (`unknown-signer`); a list changed after signing (`signature-invalid`); an expired list (`expired`); version 2 (`version-unsupported`); an unknown member (`malformed`). |
| Warned | The held list expired and no newer one came. |
| CA bundles | Sequence 7 with A and B; sequence 8 with B only. |

CI checks that the manifest names every file of the set, that the pins match the root files, that every list's signature verifies except the one a case expects to fail, and that each bundle holds the roots it names under its sequence (`just check-vectors`).

## Choices made

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| Signature | A detached JWS, ES384, by one root's X.509 key. | CMS (RFC 5652); an OpenPGP signature by the primary; minisign or an SSH signature. | The readers already parse JSON and JOSE, every language has a JWS library, and a card or a KMS key makes the raw `r` and `s` that ES384 carries. CMS needs an ASN.1 stack for a JSON file; an OpenPGP signature would need the primary, a second touch, for a list whose audience is the X.509 key's. |
| Where the verifier finds the key | The signing root's certificate in `x5c`; the host trusts only its key, and only when its hash is a pin. | Only `kid`, with the key taken from the CA bundle; a `jwk` header. | The list verifies alone, and comparing the SHA-256 of a DER key with a pin is the same operation as for the hand-off's `issuer`. A `jwk` would need a conversion to compute the same hash. |
| Detached payload | The JSON in a file of its own, the signature beside it. | The payload inside the JWS. | A person can read the list without decoding it, and the bytes signed are the bytes on disk. |
| Canonical form | RFC 8785, verified as read. | Any JSON, signed as written; a reader that canonicalises. | The same directory gives the same bytes, and a reader that never re-serialises cannot get canonicalisation wrong. sluis writes its records in the same form. |
| Order of the checks | The signer and the signature before the version and the members. | The version first, as the hand-off contract does. | Nothing in an unauthenticated list is acted on; the contract's messages have no signature of their own. |
| Explicit type | `typ` `root-list+json`. | No `typ`. | The same key signs the SSH CA key list; a type in the protected header keeps one from being read as the other. |

## Follow-ups

- The code: writing, signing and reading the list and the bundle, with the host rules, and a test that the same inputs give the same bytes ([issue #14](https://github.com/truvity/ritueel/issues/14)).
- The SSH CA key list in the same shape, with its own `typ` and vectors ([issue #55](https://github.com/truvity/ritueel/issues/55)).

:::caution[Open]
- **The command a host runs to check a list.** Issue #14 asks for a verification command with the host rules; its name and arguments are not fixed yet, and the [commands page](/reference/cli/) leaves it out until they are ([issue #14](https://github.com/truvity/ritueel/issues/14)).
- **The label of a root that `root add` makes,** and of a cloud root: `init` names its roots `A` and `B`; the rule for later roots comes with the transitions ([issue #13](https://github.com/truvity/ritueel/issues/13)).
:::

## Standards

| Standard | Used for |
|---|---|
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature, compact serialisation, detached payload (appendix F), `x5c`. |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | `ES384`. |
| [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) | Explicit typing with `typ`. |
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) | The canonical form of `root-list.json`. |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | `SubjectPublicKeyInfo`, the root certificates. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | Version 4 fingerprints. |
| [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PEM armour and the text outside it. |
| [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339), [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) | Times; Base64 and Base64url. |
