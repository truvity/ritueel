---
title: Hand-off contract, version 1
description: What a system that holds intermediate keys sends ritueel for a certificate or a subkey binding, and what comes back. Files, proofs, checks, refusals, vectors.
sidebar:
  order: 1
---

*Design phase: no certifier or requester is built yet. This is version 1 of the specification ([issue #7](https://github.com/truvity/ritueel/issues/7)), and its [test vectors](/reference/hand-off-contract/#test-vectors) match it. The choices that had a real alternative are in [Choices made](/reference/hand-off-contract/#choices-made).*

A system that holds intermediate keys, called the **requester** on this page, and ritueel, called the **certifier**, depend on neither product nor shared code. They meet at standard formats, and this page is the one place that says exactly which. A requester can be built from this page alone, and so can a certifier. The reasons are in [ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/). The vocabulary (root, intermediate, ceremony) is in [Roots, intermediates and transitions](/concepts/roots-and-transitions/).

## What travels

| Kind | The requester sends | The certifier sends back |
|---|---|---|
| X.509 intermediate (`x509-intermediate`) | A PKCS#10 certificate request, and a proof file | A certificate, and a result file |
| OpenPGP signing subkey (`openpgp-subkey`) | The public subkey and its back-signatures (one for every active primary) as OpenPGP packets, and a proof file | The subkey bound by a primary, as OpenPGP packets, and a result file |

The key is made where it will live (a YubiKey slot, a card's OpenPGP applet, an AWS KMS key, or a file in development) and never leaves. Only public keys, signatures and certificates travel. The proof file says where the key lives and carries the evidence for it.

## Messages and files

A message is a set of files that share a **stem**, a name the requester chooses: lower-case letters, digits and hyphens, 1 to 63 characters, starting with a letter or a digit. The certifier repeats the stem in its answer.

| Message | Files |
|---|---|
| X.509 request | `<stem>.csr.pem`, `<stem>.proof.json` |
| OpenPGP request | `<stem>.subkey.pgp`, `<stem>.proof.json` |
| Answer, always | `<stem>.result.json` |
| X.509 answer, issued | `<stem>.cert.pem` |
| OpenPGP answer, issued | `<stem>.bound.pgp` |

**JSON files** are one UTF-8 object, with no byte order mark and no more than 256 KiB. A member name appears once. A member this page does not define is an error, not something to skip. Numbers are integers. A time is `YYYY-MM-DDThh:mm:ssZ` in UTC (RFC 3339, whole seconds). A digest is SHA-256 in lower-case hexadecimal. A certificate or a public key inside JSON is standard Base64 (RFC 4648, with padding) of its DER encoding, as in the `x5c` member of a JSON Web Signature (RFC 7515, section 4.1.6).

**Transport is not specified.** The files may travel in a shared directory, on removable media, as attachments or as pipeline artifacts. No network protocol is defined, and nothing authenticates the requester. Authenticity comes from the ceremony: the requester prints the fingerprint of its key when it makes the request, and the person at the ceremony compares it with the one the certifier shows before anything is signed. Integrity of the answer comes from the answer itself: a certificate or a binding signature verifies against a root that the requester already trusts.

## Versioning

- Every JSON file has the member `handoff`, an integer. This page is version `1`.
- A receiver that does not know the version refuses the message with `version-unsupported` and reads nothing else in it.
- The answer carries the version of the request it answers. A requester refuses an answer whose version is not the one it sent.
- Any change to a member, a rule, a profile or a reason code that can turn an accepted message into a refused one, or the reverse, is a new version. A rewording that changes no outcome in the test vectors is not.
- **The compatibility window.** A release of the certifier states the versions it reads. It drops a version only in a major release, and not earlier than 24 months after the first release that read its successor. The reason is the yearly cadence: a requester installed a year ago must still be understood at its next ceremony, and a second year covers a missed one.
- The test vectors are versioned with the contract (`testdata/hand-off/v1/`). A change to a vector that flips its outcome is a new contract version.

## The proof file

`<stem>.proof.json` ties a request to its evidence.

| Member | Required | Meaning |
|---|---|---|
| `handoff` | yes | The contract version, `1`. |
| `type` | yes | `x509-intermediate` or `openpgp-subkey`. |
| `request_sha256` | yes | SHA-256 of the request: the DER of the CSR, or the bytes of the `.subkey.pgp` file. It binds the proof to its request and catches a swapped pair of files. |
| `store` | yes | Where the key lives: `piv` (a PIV applet, as on a YubiKey), `openpgp-card`, `aws-kms` or `software`. |
| `evidence` | for `piv`, `openpgp-card` and `aws-kms`, absent for `software` | The proof, as below. |
| `primaries` | for `openpgp-subkey` only | The fingerprints (40 hexadecimal digits each, version 4) of every active primary on the signed root list the requester read, in the order of that list. |
| `capabilities` | for `openpgp-subkey` only | The list `["sign"]`. Version 1 binds signing subkeys. |

### `piv`

```json
{ "attestation": ["<slot certificate, Base64 DER>", "<card certificate, Base64 DER>"] }
```

The YubiKey makes two certificates on request. The first is the **attestation certificate of the key's slot**: it says that this key was made inside this token, and carries its policy. The second is the **token's own certificate** (slot F9), which signed the first. The list is in this order, leaf first. Certificates above them (the maker's intermediates) are not on the token. The certifier uses its own pinned copies, and it may use extra ones from the list as untrusted helpers. **A root in the file is never trusted.** Only the roots the certifier has pinned are.

What the certifier reads from the slot certificate (checked on a test YubiKey 5, firmware 5.8.0, on 2026-10-31):

| Extension (`1.3.6.1.4.1.41482.3.…`) | Content |
|---|---|
| `.3` | Firmware version, three raw bytes (`05 08 00` is 5.8.0). |
| `.7` | Serial number, a DER INTEGER. |
| `.8` | Two raw bytes: PIN policy (1 never, 2 once, 3 always), then touch policy (1 never, 2 always, 3 cached). |
| `.9` | Form factor, one raw byte. |

Firmware 5.7 and newer chain to the maker's *current* attestation root; older tokens chain to the earlier PIV root. The certifier pins whichever roots the holder lists, so a chain that ends in an unpinned root is refused. The certifier also needs the maker's **intermediates**: the list that piv-go v2.6.0 embeds lacks the intermediate that firmware 5.8 uses, and its built-in verification fails (measured 2026-11-01). The certifier's pinned set is therefore the maker's current root plus the full intermediate bundle, and a card whose intermediate is missing from it is refused until the bundle is refreshed.

### `openpgp-card`

```json
{ "attestation": ["<key certificate, Base64 DER>", "<card certificate, Base64 DER>"] }
```

The key lives in the OpenPGP applet of a card, and the card attests it with its own command (on a YubiKey, `80 FB 01 00`, after the user PIN is verified). The list holds the certificate the card returns for the key, then the card's own attestation certificate that signed it, leaf first. The certifier chains them to a pinned root of the maker through the maker's intermediates, from its own pinned copies, as for `piv`; on firmware 5.8 the chain passes through the intermediate "Yubico OPGP Attestation B2 1" (measured 2026-11-01). The extensions of the certificate are under the OID arc `1.3.6.1.4.1.41482.5`. Their encoding, and so the policy rules that read them, are not specified yet (see [Follow-ups](/reference/hand-off-contract/#follow-ups)); a certifier that cannot read them records the key as attested and does not enforce a PIN or touch policy. This store is the one a person's daily subkey uses, with the person's own card as the requester.

### `aws-kms`

```json
{ "key_arn": "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555",
  "public_key": "<the public key, Base64 DER SubjectPublicKeyInfo>" }
```

The ARN names the key together with its Region and account. A bare key identifier does not, and the same identifier can exist in two Regions. The public key is a claim. **The certifier does not trust it: it reads the key from KMS** with `DescribeKey`, `GetPublicKey` and `GetKeyPolicy`, and compares. A key in the certifier's own account is read with its own credentials. **A key in another account is read through a small read-only role inside that account**, because `GetKeyPolicy` does not work across accounts (AWS documentation, checked 2026-11-01). The requester creates the role. It allows `DescribeKey`, `GetPublicKey` and `GetKeyPolicy` on that key, nothing else (no `Sign`), and trusts the certifier's principal to assume it. The certifier assumes the role and reads the key and its policy as a same-account caller, so the single-principal rule below is checked the same way for both. The role's ARN is not taken from the request: the certifier's policy lists it for the requester, so a request cannot make the certifier assume a role of its choosing. **The certifier re-reads the public key itself. It never accepts a copy of the description, the policy or the key in the proof**, not even one marked unverified. A proof whose key the certifier cannot read is refused (`proof-invalid`). **KMS has no attestation.** The evidence for a KMS key is what the certifier reads: the key's description, its policy and the audit trail of its uses. Two further facts apply to an OpenPGP key in KMS (measured 2026-11-01). A P-384 key signs only 48-byte SHA-384 digests, which is the hash the contract uses everywhere. The OpenPGP creation time fixes the fingerprint and is not KMS's creation date, so the requester has to keep it (for example as a tag on the key) and put it in the subkey packet; the certifier takes it from the packet.

### `software`

No `evidence`. A software key proves nothing about where it lives. The certifier accepts it only when its policy says so, which is the development setting, and it records the key as unprotected.

## X.509 intermediate

### The request

`<stem>.csr.pem` is a PKCS#10 certificate request (RFC 2986), PEM-armoured with the label `CERTIFICATE REQUEST`.

- The key is ECDSA on P-384 (`id-ecPublicKey` with `secp384r1`). Version 1 accepts no other key type.
- The request is signed by that key with `ecdsa-with-SHA384`. This is the proof of possession; for a key in a YubiKey or in KMS the device makes the signature.
- The subject is the name the requester wants in the certificate. The certifier issues it as asked or refuses; it never rewrites it.
- The extensions the requester wants are in the standard `extensionRequest` attribute (RFC 2985, section 5.4.2). Version 1 knows these:

| Extension | In the request |
|---|---|
| Basic constraints | Critical. `cA` true, path length 0. |
| Key usage | Critical. `keyCertSign` is required. `cRLSign` and `digitalSignature` may be added. |
| Name constraints | Critical. At least one permitted subtree. |
| Extended key usage | Optional. |

Any other extension is refused with `policy`.

The certifier **issues exactly what was asked, or refuses**. The request is the requester's statement of how much power it needs, and the policy of the certifier says how much it may have. A request for more than the policy allows is refused, not trimmed. Validity is the one thing the request does not carry: the certifier decides it.

### What the certifier checks

In this order. The first check that fails gives the reason code; the others are not reported.

| # | Check | Code |
|---|---|---|
| 1 | The contract version is known. | `version-unsupported` |
| 2 | The files parse, with no unknown or repeated member. | `malformed` |
| 3 | `request_sha256` is the digest of the request. | `request-mismatch` |
| 4 | The key is ECDSA P-384. | `algorithm-unsupported` |
| 5 | The request's signature verifies with its own key. | `possession-invalid` |
| 6 | The store is allowed by the policy. | `store-not-allowed` |
| 7 | The evidence is valid, as below. | `proof-invalid` |
| 8 | The key in the evidence is the key in the request. | `key-mismatch` |
| 9 | The policy accepts the request, as below. | `policy` |
| 10 | The person at the ceremony confirms. | `declined` |

**Evidence for a PIV key (check 7).** Both certificates parse. The chain from the slot certificate through the token's certificate and the maker's intermediates leads to a pinned root, with every certificate valid at the time of the ceremony; the token's certificate is a CA with path length 0. The slot certificate's subject is `YubiKey PIV Attestation <slot>`, where the slot is one of 9a, 9c, 9d, 9e or 82 to 95, and the extensions `.3`, `.7` and `.8` are present. **Evidence for an OpenPGP-card key (check 7).** Both certificates parse, and the chain from the key's certificate through the card's certificate and the maker's OpenPGP intermediates leads to a pinned root, with every certificate valid at the time of the ceremony. **Evidence for KMS (check 7).** The key's state is `Enabled`, its usage `SIGN_VERIFY`, its spec `ECC_NIST_P384`, its origin `AWS_KMS` and its manager `CUSTOMER`, and the ARN in the proof is the ARN KMS reports.

**Key match (check 8).** The attested public key (PIV or OpenPGP card), the key KMS returns, and the `public_key` in the proof, where one is given, are all the key in the request.

**Policy (check 9).** The policy is the certifier's, and is not part of the wire format. The reference policy of the test vectors has these rules, and a certifier may add more:

| Rule | Reference value |
|---|---|
| Firmware of a YubiKey | 5.7.0 or newer. |
| PIN policy of the key | Once or always. Never is refused. |
| KMS key policy | Every statement that allows `kms:Sign` (directly, or through `kms:*`) names the same single principal: a role or a user, not a wildcard and not the account root. |
| Name constraints | Present, and every permitted subtree inside the subtrees the policy lists for the requester. |
| Validity | 13 calendar months. |

Touch policy and form factor are read and recorded, and the reference policy does not enforce them.

### What is issued

The profile of the certificate. The requester can check every row.

| Field | Value |
|---|---|
| Version, serial | 3. A positive number of at most 20 bytes from a cryptographic random source, with at least 64 random bits. |
| Signature | `ecdsa-with-SHA384`, made by a root on P-384. |
| Issuer | The subject of the issuing root. |
| Subject, public key | The CSR's, unchanged. |
| Validity | `notBefore` is the ceremony time; `notAfter` is 13 calendar months later (same day and time of the month, or the last day of the month if it has none), both UTC. |
| Basic constraints | Critical. `cA` true, path length as requested (0 in version 1). |
| Key usage | Critical. Exactly as requested. |
| Name constraints | Critical. Exactly as requested. |
| Extended key usage | Exactly as requested, or absent. |
| Subject key identifier | Not critical. The leftmost 160 bits of the SHA-256 of the subject public key bits (RFC 7093, section 2, method 1). |
| Authority key identifier | Not critical. The `keyIdentifier` of the issuing root, computed the same way. |
| Anything else | Absent. |

`<stem>.cert.pem` holds the issued certificate and nothing else, because a root issues an intermediate directly. **The root is not in the file.** The requester takes its anchors from its own root list, never from the answer. `result.json` names the issuing root so the requester can tell which anchor to use.

### What the requester checks before it installs

Each failure gives one of these codes. They belong to the requester and are not sent anywhere.

| Check | Code |
|---|---|
| The answer's version is the one sent, and `request_sha256` is the digest of its own request. | `version-unsupported`, `request-mismatch` |
| The certificate verifies to an anchor in its root list, which is at least `trust_sequence` of the answer. | `issuer` |
| The public key is its own key. | `key-mismatch` |
| The subject, basic constraints, key usage, name constraints and extended key usage are exactly what it asked. No extension outside the profile is critical. | `profile` |
| The validity is the length it expects (for example 12 to 14 months) and has not ended. | `validity` |
| The digests in `result.json` match the files. | `malformed` |

## OpenPGP signing subkey

### Keys and hashes

Version 1 uses version 4 keys: the primary and the subkey are ECDSA on P-384 (algorithm 19, curve OID `1.3.132.0.34`). RFC 9580 (section 5.2.3.2) wants a digest of at least 384 bits for P-384. Every signature of the contract uses **SHA-384**, which is also the 48-byte digest a YubiKey or a KMS key signs as it is given; a KMS P-384 key accepts no other digest length. Other algorithms are refused with `algorithm-unsupported`. OpenPGP version 6 keys wait for a later version of the contract, once the verifiers people use accept them; GnuPG (`gpg` 2.4.8) refuses to parse a version 6 certificate ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys)).

### The request

`<stem>.subkey.pgp` is binary OpenPGP and holds one Public-Subkey packet followed by one back-signature for every primary in `primaries`, in this order:

1. A **Public-Subkey packet** (tag 14) with the subkey.
2. One **Signature packet** (tag 2) of type `0x19` for every active primary, in the order of `primaries`: the primary key binding, also called the **back-signature**. Each is made by the subkey, and says that the subkey agrees to belong to that primary (RFC 9580, section 5.2.1.9). It signs the primary key and then the subkey, each as `0x99`, a two-byte length and the packet body, followed by the usual signature trailer. Its hashed area has the signature creation time and the issuer fingerprint of the subkey. Its unhashed area has the issuer key ID of the subkey (see [Issuer key ID](/reference/hand-off-contract/#issuer-key-id)).

Because a back-signature covers the primary's key, it must exist before that primary can bind the subkey. **The request therefore back-signs for every active primary.** The requester reads the signed root list it already trusts, takes the active primaries from it, and makes one back-signature for each, in one request. Either root card can then make the binding: the card of the year, the other card next year, or the surviving card after one is lost, with no second request. The binding itself is made by one primary, the one the ceremony uses.

A subkey with a back-signature that is missing for a listed primary, of another type, made over another primary, without the issuer key ID, or damaged is refused with `possession-invalid`. GnuPG and Sequoia refuse a signing subkey without a good back-signature, so the certifier does not bind one.

### What the certifier checks

The same ten checks and codes as for X.509, with these differences.

| # | In OpenPGP |
|---|---|
| 3 | After the digest, `primaries` must be exactly the active primaries on the certifier's signed root list. A listed primary the certifier does not hold, or an active one the list leaves out, gives `unknown-primary`: the requester's root list is not current. |
| 4 | The subkey is ECDSA P-384. |
| 5 | The packets are the ones above, one back-signature for each listed primary. Each has type `0x19` and verifies with the subkey over that primary and the subkey, and carries the issuer fingerprint and the issuer key ID of the subkey. `capabilities` is `["sign"]`. |
| 7, 8 | As for X.509. The key in the evidence is the point of the subkey. |
| 9 | Reference policy: as for X.509, without the name constraints rule. |

### What comes back

`<stem>.bound.pgp` holds two packets: the same Public-Subkey packet, and a **subkey binding signature** (type `0x18`) made by the primary:

| Part | Value |
|---|---|
| Hashed area | Signature creation time (the ceremony time). Key flags: `0x02`, signing only. Key expiration time, marked critical, in seconds after the subkey's creation, so that the subkey ends at the same instant a certificate issued at that ceremony would. Issuer fingerprint of the primary. |
| Unhashed area | Issuer key ID. **Embedded signature** (subpacket 32): the request's back-signature for this primary, unchanged. |

Add the packets to the primary's certificate to get the updated certificate, with any tool that concatenates files:

```sh
cat test-primary-a.pgp pgp-piv-valid.bound.pgp > updated.pgp
```

A verifier then needs nothing from ritueel. The first set of vectors was checked this way with `sqv` on 2026-11-01: a signature made by an accepted subkey verifies against `updated.pgp`, and one made by a subkey whose answer lacks the embedded back-signature, or was bound by another primary, does not. The ritueel keyring package carries the same certificates ([issue #15](https://github.com/truvity/ritueel/issues/15)).

### What the requester checks before it installs

| Check | Code |
|---|---|
| The version, and `request_sha256`, as for X.509. | `version-unsupported`, `request-mismatch` |
| The first packet is its own subkey. | `key-mismatch` |
| The binding verifies, with the primary's key from its keyring, over that primary and the subkey, and the primary is one of those it named. | `issuer` |
| The key flags are exactly signing. The embedded signature is its own back-signature for that primary. | `profile` |
| The expiry is the length it expects, and has not passed. | `validity` |

### Issuer key ID

Every version 4 signature ritueel writes, and every back-signature it accepts, carries **both** the Issuer Fingerprint subpacket (type 33, hashed) and the Issuer Key ID subpacket (type 16, unhashed). go-crypto v1.5.2 writes a version 4 signature with the fingerprint only, and `gpg` 2.2.27 rejects a certificate made of such signatures on import, so a signature without the key ID is not safe to ship (measured 2026-11-01). The rule is in [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys) too.

## The answer

`<stem>.result.json`:

| Member | Meaning |
|---|---|
| `handoff`, `type`, `request_sha256` | As in the request. `request_sha256` is the digest of the request that was answered. |
| `outcome` | `issued` or `refused`. |
| `reasons` | When refused: a list of one or more codes from the table below. |
| `artifacts` | When issued: a list of `{ "name", "sha256" }`, one for each file of the answer other than this one. |
| `valid_from`, `valid_until` | The validity that was issued. |
| `issuer` | For X.509, the SHA-256 of the DER `SubjectPublicKeyInfo` of the issuing root. For OpenPGP, the fingerprint of the primary. |
| `trust_sequence` | The sequence number of the trust set (root list, CA bundle and keyring) that the answer belongs to. The requester must hold a root list at least this recent before it installs. |

A refused answer holds no artifacts and no secret. The codes:

| Code | Meaning |
|---|---|
| `version-unsupported` | The contract version is not known. |
| `malformed` | A file does not parse, or has an unknown or repeated member. |
| `request-mismatch` | The proof is not for this request. |
| `unknown-primary` | OpenPGP only: `primaries` is not the set of active primaries the certifier holds. |
| `algorithm-unsupported` | The key is not ECDSA P-384. |
| `possession-invalid` | The request's signature, or the back-signature, does not verify or is not the right kind. |
| `store-not-allowed` | The policy does not allow this key store. |
| `proof-invalid` | The evidence does not verify. |
| `key-mismatch` | The evidence is for another key. |
| `policy` | A rule of the certifier's policy refuses it. |
| `declined` | The person at the ceremony did not confirm. |

The answer does not say which part of a policy failed. The certifier's output and its ceremony record do.

**Trust products.** The CA bundle, the keyring and the signed root list are not part of this contract, and the certifier publishes them as it does for everyone ([ADR 0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/)). The contract fixes one thing about them: they carry the **trust sequence**, one integer that grows by one each time any of them changes, and `trust_sequence` in the answer says which one the answer needs. The root list's own format is [issue #14](https://github.com/truvity/ritueel/issues/14).

## What the certifier records

The ceremony record ([issue #9](https://github.com/truvity/ritueel/issues/9)) gets, for each request: the digests of the request and the proof; the store; the fingerprint of the key; for a YubiKey the serial, firmware, PIN and touch policy and form factor read from the attestation; for KMS the ARN, the key's description and the digest of its policy; the policy that was applied; the result and the digests of the artifacts. It never holds a PIN, a passphrase or a key. The record does not decide anything on this page.

## Test vectors

The vectors are in [`testdata/hand-off/v1/`](https://github.com/truvity/ritueel/tree/main/testdata/hand-off/v1). They are public material only: CSRs, certificates, public subkeys, signatures and JSON files. Every key was made in software by [`generate.py`](https://github.com/truvity/ritueel/blob/main/testdata/hand-off/generate.py), and its private half was never written down. The attestation hierarchy is a made-up "Example Test" hierarchy, not the maker's, and the certifier's roots are test roots.

- `manifest.json` lists every case with its files, the policy configuration it runs under, and the expected outcome and reason. A test in the Go code will read it ([issue #7](https://github.com/truvity/ritueel/issues/7), done when).
- `pki/` holds the pinned test attestation root and intermediates (one for the PIV applet, one for the OpenPGP applet), and the certifier's test roots: A and B are on the signed root list, each an X.509 root and an OpenPGP primary, as on two root cards; Z is on no list.
- The clock of every vector is `2026-11-15T12:00:00Z`. A test fixes its clock to that time, so the vectors do not expire.
- Two configurations: `production` (a PIV, OpenPGP-card or KMS key; software refused) and `development` (software allowed). Both use the reference policy above, and both list the read-only role for the one other account the KMS vectors use (`kms_read_roles`).
- A KMS case comes with `<case>.kms-stub.json`: the answers of `DescribeKey`, `GetPublicKey` and `GetKeyPolicy` that a test replays instead of calling AWS. For a key in another account the stub starts with `assume_role`, the role the certifier must assume first, and its answers are the ones that role gets.

| Group | Accepted | Refused |
|---|---|---|
| X.509 requests | A PIV key, a KMS key, a KMS key in another account read through its role, a software key in development. | Software in production, a bad CSR signature, a P-256 key, version 2, a proof for another request, an unknown member, an attested key that is not the request's, an untrusted attestation chain, PIN policy never, old firmware, no name constraints, a name constraint outside the policy, a KMS key that is not the request's, a KMS policy that names two actors, a KMS key in an account with no read role. |
| X.509 answers | A PIV key, a KMS key, a software key, an answer from the other root. | Another key, path length 1, expired, an issuer that is not on the root list. |
| OpenPGP requests | A PIV key, a KMS key, an OpenPGP-card key, a software key; each with a back-signature for both active primaries. | No back-signature; one for only one primary; one over a primary not on the list, of type `0x18`, damaged, or without the issuer key ID; version 2; a primary not on the list; `primaries` missing an active one; an attested key that is not the subkey; an untrusted OpenPGP-card chain; an Ed25519 subkey. |
| OpenPGP answers | A PIV key, a KMS key, an OpenPGP-card key, a software key, a binding by the other primary. | No embedded back-signature, another subkey, a primary not on the list, an expiry of two months. |

CI checks that the manifest names every file of the set, that every file it names is in the repository, and that the digests in the proofs and results match their files (`just check-vectors`).

A certifier passes when its outcome and reason code match the manifest for every request; a requester passes when its decision and code match for every answer. The vectors fix the outcome and the code, not the wording of a message.

## Choices made

The choices that had a real alternative, with the reason each alternative lost.

| Choice | Chosen | Other options | Why |
|---|---|---|---|
| Encoding of the proof file | JSON, with certificates and keys as Base64 DER. | CBOR; ASN.1 DER; one PEM file with headers; a TAR holding everything. | Readable by a person who must compare it with what they expect. Every language has a strict parser. The `x5c` precedent covers the encoding of certificates. CBOR and DER are smaller and harder to read; PEM headers have no standard shape. |
| Compatibility window | Read the previous version for 24 months after its successor first ships. | A fixed 12 months; "any older version, always". | Ceremonies are yearly. A year is not enough for a missed one. |
| Unknown members | Refused. | Ignored. | An ignored member is a field one side thinks it understands. |
| KMS key in another account | The certifier assumes a small read-only role inside the key's account (`DescribeKey`, `GetPublicKey`, `GetKeyPolicy`) and reads the key and its policy as a same-account caller | Grant the certifier's principal access in the key policy, which `GetKeyPolicy` does not honour across accounts; accept a snapshot of the description in the proof and mark it unverified; apply the policy rule to same-account keys only. | A copy is a claim, and the contract's rule is that the certifier reads the key itself. Only a role in the key's account can read the policy, so the rule is checked for every key. |
| Certificate file | The issued certificate only; the root is named in `result.json`. | The chain with the root included. | A root in a file invites trusting it. |
| Who decides validity and constraints | The certifier decides validity. The requester asks for constraints in the CSR, and the certifier issues them exactly or refuses. | The certifier overrides the request; the requester asks for validity. | Silent change is the failure to avoid: the requester then installs something it did not ask for. |
| OpenPGP request | The subkey and a back-signature for every active primary, plus the proof naming the primaries. | One primary per request, with a second request for the second root; the whole primary certificate in the request. | Either root card can make the binding, with no second request, and the requester need not know whose year it is. The certifier already holds the primaries. Cost: one more signature in the request for each active primary. |

## Follow-ups

- **The attestation of an OpenPGP-card key.** The encoding of the extensions under `1.3.6.1.4.1.41482.5`, and the policy rules that read them, are not measured yet; until then a certifier records the key as attested and enforces no PIN or touch policy from it ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- **GnuPG on the vectors.** `gpg` and `gpgv` join the verifier matrix for the OpenPGP vectors ([issue #25](https://github.com/truvity/ritueel/issues/25)).
- **The fixture generator** becomes Go once the module exists, so one toolchain builds everything ([issue #10](https://github.com/truvity/ritueel/issues/10)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986) | PKCS#10 certificate request. |
| [RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985) | The `extensionRequest` attribute. |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The certificate profile, name constraints, key usage. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The key identifiers. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | OpenPGP packets, signature types `0x18` and `0x19`, subpackets. |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | The `x5c` precedent for certificates in JSON. |
| [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) | Base64. |
| The maker's PIV attestation documentation | The extension arc `1.3.6.1.4.1.41482.3` and the attestation chain. The encodings above were measured on 2026-10-31. |
| AWS KMS API | `DescribeKey`, `GetPublicKey`, `GetKeyPolicy`, `Sign`. |
