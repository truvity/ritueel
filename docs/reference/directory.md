---
title: The directory, ritueel.yaml, root profiles and key files
description: The layout of the operator's ritueel directory, the ritueel.yaml schema, the root certificate and primary profiles, and the software root's key files.
sidebar:
  order: 6
---

*Not built yet. This is the layout the M1 code writes ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9)); the rules it follows are in [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-directory-and-the-records).*

ritueel keeps everything it knows in **one directory of plain files** that the holder keeps in version control and backs up. This directory is the *ledger* that [Learn](/learn/the-ledger/) advises on: where to keep it, and how to back it up and restore it. It holds public material only: never a private key, a PIN, a passphrase or a revocation signature. Losing it loses the registry, the attestations and the OpenPGP creation times, so it is part of every key's identity ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#consequences)). A software root's private keys live in **key files outside it**.

## The layout

| Path | Written by | Holds |
|---|---|---|
| `ritueel.yaml` | The operator | The name, the release address, the policy and the intermediates ([below](/reference/directory/#ritueelyaml)). |
| `cards.yaml` | ritueel | The registry of cards that held a root, from M2. Absent while every root is in software ([the registry](/reference/cards/#the-registry-cardsyaml)). |
| `roots/<label>/root.json` | ritueel | The facts of one root ([below](/reference/directory/#rootjson)). |
| `roots/<label>/x509.pem` | ritueel | The root's current certificate. |
| `roots/<label>/openpgp.pgp` | ritueel | The primary's current public certificate, binary. |
| `roots/<label>/attestation/` | ritueel | For a root on a card or in KMS: the attestation or the key's description and policy, as read at `init` ([cards](/reference/cards/#files), [KMS](/reference/kms-root/#evidence-files)). |
| `roots/<label>/ssh-break-glass.pub` | ritueel | From M3: the root's break-glass SSH CA key, one OpenSSH line ([the SSH CA key list](/reference/ssh-ca-key-list/#how-a-key-enters-the-list)). |
| `requests/<stem>.*` | The operator | Pending requests: the files of the [hand-off contract](/reference/hand-off-contract/#messages-and-files), one stem each. |
| `answers/<stem>.*` | ritueel | The answers: `<stem>.result.json`, and `<stem>.cert.pem` or `<stem>.bound.pgp`. |
| `plans/`, `attempts/`, `records/`, `transcripts/` | ritueel | The [ceremony files](/reference/ceremony-record/), one of each kind for each ceremony. A ceremony that makes keys also writes `attempts/<ceremony>.births.jsonl`, the [birth journal](/reference/ceremony-record/#the-birth-journal). |
| `products/<sequence>/` | ritueel | The trust products of one trust sequence: `root-list.json`, `root-list.jws` and `ca-bundle.pem` ([the root list](/reference/root-list/#files)); from M2 `crl-<label>.pem` for each active root ([the CRLs](/reference/crl/#files)); from M3 `ssh-ca-keys.json`, `ssh-ca-keys.jws` and `ssh-user-ca-keys.pub` ([the SSH CA key list](/reference/ssh-ca-key-list/#files)), `keyring/` ([the keyring package](/reference/keyring-package/#files)) and `revocations/`. |

- ritueel never writes `ritueel.yaml` or `requests/`, and the operator does not edit the other paths.
- A file that a ceremony replaces, such as `x509.pem`, keeps its history in `products/` and in version control. Nothing under `products/`, `plans/`, `attempts/`, `records/` or `transcripts/` is ever overwritten.
- ritueel refuses a request whose stem already has an answer.
- The directory is found by `--dir DIR`, or is the current directory when it holds `ritueel.yaml` ([Commands](/reference/cli/#flags-every-ceremony-shares)).

## `ritueel.yaml`

The operator writes it before `init`. An unknown key is an error, as in the contract.

```yaml
version: 1
name: Example                    # in the roots' subjects and user IDs
release_address: release@example.com
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
intermediates:
  - name: example-ca
    type: x509-intermediate
    permitted_uri_hosts: [example.com]
  - name: example-release
    type: openpgp-subkey
    kms_read_roles:
      "111122223333": arn:aws:iam::111122223333:role/example-certifier-read
  - name: example-ssh
    type: ssh-ca-key
    use: user
keyring:
  license: CC0-1.0
```

| Key | Meaning |
|---|---|
| `version` | `1`. |
| `name` | 1 to 64 characters: letters, digits, spaces and hyphens. It names the roots and their primaries ([below](/reference/directory/#the-root-certificate)). |
| `release_address` | The address in every primary's user ID: the project's release identity, never a person's ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys)). |
| `policy` | The rules every request is checked against: `stores`, `min_firmware`, `pin_policy`, `require_name_constraints` and `validity_months`, with the meanings of the [reference policy](/reference/hand-off-contract/#what-the-certifier-checks). All five are required. |
| `intermediates` | The intermediates ritueel may certify, one entry each. `name` is the `NAME` of the commands: lower-case letters, digits and hyphens, 1 to 63 characters, unique. `type` is `x509-intermediate`, `openpgp-subkey` or `ssh-ca-key`. |
| `intermediates[].permitted_uri_hosts` | For `x509-intermediate`: the hosts a request's name constraints must stay inside. Required when `require_name_constraints` is true. Only URI hosts are expressible in version 1. **Planned:** permitted and excluded DNS subtrees and excluded IP ranges, for an intermediate that issues for DNS names and for per-environment limits; the schema will grow when a first installation needs it. |
| `intermediates[].use` | For `ssh-ca-key`: `user` or `host`, required. A request for another `use` is refused with `policy`; the key is listed with this use ([the contract](/reference/hand-off-contract/#ssh-ca-key)). |
| `kind` | Optional. `personal` for a person's own OpenPGP key; absent for a company directory. A personal directory has `person` instead of `name` and `release_address` ([personal OpenPGP](/reference/personal-openpgp/)). |
| `person` | Only with `kind: personal`: `name` (1 to 64 characters) and `address`. |
| `aws_kms` | Optional, from M2; required when a root's store is `aws-kms`. The root account, the two Regions and the two roles ([the block](/reference/kms-root/#ritueelyaml)). |
| `keyring` | Optional. `license` is the SPDX identifier written into the `.rpm`, required to build one: the operator's choice, which ritueel does not default ([the keyring package](/reference/keyring-package/)). |
| `intermediates[].kms_read_roles` | For a requester's KMS key in another account: the read-only role to assume, by account ([the contract](/reference/hand-off-contract/#aws-kms)). The role is never taken from a request. |

A test vector's configuration in `testdata/hand-off/v1/manifest.json` is the `policy` block together with the one intermediate entry its requests are for: the `permitted_uri_hosts` and `kms_read_roles` there are that entry's.

:::note[Proposed]
The rules a request is checked against are split: the store, firmware, PIN and validity rules in `policy`, the name constraints and the KMS read roles in each intermediate's entry, because the contract says the policy lists them **for the requester**. An intermediate is declared here by the operator, and `intermediate add` registers it by its record; ritueel never rewrites this file.
:::

The schema, in JSON Schema (draft 2020-12), which the code ships and checks the file against:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "policy"],
  "allOf": [
    { "if": { "required": ["kind"] },
      "then": { "required": ["person"], "not": { "anyOf": [{ "required": ["name"] }, { "required": ["release_address"] }] } },
      "else": { "required": ["name", "release_address"] } }
  ],
  "properties": {
    "version": { "const": 1 },
    "kind": { "const": "personal" },
    "person": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "address"],
      "properties": {
        "name": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 .'-]{0,63}$" },
        "address": { "type": "string", "format": "email" }
      }
    },
    "name": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 -]{0,63}$" },
    "release_address": { "type": "string", "format": "email" },
    "policy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["stores", "min_firmware", "pin_policy", "require_name_constraints", "validity_months"],
      "properties": {
        "stores": { "type": "array", "uniqueItems": true, "minItems": 1,
                    "items": { "enum": ["piv", "openpgp-card", "aws-kms", "software"] } },
        "min_firmware": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$" },
        "pin_policy": { "type": "array", "uniqueItems": true, "minItems": 1,
                        "items": { "enum": ["never", "once", "always"] } },
        "require_name_constraints": { "type": "boolean" },
        "validity_months": { "type": "integer", "minimum": 1 }
      }
    },
    "keyring": {
      "type": "object",
      "additionalProperties": false,
      "properties": { "license": { "type": "string", "minLength": 1 } }
    },
    "aws_kms": {
      "type": "object",
      "additionalProperties": false,
      "required": ["account", "region", "replica_region", "admin_role", "ceremony_role"],
      "properties": {
        "account": { "type": "string", "pattern": "^[0-9]{12}$" },
        "region": { "type": "string", "minLength": 1 },
        "replica_region": { "type": "string", "minLength": 1 },
        "admin_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
        "ceremony_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" }
      }
    },
    "intermediates": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "type"],
        "properties": {
          "name": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$" },
          "type": { "enum": ["x509-intermediate", "openpgp-subkey", "ssh-ca-key"] },
          "use": { "enum": ["user", "host"] },
          "permitted_uri_hosts": { "type": "array", "uniqueItems": true, "items": { "type": "string" } },
          "kms_read_roles": { "type": "object", "propertyNames": { "pattern": "^[0-9]{12}$" },
                              "additionalProperties": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" } }
        }
      }
    }
  }
}
```

Five rules the schema cannot state: the two Regions of `aws_kms` differ, both its roles are in `account`, intermediate names are unique, an `x509-intermediate` has `permitted_uri_hosts` when `require_name_constraints` is true, and an `ssh-ca-key` has `use` and no other key of the entry. A name that begins with `break-glass-` is refused, because the SSH CA key list uses those for the break-glass keys. ritueel checks all of them when it reads the file.

## `root.json`

`roots/<label>/root.json` is one canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)), written at `init` or `root add` and not changed after, except `retired_at`, `revoked_at` and `revoked_reason`.

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `label` | The root's label: one upper-case letter, `A` and `B` for the two roots `init` makes, then the next free letter for each root `root add` makes, whatever its key store. It never names the store and is never reused. |
| `store` | `software`, `piv` or `aws-kms`. |
| `test` | True for a root made with `--test-root`. |
| `created_at` | When the root was made: the time of its ceremony. |
| `x509_spki_sha256` | The pin of the X.509 root key. |
| `openpgp_fingerprint` | The primary's fingerprint. |
| `openpgp_created` | The OpenPGP creation time of the primary, which fixes its fingerprint and is on no card ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| `revocations` | An object from reason (`compromised`, `superseded`, and any the holder added) to the SHA-256 of that revocation signature packet, which is stored elsewhere ([revocation material](/reference/revocation-material/)). |
| `store_ref` | From M2, for a root in `piv` or `aws-kms`; absent for `software`. For `piv`: `{ "serial", "x509_slot", "openpgp_slot", "ssh_slot" }`, the card's row in [`cards.yaml`](/reference/cards/#the-registry-cardsyaml) and the slots of the [slot map](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards). For `aws-kms`: `{ "x509_arn", "openpgp_arn", "ssh_arn" }`, the ARNs of the primary keys ([the cloud root](/reference/kms-root/#what-ritueel-creates)). |
| `revoked_at` | Present once the root is revoked. |
| `replaces`, `overlap_until`, `vouched_by`, `vouches`, `retired_at`, `revoked_reason` | From M3, as [the transitions page](/reference/transitions/#in-rootjson) says. `retired_at` and `revoked_at` are the only members changed after the root is written. |

## The root certificate

Every root's X.509 certificate has this profile. A relying party can check every row.

| Field | Value |
|---|---|
| Version, serial | 3. A positive number of at most 20 bytes from a cryptographic random source, with at least 64 random bits. |
| Signature | `ecdsa-with-SHA384`, self-signed with the root's own P-384 key. |
| Issuer, subject | The same name: one common name, `<name> Root <label>`, from `ritueel.yaml`, for example `CN=Example Root A`. A test root's name ends in ` (TEST ONLY)`: `CN=Example Root A (TEST ONLY)`. |
| Subject public key | The root's X.509 key: ECDSA on P-384. |
| Validity | `notBefore` is the ceremony time; `notAfter` is 36 calendar months later (same day and time of the month, or the last day of the month if it has none), both UTC. |
| Basic constraints | Critical. `cA` true, no path length. |
| Key usage | Critical. `keyCertSign` and `cRLSign`. |
| Subject key identifier | Not critical. The leftmost 160 bits of the SHA-256 of the subject public key bits (RFC 7093, section 2, method 1), as in the [intermediate's profile](/reference/hand-off-contract/#what-is-issued). |
| Name constraints | Absent: constraints belong to the intermediates. |
| Anything else | Absent, the authority key identifier included (RFC 5280, section 4.2.1.1, allows it in a self-signed certificate). |

**Each use re-issues it.** Every ceremony that signs with a root makes a new certificate over the same key and the same subject, with a new serial, starting at the ceremony time ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)). A root that is used every year or two therefore never comes close to its end, and pins on its key never change.

## The OpenPGP primary

Every root's OpenPGP primary has this profile, as [ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys) decides.

| Part | Value |
|---|---|
| Key | Version 4, ECDSA on P-384 (algorithm 19). The creation time is `openpgp_created`. |
| User ID | One: `<name> Release Root <label> <release_address>`, for example `Example Release Root A <release@example.com>`. A test root's adds ` (TEST ONLY)` before the address. No person's name. |
| Self-signature | A positive certification (type `0x13`) of the user ID, SHA-384. Hashed: signature creation time (the ceremony time), key flags `0x01` (certify only), key expiration time, marked critical, so that the key expires 36 calendar months after the ceremony, and the issuer fingerprint. Unhashed: the issuer key ID ([the packet rule](/reference/hand-off-contract/#issuer-key-id)). |
| Subkeys | None of its own. It binds the signing subkeys of intermediates through the hand-off. |
| Revocation | A key revocation signature (type `0x20`), made when the key is born and stored apart from it. |

**Each use extends it,** with a new self-signature of the same shape at the ceremony time.

The test roots of the [hand-off vectors](/reference/hand-off-contract/#test-vectors) follow both profiles, with the name `Example Test`.

## The software root's key files

A software root ([the `software` store](/decisions/0003-key-stores-and-the-card-layer/#four-stores-behind-one-interface)) serves tests, drills and development, and never anchors a signed release ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)). Its private keys are in files in a **key directory**, given by `--key-dir DIR`, which ritueel refuses when it is inside the directory. Every command that writes them, and every record of a ceremony that uses them, says that a software root can be copied.

| File | Content |
|---|---|
| `<label>.x509.key.age` | The X.509 root key: a PKCS#8 `PrivateKeyInfo` (RFC 5958), PEM-armoured as `PRIVATE KEY`, encrypted to a passphrase with age. |
| `<label>.openpgp.key.age` | The primary: a transferable secret key, binary (RFC 9580, section 10.2), version 4, whose secret key material is not protected inside (S2K usage 0) because age encrypts the whole file. |
| `<label>.revocation.<reason>.pgp.age` | The primary's revocation signature for one reason, `compromised` or `superseded` (or one the holder added), encrypted the same way. One file for each reason; the SHA-256 of the signature packet before encryption is the reason's entry in `revocations`. |

- **Encryption.** The age format (`age-encryption.org/v1`) with a passphrase recipient, which derives the key with scrypt. One passphrase for the files of a root, read from the terminal without echo, or from `--passphrase-fd N`. It is never a flag, an environment variable or a line of output.
- **`--test-root`** writes the same keys with no passphrase: `<label>.x509.key.pem` with the line `TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root.` before the armour, and `<label>.openpgp.key.asc` and `<label>.revocation.<reason>.asc`, ASCII-armoured with the header `Comment: TEST ONLY`. The root's names carry ` (TEST ONLY)` too, and products refuse to mix test and real roots.
- The holder keeps the revocation file apart from the key files, as for a card ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#revocation-readiness)).

## Follow-ups

- The code that writes `cards.yaml`, the `attestation/` files and the `aws_kms` block ([issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)); their formats are on [the cards page](/reference/cards/) and [the cloud root page](/reference/kms-root/).
- The CRLs, the SSH CA key list and the keyring files under `products/<sequence>/` come with their builders ([issue #30](https://github.com/truvity/ritueel/issues/30), [issue #55](https://github.com/truvity/ritueel/issues/55), [issue #15](https://github.com/truvity/ritueel/issues/15)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The root certificate profile. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The subject key identifier. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The primary, its self-signature and revocation, transferable secret keys. |
| [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958), [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PKCS#8 private keys and their PEM armour. |
| [age v1](https://age-encryption.org/v1) | Passphrase encryption of the software root's key files (scrypt). |
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) | The schema of `ritueel.yaml`. |
