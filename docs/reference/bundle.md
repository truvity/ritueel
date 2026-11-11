---
title: The bundle, ritueel.yaml, root profiles and key files
description: The layout of a ritueel bundle, the ritueel.yaml schema, the root certificate and primary profiles, and the software root's key files.
sidebar:
  order: 6
---

*Not built yet. This is the layout the M2 code writes ([issue #8](https://github.com/truvity/ritueel/issues/8), [issue #9](https://github.com/truvity/ritueel/issues/9)); the rules it follows are in [ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-bundle-and-the-records).*

ritueel keeps everything it knows about one trust domain in one **bundle**, a directory of plain files with a fixed structure. Its write-once part is the *ledger*, below. [Learn](/learn/the-ledger/) advises on where to keep the bundle and how to back it up and restore it: ritueel needs no git, and the holder is still advised to keep the bundle in version control. It holds public material and the sealed secrets of cards ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)), and, in a personal bundle, the wrapped backup of the person's encryption subkey ([ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#day-to-day-cards)). It never holds a private key in clear, a PIN the holder types, a passphrase or a revocation signature. Losing it loses the inventory, the attestations and the OpenPGP creation times, so it is part of every key's identity ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#consequences)). A software root's private keys live in **key files outside it**.

## One bundle, one trust domain

A bundle has its own ledger, trust sequence and roots, and a company bundle its own root list (a personal bundle has none). A holder with a personal key and a company keeps two bundles, for example `personal/` and `acme/` ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-bundle-and-the-records)). Inside a bundle the roots are `A` and `B`, then the next letter; across bundles a root is written with the bundle's name, `acme/A`. Two bundles may share a pair of root cards ([the cards page](/reference/cards/#the-inventory-cardsyaml-and-cardsnameyaml), [ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/)).

A bundle is named by its directory.

:::note[Proposed]
No file stores the bundle's name. `name` in `ritueel.yaml` is the name in the roots' subjects, `CN=Example Root A`, and is not the bundle's name: the bundle `acme` may have `name: Acme Corp`. Two bundles may then issue the same subject, and whether `name` must differ between bundles is open. Each bundle would have its own unlock key and recovery key, which open its key files as [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#the-key-file) says; with the passkey way a card shared by two bundles would then hold one credential for each, and with the slot 9d fallback the one 9d key of the card would be shared by them.
:::

## The layout

:::note[Proposed]
The maintainer decided that the ledger is a plain write-once folder with one sub-folder for each ceremony, each naming the one before, and that the bundle holds an inventory of cards and the sealed secrets of cards. The file names inside them (`plan.json`, `attempt.json`, `record.json`, `transcript.txt`, `births.jsonl`, `cards.yaml`, `cards/NAME.sealed.age`) and the `adopted` member of `root.json` are the proposed shape, awaiting the maintainer's word, and are fixed with the code.
:::

| Path | Written by | Holds |
|---|---|---|
| `ritueel.yaml` | The operator | The name, the release address, the policy and the intermediates ([below](/reference/bundle/#ritueelyaml)). |
| `cards.yaml` | ritueel | The inventory list: every card this bundle uses, of the four kinds root, day-to-day, server and rehearsal, from M2. Absent while every root is in software ([the inventory](/reference/cards/#the-inventory-cardsyaml-and-cardsnameyaml)). |
| `cards/NAME.yaml` | ritueel | The map of one card: every slot of its PIV, OpenPGP and FIDO2 applications and its use. Written from the read-only check ([cards](/reference/cards/#the-map-of-one-card-cardsnameyaml)). |
| `cards/NAME.sealed.age` | ritueel | This bundle's own copy of the card's secrets: the management key, the PUK and, on a day-to-day card, the Admin PIN, sealed to the recipients of the key files. One file for each card that ritueel adopted, root and day-to-day ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)). |
| `roots/<label>/root.json` | ritueel | The facts of one root ([below](/reference/bundle/#rootjson)). |
| `roots/<label>/x509.pem` | ritueel | The root's current certificate. |
| `roots/<label>/openpgp.pgp` | ritueel | The primary's current public certificate, binary. |
| `roots/<label>/attestation/` | ritueel | For a root on a card or in KMS: the attestation or the key's description and policy, as read at `init` ([cards](/reference/cards/#files), [KMS](/reference/kms-root/#evidence-files)). |
| `roots/<label>/ssh-break-glass.pub` | ritueel | From M2, with the cloud store: the root's break-glass SSH CA key, one OpenSSH line ([the SSH CA key list](/reference/ssh-ca-key-list/#how-a-key-enters-the-list)). |
| `requests/<stem>.*` | The operator | Pending requests: the files of the [hand-off contract](/reference/hand-off-contract/#messages-and-files), one stem each. |
| `answers/<stem>.*` | ritueel | The answers: `<stem>.result.json`, and `<stem>.cert.pem` or `<stem>.bound.pgp`. |
| `ledger/<ceremony>/` | ritueel | The ledger: one sub-folder for each ceremony, holding its [ceremony files](/reference/ceremony-record/) `plan.json`, `attempt.json`, `record.json` and `transcript.txt`. A ceremony that makes keys also writes `births.jsonl`, the [birth journal](/reference/ceremony-record/#the-birth-journal). Each sub-folder names the one before it. A sealed single-file form of the ledger is later. |
| `products/<sequence>/` | ritueel | The trust products of one trust sequence: `root-list.json`, `root-list.jws` and `ca-bundle.pem` ([the root list](/reference/root-list/#files)); from M4 `crl-<label>.pem` for each active root ([the CRLs](/reference/crl/#files)); from M4 `ssh-ca-keys.json`, `ssh-ca-keys.jws` and `ssh-user-ca-keys.pub` ([the SSH CA key list](/reference/ssh-ca-key-list/#files)) and `revocations/`; from M5 `keyring/` ([the keyring package](/reference/keyring-package/#files)). |

- ritueel never writes `ritueel.yaml` or `requests/`, and the operator does not edit the other paths.
- A file that a ceremony replaces, such as `x509.pem`, keeps its history in `products/` and in version control. Nothing under `products/` or `ledger/` is ever overwritten.
- ritueel refuses a request whose stem already has an answer.
- The bundle is found by `--dir DIR`, or is the current directory when it holds `ritueel.yaml` ([Commands](/reference/cli/#flags-every-ceremony-shares)).

## On the stick

A root on cards or in a key file runs on the offline system, which boots from a USB stick ([ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#where-a-plan-runs)). The stick carries one extra partition, and ritueel defines its layout. The picture is on [the bundle and the USB stick](/how-it-works/bundle-and-stick/#the-usb-stick).

:::note[Proposed]
The names below are the smallest layout that serves the decision. They are a proposal, awaiting the maintainer's word.

```text
RITUEEL/                          the extra partition
├── ritueel/                      the program
│   ├── 0.1.0/
│   │   ├── linux-amd64/ritueel
│   │   └── linux-arm64/ritueel
│   └── 0.2.0/ …
├── bundles/                      several bundles
│   ├── acme/                     ritueel.yaml, roots/, requests/, ledger/<ceremony>/plan.json, …
│   └── personal/
└── keys/                         the encrypted key files, one folder for each bundle
    └── personal/A.openpgp.key.age
```

- **`RITUEEL/`** is the extra partition. AirgapOS's own partitions are not touched.
- **`ritueel/<version>/<system>-<arch>/ritueel`** holds the program, and nothing else, because it is one static file. The version comes first, so that the run can use the exact version that made the plan. The system and the architecture come second, so that several machines can use one stick.
- **`bundles/<name>/`** is a bundle copied whole, so the plan in its ledger and the bundle the plan was made from arrive together. It is the directory that your workstation already uses with `--dir`, with no second format.
- **`keys/<bundle>/`** holds the key files of that bundle. Key files are never inside a bundle, so a copy of a bundle cannot carry a key by accident. The folder has the name of the bundle, so a person finds a file without a lookup.
- **The plan records the copy that made it** in a new member `ritueel`: `{ "version", "os_arch", "sha256" }`, where `sha256` is the digest of that copy. The run is then `<stick>/ritueel/<version>/<system>-<arch>/ritueel --dir <stick>/bundles/acme run ledger/<ceremony>/plan.json --confirm …`. When a plan is prepared online, ritueel refreshes its copy on the stick first.

Not decided: the label and the file system of the partition, whether a checksum file sits beside each binary, and whether the `keys/` folder of a bundle may sit inside the parent of the bundle.
:::

Not yet proven on hardware: that AirgapOS boots from a stick with such a partition and mounts it ([ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#follow-ups)).

## `ritueel.yaml`

The operator writes it before `init`. An unknown key is an error, as in the contract.

```yaml
version: 1
name: Example                    # in the roots' subjects and user IDs
release_address: release@example.com
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.4
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
intermediates:
  - name: example-ca
    type: x509-intermediate
    permitted_uri_hosts: [example.com]
  - name: example-release
    type: openpgp-subkey
    capability: sign
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
| `name` | 1 to 64 characters: letters, digits, spaces and hyphens. It names the roots and their primaries ([below](/reference/bundle/#the-root-certificate)). |
| `release_address` | The address in every primary's user ID: the project's release identity, never a person's ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keys)). |
| `policy` | The rules every request is checked against: `stores`, `min_firmware`, `pin_policy`, `require_name_constraints` and `validity_months`, with the meanings of the [reference policy](/reference/hand-off-contract/#what-the-certifier-checks). All five are required. |
| `intermediates` | The intermediates ritueel may certify, one entry each. `name` is the `NAME` of the commands: lower-case letters, digits and hyphens, 1 to 63 characters, unique. `type` is `x509-intermediate`, `openpgp-subkey` or `ssh-ca-key`. |
| `intermediates[].permitted_uri_hosts` | For `x509-intermediate`: the hosts a request's name constraints must stay inside. Required when `require_name_constraints` is true. Only URI hosts are expressible in version 1. **Planned:** permitted and excluded DNS subtrees and excluded IP ranges, for an intermediate that issues for DNS names and for per-environment limits; the schema will grow when a first installation needs it. |
| `intermediates[].capability` | For `openpgp-subkey`: `sign` or `authenticate`, required. A request for another capability is refused with `policy`; the subkey is bound with this one's key flag ([the contract](/reference/hand-off-contract/#openpgp-subkey)). |
| `intermediates[].use` | For `ssh-ca-key`: `user` or `host`, required. A request for another `use` is refused with `policy`; the key is listed with this use ([the contract](/reference/hand-off-contract/#ssh-ca-key)). |
| `kind` | Optional. `personal` for a person's own OpenPGP key; absent for a company bundle. A personal bundle has `person` instead of `name` and `release_address` ([personal OpenPGP](/reference/personal-openpgp/)). |
| `person` | Only with `kind: personal`: `name` (1 to 64 characters) and `address`. |
| `aws_kms` | Optional, from M2; required when a root's store is `aws-kms`. The root account, the two Regions and the two roles, and optionally the renewal policy ([the block](/reference/kms-root/#ritueelyaml), [the policy](/reference/kms-root/#the-policy-in-ritueelyaml)). |
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
        "ceremony_role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
        "renewal": {
          "type": "object",
          "additionalProperties": false,
          "required": ["role", "intermediates", "within_days"],
          "properties": {
            "role": { "type": "string", "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/" },
            "intermediates": { "type": "array", "uniqueItems": true, "items": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$" } },
            "within_days": { "type": "integer", "minimum": 14, "maximum": 90 }
          }
        }
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
          "capability": { "enum": ["sign", "authenticate"] },
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

Six rules the schema cannot state: the two Regions of `aws_kms` differ, both its roles are in `account`, intermediate names are unique, an `x509-intermediate` has `permitted_uri_hosts` when `require_name_constraints` is true, an `openpgp-subkey` has `capability`, and an `ssh-ca-key` has `use` and no other key of the entry. A name that begins with `break-glass-` is refused, because the SSH CA key list uses those for the break-glass keys. ritueel checks all of them when it reads the file.

## `root.json`

`roots/<label>/root.json` is one canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)), written at `init` or `root add` and not changed after, except `retired_at`, `revoked_at` and `revoked_reason`.

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `label` | The root's label: one upper-case letter, `A` and `B` for the two roots `init` makes, then the next free letter for each root `root add` makes, whatever its key store. It never names the store, is unique inside its bundle and is never reused. |
| `store` | `software`, `piv` or `aws-kms`. |
| `test` | True for a root made with `--test-root`. Set at birth and never changed; a real root never becomes a test root. |
| `created_at` | When the root was made: the time of its ceremony. |
| `x509_spki_sha256` | The pin of the X.509 root key. |
| `openpgp_fingerprint` | The primary's fingerprint. |
| `openpgp_created` | The OpenPGP creation time of the primary, which fixes its fingerprint and is on no card ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| `revocations` | An object from reason (`compromised`, `superseded`, and any the holder added) to the SHA-256 of that revocation signature packet, which is stored elsewhere ([revocation material](/reference/revocation-material/)). |
| `removal_sha256` | The SHA-256 of the root's removal authorisation, which is stored elsewhere with the revocation signatures ([revocation material](/reference/revocation-material/#the-removal-authorisation)). Absent in a personal bundle. |
| `adopted` | True for an OpenPGP primary adopted as it was ([ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#stage-one)) or for a cloud key that ritueel adopted instead of creating ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#adopting-a-key)). Absent otherwise. |
| `store_ref` | For a root in `piv` (from M6) or `aws-kms` (from M2); absent for `software`. For `piv`: `{ "serial", "row" }`, the card's entry in [`cards.yaml`](/reference/cards/#the-inventory-cardsyaml-and-cardsnameyaml) and the root's row in the [slot map](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-rows); the slots follow from the built-in map. For `aws-kms`: `{ "x509_arn", "openpgp_arn", "ssh_arn" }`, the ARNs of the primary keys ([the cloud root](/reference/kms-root/#what-ritueel-creates)). |
| `revoked_at` | Present once the root is revoked. |
| `replaces`, `overlap_until`, `vouched_by`, `vouches`, `retired_at`, `revoked_reason` | From M4, as [the transitions page](/reference/transitions/#in-rootjson) says. `retired_at` and `revoked_at` are the only members changed after the root is written. |

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
| Subkeys | None of its own. It binds the subkeys of intermediates through the hand-off. |
| Revocation | A key revocation signature (type `0x20`), made when the key is born and stored apart from it. |

**Each use extends it,** with a new self-signature of the same shape at the ceremony time.

The test roots of the [hand-off vectors](/reference/hand-off-contract/#test-vectors) follow both profiles, with the name `Example Test`.

## The software root's key files

A software root ([the `software` store](/decisions/0003-key-stores-and-the-card-layer/#four-stores-behind-one-interface)) serves tests, drills and development, and never anchors a signed release ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)). Its private keys are in files in a **key directory**, given by `--key-dir DIR`, which ritueel refuses when it is inside the bundle. Every command that writes them, and every record of a ceremony that uses them, says that a software root can be copied.

| File | Content |
|---|---|
| `<label>.x509.key.age` | The X.509 root key: a PKCS#8 `PrivateKeyInfo` (RFC 5958), PEM-armoured as `PRIVATE KEY`, encrypted with age to the recipients below. |
| `<label>.openpgp.key.age` | The primary: a transferable secret key, binary (RFC 9580, section 10.2), version 4, whose secret key material is not protected inside (S2K usage 0) because age encrypts the whole file. |
| `<label>.revocation.<reason>.pgp.age` | The primary's revocation signature for one reason, `compromised` or `superseded` (or one the holder added), encrypted the same way. One file for each reason; the SHA-256 of the signature packet before encryption is the reason's entry in `revocations`. |
| `<label>.removal.jws.age` | The root's removal authorisation, encrypted the same way; the SHA-256 of the JWS text before encryption is `removal_sha256`. |

- **Encryption.** The age format (`age-encryption.org/v1`). By default a key file is encrypted to two recipients: the public half of an age key (the unlock key) and a recovery recipient. A passkey on each root card unwraps the private half of the unlock key; the recovery key is an age identity in a passphrase-protected file kept apart from the cards ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#the-key-file)). Encrypting needs no card. The members that hold the wrapped private half of the unlock key, and the recovery file, are fixed with the passkey proof (M1), and are not written here before it.
- **A passphrase instead,** for a holder without cards: the age passphrase recipient, which derives the key with scrypt. A passphrase file holds only that recipient, because the age v1 specification says "An scrypt stanza, if present, MUST be the only stanza in the header" (read 2026-11-11, [age v1](https://age-encryption.org/v1)). The passphrase is read from the terminal without echo, or from `--passphrase-fd N`; it is never a flag, an environment variable or a line of output. A test root or a script uses it.
- **`--test-root`** writes the same keys with no passphrase: `<label>.x509.key.pem` with the line `TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root.` before the armour, `<label>.openpgp.key.asc` and `<label>.revocation.<reason>.asc`, ASCII-armoured with the header `Comment: TEST ONLY`, and `<label>.removal.jws`. The root's names carry ` (TEST ONLY)` too, and products refuse to mix test and real roots.
- The holder keeps the revocation files and the removal authorisation apart from the key files, as for a card ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#revocation-readiness)).

## Follow-ups

- The code that writes `cards.yaml`, `cards/NAME.yaml`, the sealed files, the `attestation/` files and the `aws_kms` block ([issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)); their formats are on [the cards page](/reference/cards/) and [the cloud root page](/reference/kms-root/).
- The CRLs, the SSH CA key list and the keyring files under `products/<sequence>/` come with their builders ([issue #30](https://github.com/truvity/ritueel/issues/30), [issue #55](https://github.com/truvity/ritueel/issues/55), [issue #15](https://github.com/truvity/ritueel/issues/15)), in M4 (the CRLs and the SSH CA key list) and M5 (the keyring).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | The root certificate profile. |
| [RFC 7093](https://datatracker.ietf.org/doc/html/rfc7093) | The subject key identifier. |
| [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The primary, its self-signature and revocation, transferable secret keys. |
| [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958), [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PKCS#8 private keys and their PEM armour. |
| [age v1](https://age-encryption.org/v1) | Encryption of the software root's key files, and the passphrase recipient (scrypt). |
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) | The schema of `ritueel.yaml`. |
