---
title: Staff OpenPGP
description: The staff directory, the per-person primary in AWS KMS and its key policy, the checks, the commands for joiner, mover and leaver, and the staff keyring.
sidebar:
  order: 16
---

*Not built yet. This is the page that [ADR 0013](/decisions/0013-staff-openpgp-a-primary-per-person-in-a-cloud-key-service-subkeys-born-on-the-persons-card/) leaves for the details; that record is `Accepted`. The code is [issue #103](https://github.com/truvity/ritueel/issues/103), after the first version. It builds on the `aws-kms` store ([issue #12](https://github.com/truvity/ritueel/issues/12)), the `openpgp-card` store ([issue #18](https://github.com/truvity/ritueel/issues/18)) and the keyring builder ([issue #15](https://github.com/truvity/ritueel/issues/15)). A person's own key is a different flow: [Personal OpenPGP](/reference/personal-openpgp/).*

A staff key is an OpenPGP key the company issues to a member of staff: one primary per person in a KMS key that ritueel uses, and signing and authentication subkeys born on the person's card, which ritueel binds after checking the card with the person present. sluis certifies the primary online and syncs the keyring to the person's hosting account; neither is specified here.

## The staff directory

An ordinary directory with `kind: staff`, in the operator's custody like any other. It holds no root: the company's roots are in their own directory, and the delegation to sluis's certification key is a ceremony of that one ([Company OpenPGP](/decisions/0013-staff-openpgp-a-primary-per-person-in-a-cloud-key-service-subkeys-born-on-the-persons-card/#the-company-root-and-sluis)). Its `ritueel.yaml`:

```yaml
version: 1
kind: staff
domain: example.com
policy:
  stores: [openpgp-card]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  validity_months: 13
aws_kms:
  account: "123456789012"
  region: eu-west-1
  admin_role: arn:aws:iam::123456789012:role/ritueel-staff-admin
  ceremony_role: arn:aws:iam::123456789012:role/ritueel-staff-ceremony
intermediates:
  - name: daily
    type: openpgp-subkey
    capability: sign
  - name: ssh
    type: openpgp-subkey
    capability: authenticate
```

| Member | Meaning |
|---|---|
| `kind` | `staff`. Additive, like `personal`: a file without `kind` is a company directory. |
| `domain` | The domain of the staff addresses. A user ID outside it is refused. |
| `aws_kms` | As in [the cloud root](/reference/kms-root/#ritueelyaml), without `replica_region` and `renewal`: a staff primary has no replica, and no renewal role may be declared. `account` is not the root account. |
| `policy`, `intermediates` | As in [Personal OpenPGP](/reference/personal-openpgp/#the-directory). Every card holds one subkey of each entry. |

Beside the usual files the directory keeps `people/<handle>/`, one folder for each person that ever had a staff key: `person.yaml` (name, address, state), the primary's public key and creation time, the certificate, the registered cards (serial, role, attestation files, [as for root cards](/reference/cards/)), and the revocation signatures made at birth. The `state` is `active`, `left` or `revoked`. A handle is a short name the operator chooses; it is not an address.

## The primary in AWS KMS

| Property | Value |
|---|---|
| Key spec, usage | `ECC_NIST_EDWARDS25519`, `SIGN_VERIFY`. Origin `AWS_KMS`; imported material is refused. |
| OpenPGP | Version 4, algorithm 22 (EdDSA legacy), curve OID `1.3.6.1.4.1.11591.15.1`, certify-only. If the conformance test fails, ECDSA on P-384 with `ECC_NIST_P384` and `ECDSA_SHA_384` ([the contract's profile](/reference/hand-off-contract/#keys-and-hashes)). |
| Hash | SHA-512 for every signature the primary makes. |
| Multi-Region | No. |
| Tags | `ritueel:staff` (the handle), `ritueel:purpose` (`staff-primary`), `ritueel:openpgp-created` (as in [the cloud root](/reference/kms-root/#what-ritueel-creates)). |
| Alias, deletion | None, and ritueel never schedules a deletion. |

### Why this works: what the documents say

Read on 2026-11-06. Nothing here was run against a key yet; the test is in [Follow-ups](/reference/staff-openpgp/#follow-ups).

- **KMS has the key.** The key spec `ECC_NIST_EDWARDS25519` (ed25519) is for signing and verification only. The signing algorithm `ED25519_SHA_512` is pure Ed25519 (FIPS 186-5, section 7.6) and **requires `MessageType` `RAW`**; `ED25519_PH_SHA_512` is Ed25519ph and requires `DIGEST`. They are not interchangeable ([key spec reference](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html), [Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)). A raw message may be up to 4096 bytes.
- **OpenPGP feeds a digest to pure Ed25519.** RFC 9580, section 12.7: the digest of the signature data "is used verbatim as input to the EdDSA algorithm", and "OpenPGP uses the 'pure' variant (PureEdDSA)... that hash itself is fed as the input message to the PureEdDSA algorithm". EdDSALegacy needs a digest of at least the curve's 256 bits (section 5.2.3.3). A 64-byte SHA-512 digest sent to KMS as a raw message, with `ED25519_SHA_512`, therefore gives exactly the signature an algorithm-22 packet carries. `ED25519_PH_SHA_512` would give a different signature and is not usable; the key policy refuses it.
- **Encoding.** The two MPIs of the signature are the octet strings R and S of RFC 8032, 32 octets each, as they are (section 5.2.3.3.1). The public key is the 32 bytes inside the DER `SubjectPublicKeyInfo` that `GetPublicKey` returns, written as an MPI of `0x40` followed by the 32 bytes, 263 bits (sections 5.5.5.5 and 11.2.2). The AWS pages do not state the layout of the signature bytes `Sign` returns for Ed25519, only the layouts for RSA and ECDSA; that is what the test settles.
- **Why not SHA-384 here.** The contract uses SHA-384 because a KMS P-384 key signs only 48-byte digests. Ed25519 has no such limit and uses SHA-512 inside, so the staff primary signs SHA-512 digests.

The same conformance test ([Follow-ups](/reference/staff-openpgp/#follow-ups)) decides between the primary of this page and its P-384 fallback; nothing else on this page depends on the choice.

## The key policy

The policy of [the cloud root](/reference/kms-root/#the-key-policy), with these changes:

| Statement | Principal | Allows | Condition |
|---|---|---|---|
| Read | the admin role, the ceremony role | `DescribeKey`, `GetPublicKey`, `GetKeyPolicy`, `ListResourceTags`, `ListGrants` | none |
| Sign | the ceremony role only | `Sign` | `aws:MultiFactorAuthPresent`; `kms:SigningAlgorithm` is `ED25519_SHA_512`; `kms:MessageType` is `RAW` |
| Manage | the admin role only | `PutKeyPolicy`, `TagResource`, `DisableKey`, `EnableKey`, `ScheduleKeyDeletion` | none |
| Deny grants | every principal | `CreateGrant`, `RetireGrant`, `RevokeGrant` | none |

There is no Renew statement and no `ReplicateKey`. No statement names the account root, and none allows `Sign` to the admin role. The digest of the policy text is `policy_sha256` in the record.

## The checks

The checks 1 to 5, 7 and 8 of [the cloud root](/reference/kms-root/#the-checks) (state, spec and usage, the Sign statement, the extra-signer rule, the admin rule, grants, tags, the policy digest) run on every staff key, with the staff spec and conditions, and check 6 (the replica) does not run. Check 9 is the ceremony role with multi-factor authentication, always. These are added; each stops the ceremony, with exit code 3 unless said:

| # | Check | Code |
|---|---|---|
| S1 | The key is enabled, unless the person's `state` is `left`, in which case it is disabled. | `kms-state` |
| S2 | Every `Sign` in the key's audit trail since the last reconciliation has an entry in the ledger. One without an entry is an incident, not a warning. If the trail cannot be read, the check is `not-run` and a ceremony that signs stops. | `kms-unrecorded-sign` |
| S3 | The card's serial is the one registered for this person, and no other person has it. | `card-not-registered` |
| S4 | The card's attestation chains to the maker's pinned bundle and the key is the one on the card ([cards](/reference/cards/#what-is-checked-on-a-card)); the firmware is at or above `min_firmware`. | `attestation-invalid`, `card-firmware` |
| S5 | The subkey's back-signature verifies over the person's one primary and the subkey, and carries both issuer subpackets ([the contract](/reference/hand-off-contract/#what-the-certifier-checks-1)). | `possession-invalid` |
| S6 | The person's `state` is `active`. A `left` or `revoked` person is never bound. | `person-inactive` |
| S7 | The user ID is in `domain`. | `uid-domain` |

## The commands

| Command | Does | Needs the person |
|---|---|---|
| `ritueel init --kind staff ...` | Makes the directory. Holds no key. | No |
| `ritueel staff card register HANDLE --serial SERIAL` | Records a card for a person when the operator issues it. | No |
| `ritueel staff card prepare --card SERIAL` | Checks the firmware, changes the PIN and Admin PIN at the terminal, sets the touch policy per key. Nothing is stored. | Yes |
| `ritueel staff add HANDLE --name NAME --address ADDRESS` | The joiner ceremony: creates the KMS key and the user ID, then for each registered card makes the subkeys, reads and checks the attestation, binds them, and rebuilds the certificate and the staff keyring. | Yes |
| `ritueel staff update HANDLE --address ADDRESS` | The mover: certifies the new user ID, revokes the old one, rebuilds the keyring. | No; the operator confirms |
| `ritueel staff card replace HANDLE --old SERIAL --new SERIAL` | Revokes the old card's subkeys (`--hard` after theft), binds the new card's subkeys. | Yes |
| `ritueel staff leave HANDLE` | The leaver: marks the person `left`, disables the key, drops it from the keyring, keeps the certificate in the archive. | No; the operator confirms |
| `ritueel yearly --kind staff` | The batch re-binding and extension of every active person, in one plan. | The operator, once |
| `ritueel staff revoke HANDLE` | A compromise: the hard revocation from the signatures made at birth, then the keyring without the key. | The operator |

Everything else works as for a root: `status` warns at 60, 30 and 14 days for a binding, `revocation check` and `drill restore` work on the staff directory. A person's revocation signatures are made at birth and kept apart ([revocation material](/reference/revocation-material/)).

## The staff keyring

Built by `ritueel keyring build --kind staff --name NAME`, with the layout and the verification of [the keyring package](/reference/keyring-package/) and the name `<name>-staff-keyring`. It holds, for each `active` person, one certificate: the primary, the user IDs with their self-certifications, every subkey ever bound with its binding and its back-signature, and the soft revocations. A `left` person is not in it; a hard-revoked key is not in it, and its revocation signature is written beside it. It holds no certification by sluis. It is never merged with a release keyring ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/)).

ritueel does not sign or publish it. sluis reads it and syncs the fingerprints it holds to the hosting accounts; it should add a subkey only when the binding verifies under a primary sluis certified itself.

## Follow-ups

- The directory, the commands, the checks and the `staff-primary` purpose of the `aws-kms` store ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The Ed25519 conformance test: a KMS `ECC_NIST_EDWARDS25519` key, `ED25519_SHA_512` on a raw 64-byte SHA-512 digest, the signature written as two MPIs, a self-certification, a binding and a revocation; accepted by `gpg`, `gpgv`, `sqv` and the hosting platform's key upload. It uses a test account and test keys only ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The staff profile in the hand-off contract, with test vectors ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- Guides for the joiner, mover, leaver and card replacement flows ([issue #103](https://github.com/truvity/ritueel/issues/103)).

## Sources

| Source | What it fixes |
|---|---|
| [AWS KMS key spec reference](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html), read 2026-11-06 | `ECC_NIST_EDWARDS25519`, `ED25519_SHA_512` (RAW) and `ED25519_PH_SHA_512` (DIGEST). |
| [AWS KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html), read 2026-11-06 | The message types, the 4096-byte limit of a raw message. |
| [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), sections 5.2.3.3, 5.2.4, 5.5.5.5, 11.2.2, 12.7 | EdDSALegacy signature and key fields, and the digest fed to PureEdDSA. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | Ed25519 and its native encodings. |
