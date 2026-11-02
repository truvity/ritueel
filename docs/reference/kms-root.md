---
title: The cloud root in AWS KMS
description: What the operator provides for a KMS root, the ritueel.yaml block, the keys and key policy ritueel creates, and every check it makes, with its reason code.
sidebar:
  order: 10
---

*Not built yet. This is the page that [ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) leaves for the details of the `aws-kms` store; the code is [issue #12](https://github.com/truvity/ritueel/issues/12), in M2. The custody model is in [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/): one dedicated root account, one root, a multi-Region replica that is never counted as a second root.*

A KMS key has no attestation. The evidence that it is the root it should be is the key itself, its policy and its audit trail, read from the service every time ([principle 4](/principles/)). This page says what ritueel creates, what it reads, and what makes it refuse.

## What the operator provides

Before `init`, with the operator's own infrastructure tools ([Prepare the cloud root](/guides/prepare-the-cloud-root/)):

| Part | What it is |
|---|---|
| The root account | A dedicated AWS account that holds nothing else. |
| The admin role | Creates and replicates the keys and reads them. It can never `kms:Sign`. |
| The ceremony role | The only principal that may `kms:Sign` with a root key. It can be assumed only with multi-factor authentication. |
| Controls around them | Optional and the operator's: an organisation policy against deleting or disabling the keys, an alarm on every `Sign`, retention of the audit trail. The guide teaches them; ritueel does not create or check them. |

One person may be able to assume both roles ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit)). The roles separate the acts (creating, signing) so that each is a decision and leaves its own trail.

## `ritueel.yaml`

An optional block, required when a root's store is `aws-kms`. An unknown member is an error.

```yaml
aws_kms:
  account: "123456789012"
  region: eu-west-1
  replica_region: eu-central-1
  admin_role: arn:aws:iam::123456789012:role/ritueel-admin
  ceremony_role: arn:aws:iam::123456789012:role/ritueel-ceremony
```

| Member | Meaning |
|---|---|
| `account` | The root account's 12-digit id. Every ARN ritueel reads or writes must carry it. |
| `region`, `replica_region` | The Region of the primary keys, and the one Region of the replicas. They differ. |
| `admin_role`, `ceremony_role` | The two roles, by ARN, in `account`. |

Credentials come from the caller's standard chain ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards)). ritueel assumes the admin role to create and read, and the ceremony role to sign. The multi-factor code for the ceremony role is typed at the terminal without echo, as a PIN is, and never stored. The `aws_kms` block is added to the schema of [the directory](/reference/directory/#ritueelyaml) with the store; it is additive, so `version` stays `1`.

## What ritueel creates

At `init` and at `root add --store aws-kms`, for each of the three keys of a root (`x509-root`, `openpgp-primary`, `ssh-break-glass`), under the admin role:

| Property | Value |
|---|---|
| Key spec, usage | `ECC_NIST_P384`, `SIGN_VERIFY`. Only SHA-384 digests are signed ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| Origin | `AWS_KMS`: the key is born in the service. Imported key material is refused. |
| Multi-Region | A primary in `region`, and a replica in `replica_region`, made with `ReplicateKey`. |
| Key policy | The one below, rendered from `ritueel.yaml`, on the primary and, separately, on the replica: AWS does not share a key policy between the keys of a multi-Region set. |
| Tags | `ritueel:root` (the label), `ritueel:purpose` (`x509-root`, `openpgp-primary` or `ssh-break-glass`), and `ritueel:openpgp-created`, the OpenPGP creation time of the key as `YYYY-MM-DDThh:mm:ssZ` ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| Alias | None. An alias is a pointer that anyone with the right permission can move; the ARN is the identity. |
| Deletion | ritueel never schedules the deletion of a key. |

## The key policy

The same text for every key, with the two role ARNs and the account filled in. A role named here exists; a principal that does not is refused by AWS.

| Statement | Principal | Allows | Condition |
|---|---|---|---|
| Read | the admin role, the ceremony role | `DescribeKey`, `GetPublicKey`, `GetKeyPolicy`, `ListResourceTags`, `ListGrants` | none |
| Sign | the ceremony role only | `Sign` | multi-factor authentication present (`aws:MultiFactorAuthPresent`); `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Manage | the admin role only | `PutKeyPolicy`, `TagResource`, `ReplicateKey`, `ScheduleKeyDeletion`, `DisableKey`, `EnableKey` | none |
| Deny grants | every principal | `CreateGrant`, `RetireGrant`, `RevokeGrant` | none |

`PutKeyPolicy` stays with the admin role because AWS refuses a policy that would lock out its own caller. No statement names the account root, and none allows `Sign` to the admin role. The condition keys are those of the KMS documentation (read 2026-11-02, [AWS KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)). The digest of the policy text, as the service returns it, is `policy_sha256` in the record.

## The checks

Made at `init` after the keys exist, and again, reading from the service, at every ceremony that signs with the root and at the restore drill ([issue #68](https://github.com/truvity/ritueel/issues/68)). A check that cannot run is `not-run`, and the ceremony stops. Exit code 3 for each, 4 for `kms-session`.

| # | Check | Code |
|---|---|---|
| 1 | The ARN carries `account` and the expected Region; the key is enabled and not pending deletion. | `kms-account`, `kms-state` |
| 2 | Spec, usage and origin are as above; the key is a multi-Region primary; its `GetPublicKey` answer equals the public key in the directory. | `kms-key-spec`, `kms-key-mismatch` |
| 3 | Every statement that allows `Sign`, directly or through `kms:*` or a wildcard action, names exactly the ceremony role, and carries the three conditions. The contract's single-principal rule ([the contract](/reference/hand-off-contract/#what-the-certifier-checks)) is this check. | `kms-policy-sign` |
| 4 | No statement allows the admin role to sign, and none names the account root or a wildcard principal. | `kms-policy-admin` |
| 5 | The key has no grant. | `kms-grants` |
| 6 | The replica exists in `replica_region`, has the same public key, and passes checks 1 to 5 on its own policy. | `kms-replica` |
| 7 | The tags are present and `ritueel:openpgp-created` equals the creation time in the directory. | `kms-tags` |
| 8 | The policy is the one the last ceremony recorded. If its digest changed, the plan says so in words and shows both digests, and the person confirms the change as part of the plan; the record keeps both. | none |
| 9 | At a ceremony that signs: the session is the ceremony role, with multi-factor authentication. | `kms-session` |

## Evidence files

Written at `init` under `roots/<label>/attestation/`, one set for each key, named by purpose. They are public material.

| File | Holds |
|---|---|
| `<purpose>.policy.json` | The key policy exactly as `GetKeyPolicy` returned it, and the replica's as `<purpose>.replica-policy.json`. |
| `<purpose>.key.json` | One canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)): `key_arn`, `spec`, `usage`, `origin`, `multi_region`, `state`, `replica_arn`, the tags, `public_key_sha256` and `policy_sha256`. |
| `result.json` | The checks that ran and their results, the `role_session` (the assumed-role ARN and session name, never a credential), and `checked_at`. |

A ceremony that signs writes a new `result.json` into its record, not over the old file.

## Failure

- **A key made and not recorded.** The birth journal ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)) lists every ARN as it is created. `records close` prints them, and ritueel asks the operator to schedule their deletion with the admin role. It does not delete them.
- **A replica that failed.** The root is not complete: `init` stops before it signs anything, and a re-run with the same plan finds the primary and replicates it.
- **A deleted or disabled key** shows as check 1 at the next ceremony or drill. For a root, that is the loss of a root: `root revoke` and `root add`.

## Follow-ups

- The `aws-kms` store, the block, the policy, the checks and their tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).

## Standards

| Standard | Used for |
|---|---|
| [AWS KMS developer guide](https://docs.aws.amazon.com/kms/latest/developerguide/), read 2026-11-02 | Multi-Region keys, key policies, condition keys, `ReplicateKey` (the key policy is not shared between the keys of a set) and the lockout check. |
| [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480), [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The P-384 public key in X.509 and in OpenPGP. |
