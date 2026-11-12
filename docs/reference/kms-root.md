---
title: The cloud root in AWS KMS
description: What the holder provides for a KMS root, the ritueel.yaml block, the keys ritueel makes or adopts, the key policy and its checks.
sidebar:
  order: 10
---

*Not built yet. This is the page that [record 0004](../decisions/0004-the-cloud-root.md) leaves for the details of the `aws-kms` store; the code is [issue #12](https://github.com/truvity/ritueel/issues/12), in M2. The custody model is in that record: one dedicated root account that holds three keys, one for each kind of root, and a multi-Region replica that is never counted as a second key. The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

A KMS key has no attestation. The evidence that it is the root it should be is the key itself, its policy and its audit trail, read from the service every time ([principle 4](/principles/)). This page says what ritueel creates or adopts, what it reads, and what makes it refuse.

## What the holder provides

Before the first `apply`, with the holder's own infrastructure tools ([Prepare the cloud root](/guides/prepare-the-cloud-root/)):

| Part | What it is |
|---|---|
| The root account | A dedicated AWS account that holds nothing else. |
| The admin role | Creates the keys and reads them. It replicates only before the policy that refuses replicas is in force, or through the break-glass principal. It can never `kms:Sign`. |
| The ceremony role | The principal that may `kms:Sign` with a root key at a ceremony, and the only one that may sign anything new. ritueel asks for no particular sign-in to assume it ([record 0004](../decisions/0004-the-cloud-root.md)); how it is assumed is the holder's. |
| The break-glass principal | The one principal that may still replicate a key or move its primary Region, for example after the loss of a Region. It is created like the admin role and is never named after a person. Using it is a manual, logged act ([record 0004](../decisions/0004-the-cloud-root.md)). It can never `kms:Sign`. |
| The keys | Optional. An existing key that ritueel [adopts](/reference/kms-root/#adopting-an-existing-key), with its alias and policy owned by the holder's own infrastructure code. Without one, ritueel creates the keys. |
| Controls around them | Optional and the holder's: an alarm on every `Sign`, retention of the audit trail. The guide teaches them; ritueel does not create or check them. |

One person may be able to assume the admin and the ceremony role ([record 0004](../decisions/0004-the-cloud-root.md)). The roles separate the acts (creating, signing) so that each is a decision and leaves its own trail.

## `ritueel.yaml`

An optional block, required when a root key's store is `aws-kms`. An unknown member is an error.

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

Credentials come from the caller's standard chain ([record 0004](../decisions/0004-the-cloud-root.md)). ritueel assumes the admin role to create and read, and the ceremony role to sign. ritueel does not sign the person in and holds no credential: the chain hands it a session of the ceremony role, and ritueel checks only that the session is the ceremony role's (check 9). The `aws_kms` block is added to the schema of [the bundle](/reference/bundle/#ritueelyaml) with the store; it is additive, so `version` stays `1`.

## What ritueel creates

At the first `apply`, and at an `apply` that adds a root key in `aws-kms`, for each of the three keys, one for each kind of root (`x509-root`, `openpgp-primary`, `ssh-break-glass`), under the admin role:

| Property | Value |
|---|---|
| Key spec, usage | `ECC_NIST_P384`, `SIGN_VERIFY`. Only SHA-384 digests are signed ([record 0004](../decisions/0004-the-cloud-root.md)). |
| Origin | `AWS_KMS`: the key is born in the service. Imported key material is refused. |
| Multi-Region | A primary in `region`, and a replica in `replica_region`, made with `ReplicateKey`. |
| Key policy | The one below, rendered from `ritueel.yaml`, on the primary and, separately, on the replica: AWS does not share a key policy between the keys of a multi-Region set. |
| Tags | `ritueel:root` (the label), `ritueel:purpose` (`x509-root`, `openpgp-primary` or `ssh-break-glass`), and `ritueel:openpgp-created`, the OpenPGP creation time of the key as `YYYY-MM-DDThh:mm:ssZ` ([record 0006](../decisions/0006-bundle-history-and-trust-files.md)). |
| Alias | None on a key ritueel creates. An adopted key may carry one. An alias is a pointer that anyone with the right permission can move; the ARN is the identity. |
| Deletion | ritueel never schedules the deletion of a key. |

## Adopting an existing key

:::note[Proposed]
Four details on this page go beyond what the maintainer decided, and await the maintainer's word: that the identity of an adopted key is its ARN and not its alias; that ritueel never edits the policy of an adopted key; that the break-glass principal can never `kms:Sign`; and the check `kms-policy-replica` (3b) with its reason code.
:::

A cloud root may be a key that already exists in the service ([record 0004](../decisions/0004-the-cloud-root.md)). The holder's own infrastructure code may own the key, its alias and its policy. ritueel then does not create the key. At the first `apply`, and at an `apply` that adds a root key, it:

1. reads the public key from the service;
2. reads the key policy and runs [the checks](/reference/kms-root/#the-checks) on it, the same checks as for a key it created;
3. fixes the OpenPGP creation time and records it in the bundle and in the certificate;
4. writes the certificate.

The identity of the key is its ARN, not its alias. ritueel reads the policy at every ceremony and never edits an adopted key's policy. An adopted key must be one born in the service: key material imported from outside is refused, as it is for a created key. A key that fails a check is refused with the check's reason code. How the holder names the key to adopt is fixed with the store ([issue #12](https://github.com/truvity/ritueel/issues/12)). The file `root.json` of the key says it was adopted ([`adopted`](/reference/bundle/#rootjson)).

## The key policy

The reference key policy: the same text for every key, with the role ARNs and the account filled in. A key that ritueel creates gets it; an adopted key's policy is the holder's, and is checked against the same rules. A role named here exists; a principal that does not is refused by AWS.

| Statement | Principal | Allows | Condition |
|---|---|---|---|
| Read | the admin role, the ceremony role | `DescribeKey`, `GetPublicKey`, `GetKeyPolicy`, `ListResourceTags`, `ListGrants` | none |
| Sign | the ceremony role only | `Sign` | `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Manage | the admin role only | `PutKeyPolicy`, `TagResource`, `ScheduleKeyDeletion`, `DisableKey`, `EnableKey` | none |
| Break glass | the break-glass principal only | `ReplicateKey`, `UpdatePrimaryRegion` | none |
| Deny replicas | every principal except the break-glass principal | `ReplicateKey`, `UpdatePrimaryRegion` | none |
| Deny grants | every principal | `CreateGrant`, `RetireGrant`, `RevokeGrant` | none |

`PutKeyPolicy` stays with the admin role because AWS refuses a policy that would lock out its own caller. The policy refuses new replicas and moving the primary Region to everyone but the break-glass principal, so that an administrator cannot copy the key to a Region where no one watches; it allows digests only (the Sign row). The replicas are made before the refusal applies, or by the break-glass principal; the sequence for the keys that ritueel creates is written here when the store is built ([record 0004](../decisions/0004-the-cloud-root.md)). No statement names the account root, and none allows `Sign` to the admin role or the break-glass principal. The `kms:` condition keys are those of the KMS documentation (read 2026-11-02, [AWS KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)). The digest of the policy text, as the service returns it, is `policy_sha256` in the ceremony record.

## The checks

Made at the first `apply` after the keys exist, and again, reading from the service, at every ceremony that signs with the root and at the restore drill ([issue #68](https://github.com/truvity/ritueel/issues/68)). A check that cannot run is `not-run`, and the ceremony stops. Exit code 3 for each, except `kms-session`, which is 4: the key store's side refuses the session ([exit codes](/reference/cli/#exit-codes)).

| # | Check | Code |
|---|---|---|
| 1 | The ARN carries `account` and the expected Region; the key is enabled and not pending deletion. | `kms-account`, `kms-state` |
| 2 | Spec, usage and origin are as above; the key is a multi-Region primary; its `GetPublicKey` answer equals the public key in the bundle. | `kms-key-spec`, `kms-key-mismatch` |
| 3 | The statement that allows `Sign` to the ceremony role carries the two conditions. | `kms-policy-sign` |
| 3a | Every statement that allows `Sign`, directly or through `kms:*` or a wildcard action, names the ceremony role, with its two conditions. Any other principal (the break-glass principal included) is refused. This is the root's form of the contract's single-principal rule ([the contract](/reference/hand-off-contract/#what-the-certifier-checks)). | `extra-sign-principal` |
| 3b | A statement denies `ReplicateKey` and `UpdatePrimaryRegion` to every principal except the break-glass principal, and no other statement allows them to anyone else. | `kms-policy-replica` |
| 4 | No statement allows the admin role or the break-glass principal to sign, and none names the account root or a wildcard principal. | `kms-policy-admin` |
| 5 | The key has no grant. | `kms-grants` |
| 6 | The replica exists in `replica_region`, has the same public key, and passes checks 1 to 5 on its own policy. | `kms-replica` |
| 7 | For a key ritueel created, the tags are present and `ritueel:openpgp-created` equals the creation time in the bundle. For an adopted key, a tag is read when present and must equal the bundle's value; it is not required. | `kms-tags` |
| 8 | The policy is the one the last ceremony recorded. If its digest changed, the plan says so in words and shows both digests, and the person confirms the change as part of the plan; the ceremony record keeps both. | none |
| 9 | At a ceremony that signs: `sts get-caller-identity` names a session of the ceremony role, in `account`. A different role or an expired session stops the run, and the message says to take a session of the ceremony role again. | `kms-session` |

## Evidence files

Written at the first `apply` under `roots/<label>/attestation/`, one set for each key, named by purpose. They are public material.

| File | Holds |
|---|---|
| `<purpose>.policy.json` | The key policy exactly as `GetKeyPolicy` returned it, and the replica's as `<purpose>.replica-policy.json`. |
| `<purpose>.key.json` | One canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)): `key_arn`, `spec`, `usage`, `origin`, `multi_region`, `state`, `replica_arn`, the tags, `public_key_sha256` and `policy_sha256`. |
| `result.json` | The checks that ran and their results, the `role_session` (the assumed-role ARN and session name, never a credential), and `checked_at`. |

A ceremony that signs writes a new `result.json` into its ceremony record, not over the old file.

## Failure

- **A key made and not recorded.** The birth journal ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)) lists every ARN as it is created. `close` prints them, and ritueel asks the holder to schedule their deletion with the admin role. It does not delete them.
- **A replica that failed.** The root is not complete: the first `apply` stops before it signs anything, and `status` shows the attempt as critical until a person runs `close`.
- **A deleted or disabled key** shows as check 1 at the next ceremony or drill. For a root key, that is a loss: answer it with `revoke`, then add a new key to the wanted root file and run `apply`.

## Follow-ups

- The `aws-kms` store, the block, the policy, the checks and their tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- The adoption path, the reworded checks, and the replica and primary-Region refusal in the reference policy, with tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).

## Standards

| Standard | Used for |
|---|---|
| [Control access to multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-auth.html), read 2026-11-11 | Replicating a key needs `kms:ReplicateKey` in the key policy of the primary key, and `kms:CreateKey` in the replica Region; updating the primary Region needs `kms:UpdatePrimaryRegion` in both Regions. So a policy that denies them to everyone but the break-glass principal stops a copy to another Region. |
| [AWS KMS developer guide](https://docs.aws.amazon.com/kms/latest/developerguide/), read 2026-11-02 | Multi-Region keys, key policies, condition keys, `ReplicateKey` (the key policy is not shared between the keys of a set) and the lockout check. |
| [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480), [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The P-384 public key in X.509 and in OpenPGP. |
