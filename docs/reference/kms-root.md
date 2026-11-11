---
title: The cloud root in AWS KMS
description: What the operator provides for a KMS root, the ritueel.yaml block, the keys ritueel creates or adopts, the reference key policy, its checks, and renewal.
sidebar:
  order: 10
---

*Not built yet. This is the page that [ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) leaves for the details of the `aws-kms` store; the code is [issue #12](https://github.com/truvity/ritueel/issues/12), in M2. The custody model is in [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/): one dedicated root account, one root, a multi-Region replica that is never counted as a second root.*

A KMS key has no attestation. The evidence that it is the root it should be is the key itself, its policy and its audit trail, read from the service every time ([principle 4](/principles/)). This page says what ritueel creates or adopts, what it reads, and what makes it refuse.

## What the operator provides

Before `init`, with the operator's own infrastructure tools ([Prepare the cloud root](/guides/prepare-the-cloud-root/)):

| Part | What it is |
|---|---|
| The root account | A dedicated AWS account that holds nothing else. |
| The admin role | Creates the keys and reads them. It replicates only before the policy that refuses replicas is in force, or through the break-glass principal. It can never `kms:Sign`. |
| The ceremony role | The principal that may `kms:Sign` with a root key at a ceremony, and the only one that may sign anything new. ritueel asks for no particular sign-in to assume it ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)); how it is assumed is the operator's. |
| The renewal role | Optional, with a [renewal policy](/reference/kms-root/#renewal-under-a-policy). The second and last principal that may `kms:Sign`: sign-only, assumable only by the operator's scheduler. ritueel lets it sign only what the directory already holds. |
| The break-glass principal | The one principal that may still replicate a key or move its primary Region, for example after the loss of a Region. It is created like the admin role and is never named after a person. Using it is a manual, logged act ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#the-reference-key-policy)). It can never `kms:Sign`. |
| The keys | Optional. An existing key that ritueel [adopts](/reference/kms-root/#adopting-an-existing-key), with its alias and policy owned by the operator's own infrastructure code. Without one, ritueel creates the keys. |
| Controls around them | Optional and the operator's: an alarm on every `Sign`, retention of the audit trail. The guide teaches them; ritueel does not create or check them. |

One person may be able to assume the admin and the ceremony role ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit)). The roles separate the acts (creating, signing) so that each is a decision and leaves its own trail.

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
| `renewal` | Optional: the [renewal policy](/reference/kms-root/#renewal-under-a-policy). Absent, no principal but the ceremony role may sign. |

Credentials come from the caller's standard chain ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards)). ritueel assumes the admin role to create and read, and the ceremony role to sign. ritueel does not sign the person in and holds no credential: the chain hands it a session of the ceremony role, and ritueel checks only that the session is the ceremony role's (check 9). The `aws_kms` block is added to the schema of [the directory](/reference/directory/#ritueelyaml) with the store; it is additive, so `version` stays `1`.

## What ritueel creates

At `init` and at `root add --store aws-kms`, for each of the three keys of a root (`x509-root`, `openpgp-primary`, `ssh-break-glass`), under the admin role:

| Property | Value |
|---|---|
| Key spec, usage | `ECC_NIST_P384`, `SIGN_VERIFY`. Only SHA-384 digests are signed ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| Origin | `AWS_KMS`: the key is born in the service. Imported key material is refused. |
| Multi-Region | A primary in `region`, and a replica in `replica_region`, made with `ReplicateKey`. |
| Key policy | The one below, rendered from `ritueel.yaml`, on the primary and, separately, on the replica: AWS does not share a key policy between the keys of a multi-Region set. |
| Tags | `ritueel:root` (the label), `ritueel:purpose` (`x509-root`, `openpgp-primary` or `ssh-break-glass`), and `ritueel:openpgp-created`, the OpenPGP creation time of the key as `YYYY-MM-DDThh:mm:ssZ` ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#rules-for-every-store)). |
| Alias | None on a key ritueel creates. An adopted key may carry one. An alias is a pointer that anyone with the right permission can move; the ARN is the identity. |
| Deletion | ritueel never schedules the deletion of a key. |

## Adopting an existing key

:::note[Proposed]
Four details on this page go beyond what the maintainer decided on 2026-11-10 and 11, and await his word: that the identity of an adopted key is its ARN and not its alias; that ritueel never edits the policy of an adopted key; that the break-glass principal can never `kms:Sign`; and the check `kms-policy-replica` (3b) with its reason code.
:::

A cloud root may be a key that already exists in the service ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#adopting-a-key)). The operator's own infrastructure code may own the key, its alias and its policy. ritueel then does not create the key. At `init` and `root add` it:

1. reads the public key from the service;
2. reads the key policy and runs [the checks](/reference/kms-root/#the-checks) on it, the same checks as for a key it created;
3. fixes the OpenPGP creation time and records it in the directory and in the certificate;
4. writes the certificate.

The identity of the key is its ARN, not its alias. ritueel reads the policy at every ceremony and never edits an adopted key's policy. An adopted key must be one born in the service: key material imported from outside is refused, as it is for a created key. A key that fails a check is refused with the check's reason code. How the operator names the key to adopt is fixed with the store ([issue #12](https://github.com/truvity/ritueel/issues/12)). The root's record says it was adopted ([`adopted`](/reference/directory/#rootjson)).

## The key policy

The reference key policy: the same text for every key, with the role ARNs and the account filled in. A key that ritueel creates gets it; an adopted key's policy is the operator's, and is checked against the same rules. A role named here exists; a principal that does not is refused by AWS.

| Statement | Principal | Allows | Condition |
|---|---|---|---|
| Read | the admin role, the ceremony role | `DescribeKey`, `GetPublicKey`, `GetKeyPolicy`, `ListResourceTags`, `ListGrants` | none |
| Sign | the ceremony role only | `Sign` | `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Renew | the renewal role, only when `renewal` is declared, and only on the `x509-root` and `openpgp-primary` keys | `Sign`, and the five read actions above | `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Manage | the admin role only | `PutKeyPolicy`, `TagResource`, `ScheduleKeyDeletion`, `DisableKey`, `EnableKey` | none |
| Break glass | the break-glass principal only | `ReplicateKey`, `UpdatePrimaryRegion` | none |
| Deny replicas | every principal except the break-glass principal | `ReplicateKey`, `UpdatePrimaryRegion` | none |
| Deny grants | every principal | `CreateGrant`, `RetireGrant`, `RevokeGrant` | none |

`PutKeyPolicy` stays with the admin role because AWS refuses a policy that would lock out its own caller. The policy refuses new replicas and moving the primary Region to everyone but the break-glass principal, so that an administrator cannot copy the key to a Region where no one watches; it allows digests only (the Sign row). The replicas are made before the refusal applies, or by the break-glass principal; the sequence for the keys that ritueel creates is written here when the store is built ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#the-reference-key-policy)). No statement names the account root, and none allows `Sign` to the admin role or the break-glass principal. The break-glass SSH CA key has no Renew statement: nothing it signs is ever renewed. The `kms:` condition keys are those of the KMS documentation (read 2026-11-02, [AWS KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)); The digest of the policy text, as the service returns it, is `policy_sha256` in the record.

## A later option: a hardware-key sign-in

**Not required, not built and not checked by ritueel.** The maintainer dropped it on 2026-11-10 and 2026-11-11 and it may come back ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)). This section keeps what was learned, so that it need not be found again. If it returns, the decision is rewritten and this section becomes the detail.

A KMS root has no card, so a gate on the ceremony role is the only way to ask for a person with a hardware key. AWS does not set `aws:MultiFactorAuthPresent` for a federated sign-in (read 2026-11-06, [IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)). The way AWS documents is a session tag that the identity provider sets from the sign-in (read 2026-11-06, [session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)):

- **The tag.** Key `mfa`, value `hardware`, set by the provider only after a sign-in with a device-bound hardware key. In an OIDC token it is the claim `https://aws.amazon.com/tags`, then `principal_tags`, then `mfa`; in SAML it is the attribute `https://aws.amazon.com/SAML/Attributes/PrincipalTag:mfa`.
- **The key policy.** The `Sign` statement would add `StringEquals` on `aws:PrincipalTag/mfa` with the value `hardware`.
- **The trust policy.** Its only principal would be the federated provider, with `sts:TagSession` and `aws:RequestTag/mfa` on both statements, and no role chaining: `AssumeRole` takes caller-supplied `Tags`, so a chained principal could write the tag itself.
- **The provider.** It would have to ask for a fresh hardware-key sign-in for each ceremony, issue tokens of 5 minutes or less, and never mint the tag from a refresh token or an earlier sign-in. IAM Identity Center cannot be that provider (read 2026-11-06, [attributes for access control](https://docs.aws.amazon.com/singlesignon/latest/userguide/attributesforaccesscontrol.html), [permission sets](https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html)).
- **Freshness.** A policy variable cannot be used in a date comparison, so a tag cannot carry its own expiry. The bound is the provider's token plus the role's session, at most one hour.
- **No call returns a session's own tags** (read 2026-11-06, [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)), so a check by ritueel would need a different way to ask AWS; none was tested.

[ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/) decides that it is not required.

## The checks

Made at `init` after the keys exist, and again, reading from the service, at every ceremony that signs with the root and at the restore drill ([issue #68](https://github.com/truvity/ritueel/issues/68)). A check that cannot run is `not-run`, and the ceremony stops. Exit code 3 for each, except `kms-session`, which is 4: the key store's side refuses the session ([exit codes](/reference/cli/#exit-codes)).

| # | Check | Code |
|---|---|---|
| 1 | The ARN carries `account` and the expected Region; the key is enabled and not pending deletion. | `kms-account`, `kms-state` |
| 2 | Spec, usage and origin are as above; the key is a multi-Region primary; its `GetPublicKey` answer equals the public key in the directory. | `kms-key-spec`, `kms-key-mismatch` |
| 3 | The statement that allows `Sign` to the ceremony role carries the two conditions. | `kms-policy-sign` |
| 3a | Every statement that allows `Sign`, directly or through `kms:*` or a wildcard action, names the ceremony role, or the renewal role when `renewal` is declared, on a key that may have it and with its two conditions. Any other principal (the break-glass principal included), a renewal role that is not declared, or one on the break-glass key is refused. This is the root's form of the contract's single-principal rule ([the contract](/reference/hand-off-contract/#what-the-certifier-checks)), with the one declared exception. | `extra-sign-principal` |
| 3b | A statement denies `ReplicateKey` and `UpdatePrimaryRegion` to every principal except the break-glass principal, and no other statement allows them to anyone else. | `kms-policy-replica` |
| 4 | No statement allows the admin role or the break-glass principal to sign, and none names the account root or a wildcard principal. | `kms-policy-admin` |
| 5 | The key has no grant. | `kms-grants` |
| 6 | The replica exists in `replica_region`, has the same public key, and passes checks 1 to 5 on its own policy. | `kms-replica` |
| 7 | For a key ritueel created, the tags are present and `ritueel:openpgp-created` equals the creation time in the directory. For an adopted key, a tag is read when present and must equal the directory's value; it is not required. | `kms-tags` |
| 8 | The policy is the one the last ceremony recorded. If its digest changed, the plan says so in words and shows both digests, and the person confirms the change as part of the plan; the record keeps both. | none |
| 9 | At a ceremony that signs: `sts get-caller-identity` names a session of the ceremony role, in `account`. At a renewal: the same with the renewal role. A different role or an expired session stops the run, and the message says to take a session of the ceremony role again. | `kms-session` |

## Renewal under a policy

*Designed, built later (M7): [ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) moves it after the first release candidate.* A cloud root can renew what it already certified without a person. A card root cannot: its PIN and touch are physical, so it has the [yearly ceremony](/guides/re-sign-yearly/) and the reminders of `status`. Which acts may run unattended, and why, is taught in [Re-sign](/learn/re-sign/#what-may-run-unattended).

**The rule.** `ritueel renew` signs only what the directory already holds: the same keys, the same subjects, the same constraints and key flags, the same profile, and the same content of the root list, the CA bundle, the SSH CA key list, the CRLs and the root's own certificate and primary, each with a new validity from the time of the run and the next trust sequence. If any byte it would sign names a key, a name, a root or a constraint the directory does not already hold, it refuses. It can extend trust; it never creates it, and it never revokes.

### The policy in `ritueel.yaml`

```yaml
aws_kms:
  # ... the members above ...
  renewal:
    role: arn:aws:iam::123456789012:role/ritueel-renewal
    intermediates: [example-ca, example-release]
    within_days: 60
```

| Member | Meaning |
|---|---|
| `role` | The renewal role, by ARN, in `account`. It is the operator's to create, and is assumable only by the operator's scheduler identity ([Prepare the cloud root](/guides/prepare-the-cloud-root/)). |
| `intermediates` | The names of the `intermediates` entries that `renew` may re-sign. An empty list renews the trust products and the root only. |
| `within_days` | The earliest renewal: `renew` runs only when an item it may renew expires within this many days. 14 to 90. |

The validity of everything `renew` signs is the profile's (13 calendar months for an intermediate and a list, 25 for a CRL, 36 for the root), never more. The block is additive, so `version` stays `1`.

### What `renew` does

1. **Read, under the renewal role.** The checks 1 to 9 above, on every key it will use. A key policy with a third principal that can sign stops it (`extra-sign-principal`).
2. **Plan.** For each intermediate in `intermediates` that is not revoked or replaced, the certificate or binding over the key of its last one, with that one's subject, extensions or key flags; then the root list with the same roots, the SSH CA key list with the same keys, each root's CRL with the entries of its last one that have not expired, the root's certificate and self-signature over the same keys, the CA bundle and the keyring. It prints the plan in words and its digest, as for every ceremony, and writes it. `--plan-only` stops there.
3. **Check the plan against the directory and the policy,** below. A refused check stops the run before anything is signed.
4. **Reserve, sign, verify and record,** as the six steps of every ceremony, with no confirmation by a person: the record says `confirmation.by` `policy` ([the record](/reference/ceremony-record/#the-record)).

A request that a requester left in `requests/` is used when its key, subject and extensions equal the directory's; one that differs is refused, and the change waits for a ceremony.

### The checks of a renewal

Exit code 3 for each, except `kms-session` (4). They follow the KMS checks above, and run before anything is signed.

| # | Check | Code |
|---|---|---|
| 10 | Every active root of the directory is in `aws-kms`, and `renewal` is declared. A card or software root is refused with a message that names the yearly ceremony. | `not-in-policy` |
| 11 | Every intermediate to renew is named in `intermediates`, and is neither revoked nor replaced. | `not-in-policy` |
| 12 | Every key, subject, constraint, key flag, `use`, root and list entry in the plan is one the directory already holds for that item, and every CRL entry of the last CRL that has not expired is kept. | `key-not-in-ledger` |
| 13 | The item that expires first among those to renew expires within `within_days`. An earlier run is refused, so a schedule that runs too often cannot move the trust sequence every day. | `too-early` |
| 14 | The session is the renewal role (check 9). | `kms-session` |

### What the renewal role can and cannot do

It can keep alive what a ceremony already certified. It cannot add a key, a name or a root, change the root set, or revoke. If it is misused, an intermediate that should have lapsed keeps working until a person revokes it at a ceremony; every use is a `Sign` call in the audit trail under its own principal, distinct from the ceremony role, and each run leaves a record. What it cannot do is the reason a renewal needs no person ([principle 7](/principles/)).

**A person still meets the root.** A new key, a change of the root set and a revocation are ceremonies with the ceremony role. The [restore drill](/reference/drill/#when-it-is-due) stays yearly.

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
- **A replica that failed.** The root is not complete: `init` stops before it signs anything, and a re-run with the same plan finds the primary and replicates it, before the policy that refuses replicas is in force or through the break-glass principal.
- **A deleted or disabled key** shows as check 1 at the next ceremony or drill. For a root, that is the loss of a root: `root revoke` and `root add`.

## Follow-ups

- The `aws-kms` store, the block, the policy, the checks and their tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- The adoption path, the reworded checks, and the replica and primary-Region refusal in the reference policy, with tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- Later (M7): `ritueel renew`, the renewal policy, its checks and the Renew statement, with a test that a third Sign principal is refused ([issue #12](https://github.com/truvity/ritueel/issues/12), [issue #30](https://github.com/truvity/ritueel/issues/30)).

## Standards

| Standard | Used for |
|---|---|
| [Control access to multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-auth.html), read 2026-11-11 | Replicating a key needs `kms:ReplicateKey` in the key policy of the primary key, and `kms:CreateKey` in the replica Region; updating the primary Region needs `kms:UpdatePrimaryRegion` in both Regions. So a policy that denies them to everyone but the break-glass principal stops a copy to another Region. |
| [AWS KMS developer guide](https://docs.aws.amazon.com/kms/latest/developerguide/), read 2026-11-02 | Multi-Region keys, key policies, condition keys, `ReplicateKey` (the key policy is not shared between the keys of a set) and the lockout check. |
| [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480), [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The P-384 public key in X.509 and in OpenPGP. |
