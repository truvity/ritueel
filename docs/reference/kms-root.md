---
title: The cloud root in AWS KMS
description: What the operator provides for a KMS root, the ritueel.yaml block, the keys and key policy ritueel creates, its checks, and renewal under a policy.
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
| The ceremony role | The principal that may `kms:Sign` with a root key at a ceremony, and the only one that may sign anything new. It can be assumed only through a sign-in with a hardware key, which the identity provider records as a [session tag](/reference/kms-root/#the-hardware-key-proof) ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)). |
| The renewal role | Optional, with a [renewal policy](/reference/kms-root/#renewal-under-a-policy). The second and last principal that may `kms:Sign`: sign-only, with no hardware-key proof, assumable only by the operator's scheduler. ritueel lets it sign only what the ledger already holds. |
| Controls around them | Optional and the operator's: an organisation policy against deleting or disabling the keys, an alarm on every `Sign`, retention of the audit trail. The guide teaches them; ritueel does not create or check them. |

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

Credentials come from the caller's standard chain ([ADR 0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards)). ritueel assumes the admin role to create and read, and the ceremony role to sign. ritueel does not sign the person in and holds no credential: the chain hands it a session of the ceremony role, made after a sign-in with a hardware key ([below](/reference/kms-root/#the-hardware-key-proof)). The `aws_kms` block is added to the schema of [the directory](/reference/directory/#ritueelyaml) with the store; it is additive, so `version` stays `1`.

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
| Sign | the ceremony role only | `Sign` | the session tag `mfa` is `hardware` (`aws:PrincipalTag/mfa`); `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Renew | the renewal role, only when `renewal` is declared, and only on the `x509-root` and `openpgp-primary` keys | `Sign`, and the five read actions above | `kms:SigningAlgorithm` is `ECDSA_SHA_384`; `kms:MessageType` is `DIGEST` |
| Manage | the admin role only | `PutKeyPolicy`, `TagResource`, `ReplicateKey`, `ScheduleKeyDeletion`, `DisableKey`, `EnableKey` | none |
| Deny grants | every principal | `CreateGrant`, `RetireGrant`, `RevokeGrant` | none |

`PutKeyPolicy` stays with the admin role because AWS refuses a policy that would lock out its own caller. No statement names the account root, and none allows `Sign` to the admin role. The break-glass SSH CA key has no Renew statement: nothing it signs is ever renewed. The `kms:` condition keys are those of the KMS documentation (read 2026-11-02, [AWS KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)); `aws:PrincipalTag` is a global condition key (read 2026-11-06, [IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)). The digest of the policy text, as the service returns it, is `policy_sha256` in the record.

## The hardware-key proof

A KMS root has no card, so the ceremony role is the only proof that a person with a hardware key is present. AWS does not set `aws:MultiFactorAuthPresent` for a federated sign-in (read 2026-11-06, [IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)), so the proof is a session tag that the identity provider sets ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)). What each party does:

| Party | Does |
|---|---|
| The identity provider | After a sign-in with a device-bound hardware key, and only then, puts the tag `mfa` = `hardware` in the token or assertion. In an OIDC token the nested form is the claim `https://aws.amazon.com/tags`, then `principal_tags`, then `mfa`, an array of one string: `{"https://aws.amazon.com/tags": {"principal_tags": {"mfa": ["hardware"]}}}`. The flattened form, for providers that cannot nest, is the claim `https://aws.amazon.com/tags/principal_tags/mfa` with the string `hardware`. In SAML it is the attribute `https://aws.amazon.com/SAML/Attributes/PrincipalTag:mfa`. It may add `auth_time`; nothing tests it ([session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html), read 2026-11-06). |
| The ceremony role's trust policy | Names the federated provider as its only principal, and nothing else (below). Its maximum session duration is one hour, the least AWS allows. The operator writes it ([Prepare the cloud root](/guides/prepare-the-cloud-root/)). |
| The key policy | Allows `Sign` to the ceremony role only when `aws:PrincipalTag/mfa` is `hardware` (the Sign row above). |
| ritueel | Asks AWS in check 9; sets nothing and reads no tag. |

### The trust policy

For an OIDC provider (`123456789012` and `idp.example.com` are placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SignInWithProof",
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/idp.example.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "idp.example.com:aud": "ritueel-ceremony",
          "aws:RequestTag/mfa": "hardware"
        }
      }
    },
    {
      "Sid": "PassTheProof",
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/idp.example.com" },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": { "aws:RequestTag/mfa": "hardware" }
      }
    }
  ]
}
```

For a SAML provider, the principal is `arn:aws:iam::123456789012:saml-provider/idp.example.com`, the first action is `sts:AssumeRoleWithSAML`, and the audience condition is `"SAML:aud": "https://signin.aws.amazon.com/saml"`. Whether `aws:RequestTag` is evaluated on the assume statement itself, and not only on `sts:TagSession`, is tested with the store ([issue #12](https://github.com/truvity/ritueel/issues/12)); the condition is on both so that neither statement alone lets a call through without the tag.

**Rules for the trust policy.**

- **The only principal is the federated provider.** No `AWS` principal, no account root, no other role. `AssumeRole` takes caller-supplied `Tags`, so any principal that may assume the role and call `sts:TagSession` could write `mfa=hardware` itself; the tag is a proof only because the provider's signed token is the only way to set it. **Role chaining into the ceremony role is forbidden**, from a person's session or from another role.
- **IAM Identity Center is not a provider for this role.** A directory attribute mapping replaces the value the identity provider sends, its permission-set roles carry trust policies the operator cannot edit, and a ceremony role reached from an SSO session is role chaining ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/#roads-not-taken)).
- **The tag is not transitive.** The provider does not set `transitive_tag_keys`.

### What the provider must do

AWS cannot see how the person signed in, so the proof is only as good as the provider. The operator picks a provider that:

1. asks for a fresh hardware-key sign-in for each ceremony (`max_age` in OIDC, `ForceAuthn` in SAML) and sets the tag only if `auth_time` meets that recency;
2. issues a token or assertion that lives 5 minutes or less;
3. never mints a token that carries `mfa=hardware` from a refresh token, a session cookie or an earlier sign-in without a fresh hardware-key sign-in.

**How fresh the proof is.** A date comparison cannot use a policy variable, so a tag cannot carry its own expiry. The bound is the provider's token (5 minutes or less) plus the role's session (at most one hour): about an hour and five minutes at the last use, for this one hop; chaining is forbidden, so it is not carried further. For a tighter bound the person's SDK credential chain (the profile or environment setting that asks for a `DurationSeconds`; this is not role chaining) requests a 15-minute session, which AWS allows.

**Why check 9 asks with a dry run.** No call returns a session's own tags: `sts get-caller-identity` returns the account, the ARN and the user id, and `sts get-session-token` is for the long-term credentials of an IAM user or the root user, which a federated session does not have (read 2026-11-06, [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html), [GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html)).

:::caution[Unverified]
That a `Sign` dry run evaluates the key policy's principal-tag condition is an assumption from the documentation of `DryRun` ([Testing your permissions](https://docs.aws.amazon.com/kms/latest/developerguide/testing-permissions.html), read 2026-11-06), which says the call returns `DryRunOperationException` when the request would succeed and `AccessDeniedException` when it would not. It does not say that principal-tag conditions are evaluated, nor which CloudTrail `eventName` and `errorCode` a dry run leaves. [Issue #12](https://github.com/truvity/ritueel/issues/12) tests both before check 9 is built. **Fallback:** if a dry run skips the condition, check 9 does only its first step, and the ceremony's first real `Sign` fails closed: AWS denies it without the tag and nothing is signed. A real `Sign` over a fixed test digest was weighed and refused: it is a signature by the root key.
:::

[ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/) is the decision; this page is the detail. The enforcement is built with the store ([issue #12](https://github.com/truvity/ritueel/issues/12)).

## The checks

Made at `init` after the keys exist, and again, reading from the service, at every ceremony that signs with the root and at the restore drill ([issue #68](https://github.com/truvity/ritueel/issues/68)). A check that cannot run is `not-run`, and the ceremony stops. Exit code 3 for each, except `kms-session`, which is 4: the key store's side refuses the session ([exit codes](/reference/cli/#exit-codes)).

| # | Check | Code |
|---|---|---|
| 1 | The ARN carries `account` and the expected Region; the key is enabled and not pending deletion. | `kms-account`, `kms-state` |
| 2 | Spec, usage and origin are as above; the key is a multi-Region primary; its `GetPublicKey` answer equals the public key in the directory. | `kms-key-spec`, `kms-key-mismatch` |
| 3 | The statement that allows `Sign` to the ceremony role carries the three conditions. | `kms-policy-sign` |
| 3a | Every statement that allows `Sign`, directly or through `kms:*` or a wildcard action, names the ceremony role, or the renewal role when `renewal` is declared, on a key that may have it and with its two conditions. Any other principal, a renewal role that is not declared, or one on the break-glass key is refused. This is the root's form of the contract's single-principal rule ([the contract](/reference/hand-off-contract/#what-the-certifier-checks)), with the one declared exception. | `extra-sign-principal` |
| 4 | No statement allows the admin role to sign, and none names the account root or a wildcard principal. | `kms-policy-admin` |
| 5 | The key has no grant. | `kms-grants` |
| 6 | The replica exists in `replica_region`, has the same public key, and passes checks 1 to 5 on its own policy. | `kms-replica` |
| 7 | The tags are present and `ritueel:openpgp-created` equals the creation time in the directory. | `kms-tags` |
| 8 | The policy is the one the last ceremony recorded. If its digest changed, the plan says so in words and shows both digests, and the person confirms the change as part of the plan; the record keeps both. | none |
| 9 | At a ceremony that signs: `sts get-caller-identity` names a session of the ceremony role, in `account`. Then, unverified until [issue #12](https://github.com/truvity/ritueel/issues/12) tests it, a `Sign` dry run on the key under that session ends in `DryRunOperationException`, which AWS returns when the real call would succeed (the fallback is in [the proof](/reference/kms-root/#the-hardware-key-proof)). At a renewal: the same with the renewal role, without the proof. A different role, an `AccessDeniedException` (the tag is missing or is not `hardware`) or an expired session (the proof lapses with it) stops the run, and the message says to sign in again with the hardware key. | `kms-session` |

## Renewal under a policy

A cloud root can renew what it already certified without a person. A card root cannot: its PIN and touch are physical, so it has the [yearly ceremony](/guides/re-sign-yearly/) and the reminders of `status`. Which acts may run unattended, and why, is taught in [Re-sign](/learn/re-sign/#what-may-run-unattended).

**The rule.** `ritueel renew` signs only what the ledger already holds: the same keys, the same subjects, the same constraints and key flags, the same profile, and the same content of the root list, the CA bundle, the SSH CA key list, the CRLs and the root's own certificate and primary, each with a new validity from the time of the run and the next trust sequence. If any byte it would sign names a key, a name, a root or a constraint the ledger does not already hold, it refuses. It can extend trust; it never creates it, and it never revokes.

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
3. **Check the plan against the ledger and the policy,** below. A refused check stops the run before anything is signed.
4. **Reserve, sign, verify and record,** as the six steps of every ceremony, with no confirmation by a person: the record says `confirmation.by` `policy` ([the record](/reference/ceremony-record/#the-record)).

A request that a requester left in `requests/` is used when its key, subject and extensions equal the ledger's; one that differs is refused, and the change waits for a ceremony.

### The checks of a renewal

Exit code 3 for each, except `kms-session` (4). They follow the KMS checks above, and run before anything is signed.

| # | Check | Code |
|---|---|---|
| 10 | Every active root of the directory is in `aws-kms`, and `renewal` is declared. A card or software root is refused with a message that names the yearly ceremony. | `not-in-policy` |
| 11 | Every intermediate to renew is named in `intermediates`, and is neither revoked nor replaced. | `not-in-policy` |
| 12 | Every key, subject, constraint, key flag, `use`, root and list entry in the plan is one the ledger already holds for that item, and every CRL entry of the last CRL that has not expired is kept. | `key-not-in-ledger` |
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
- **A replica that failed.** The root is not complete: `init` stops before it signs anything, and a re-run with the same plan finds the primary and replicates it.
- **A deleted or disabled key** shows as check 1 at the next ceremony or drill. For a root, that is the loss of a root: `root revoke` and `root add`.

## Follow-ups

- The `aws-kms` store, the block, the policy, the checks and their tests against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- `ritueel renew`, the renewal policy, its checks and the Renew statement, with a test that a third Sign principal is refused, in M3 with the yearly root extension ([issue #12](https://github.com/truvity/ritueel/issues/12), [issue #30](https://github.com/truvity/ritueel/issues/30)).

## Standards

| Standard | Used for |
|---|---|
| [AWS KMS developer guide](https://docs.aws.amazon.com/kms/latest/developerguide/), read 2026-11-02 | Multi-Region keys, key policies, condition keys, `ReplicateKey` (the key policy is not shared between the keys of a set) and the lockout check. |
| [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480), [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The P-384 public key in X.509 and in OpenPGP. |
