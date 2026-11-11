# 0013 — The KMS ceremony role is the only signer, and ritueel asks nothing of its sign-in

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards) and [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) make a KMS root signable only through a ceremony role, and [the KMS reference](/reference/kms-root/#the-key-policy) describes its key policy. A card root has a person's PIN and touch; a KMS root has no card, so the ceremony role is the only thing between a caller and a signature. The proposal is [issue #101](https://github.com/truvity/ritueel/issues/101).

The earlier design of this record (2026-11-06) gated the role on a session tag that a federated identity provider sets after a sign-in with a hardware key, because AWS does not set `aws:MultiFactorAuthPresent` for a federated sign-in. It asked a lot of the operator: a provider with three obligations, a trust policy that names only that provider, no role chaining, and a dry-run pre-check.

The maintainer dropped the hardware-key requirement, and with it an organisation-policy lock on the keys. Neither is a rule of ritueel.

## Decision

**The ceremony role is the only principal that may `kms:Sign`, and ritueel asks nothing of how a person signed in.**

- **The `Sign` statement keeps its two `kms:` conditions,** `kms:SigningAlgorithm` is `ECDSA_SHA_384` and `kms:MessageType` is `DIGEST`, and has no session-tag condition and no `aws:MultiFactorAuthPresent` condition.
- **ritueel neither sets, requires nor checks how the person signed in.** The trust policy of the role is the operator's, and ritueel never reads it.
- **Removed from what ritueel asks or checks:** the `mfa=hardware` session tag; the trust policy that names only a federated provider, and the ban on role chaining; the obligations of the provider (a fresh sign-in, tokens of 5 minutes or less, no minting from a refresh token); the exclusion of IAM Identity Center; the dry-run pre-check of check 9; and an organisation-policy lock on the keys.
- **Kept:** the key policy still refuses a replica and a move of the primary Region except to the break-glass principal, and signs digests only; admin and break-glass can never sign; the confirmation is the typed plan digest plus a session of the ceremony role ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards)); the renewal role stays optional and later ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)).
- **Card ceremonies do not change.** PIN and touch, always ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#who-signs-and-when)).

## Consequences

- Nothing in AWS now ties a signature to a person. Anyone who can assume the ceremony role can call `Sign` on any SHA-384 digest without ritueel. The typed digest is ritueel's gate, not AWS's.
- What remains is the account's access control, the single-signer key policy, the refusal of a replica and of a move of the primary Region, and the audit trail. An alarm on `Sign` is taught in the guide and not checked.
- This widens the accepted limit of [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) ("the role that uses a cloud root").
- Any operator can use a KMS root with whatever sign-in they have. There are no provider obligations, and no dry run in the audit trail.

## Roads not taken

- **Keep the hardware-key session tag (the earlier design).** The only proof that a person with a hardware key is present, but it needs an identity provider that meets three obligations; the maintainer dropped it (see the Decision).
- **Drop the condition.** The simplest. The earlier text weighed it on 2026-11-06 and refused it as too weak for the root of a trust chain; the maintainer chose it (see the Decision).
- **Gate on `aws:MultiFactorAuthPresent`.** The natural condition, but AWS does not set it for a federated sign-in (read 2026-11-06, [IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)), so most operators could never pass it.
- **An organisation-policy lock on the keys.** A second wall around the key policy, but it needs the operator's organisation to carry it; the maintainer dropped it (see the Decision).
- **A dedicated IAM user with a hardware MFA device.** `aws:MultiFactorAuthPresent` would work unchanged, but it adds a long-lived principal with an access key and a second device to keep.
- **IAM Identity Center as the provider.** People already sign in there, but its permission sets and attribute mapping stop it from carrying the tag (read 2026-11-06).
- **`aws:MultiFactorAuthPresent` with `BoolIfExists`.** It would pass federated sessions, but only because the key is absent, so it would also pass a session with no second factor.
- **Reach the ceremony role by role chaining.** No second sign-in, but `AssumeRole` takes caller-supplied `Tags`, so the tag proves nothing.
- **A tag that holds an expiry, checked against the clock.** An exact freshness, but AWS allows no policy variable in a date comparison, so it cannot be written.

## Follow-ups

None.
