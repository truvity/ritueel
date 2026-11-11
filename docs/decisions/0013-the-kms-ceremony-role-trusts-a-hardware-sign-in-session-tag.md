# 0013 — The KMS ceremony role needs no hardware-key sign-in for now

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards) and [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) make a KMS root signable only through a ceremony role, and [the KMS reference](/reference/kms-root/#the-key-policy) describes its key policy. A card root has a person's PIN and touch; a KMS root has no card, so the ceremony role is the only thing between a caller and a signature. The proposal is [issue #101](https://github.com/truvity/ritueel/issues/101).

The earlier design of this record (2026-11-06) gated the role on a session tag that a federated identity provider sets after a sign-in with a hardware key, because AWS does not set `aws:MultiFactorAuthPresent` for a federated sign-in. It asked a lot of the operator: a provider with three obligations, a trust policy that names only that provider, no role chaining, and a dry-run pre-check. The facts it rested on are kept, with their dates, in [the KMS reference](/reference/kms-root/#a-later-option-a-hardware-key-sign-in).

The maintainer decided to drop the hardware-key requirement for now, and with it an organisation-policy lock on the keys. It may come back later.

## Decision

**The ceremony role needs no hardware-key sign-in, and ritueel asks for none.**

- **The ceremony role is the only principal that may `kms:Sign`.** The `Sign` statement keeps its two `kms:` conditions, `kms:SigningAlgorithm` is `ECDSA_SHA_384` and `kms:MessageType` is `DIGEST`, and has no session-tag condition and no `aws:MultiFactorAuthPresent` condition.
- **ritueel neither sets, requires nor checks how the person signed in.** The trust policy of the role is the operator's, and ritueel never reads it.
- **Removed from what ritueel asks or checks:** the `mfa=hardware` session tag; the trust policy that names only a federated provider, and the ban on role chaining; the obligations of the provider (a fresh sign-in, tokens of 5 minutes or less, no minting from a refresh token); the exclusion of IAM Identity Center; and the dry-run pre-check of check 9.
- **Kept:** the key policy still refuses a replica and a move of the primary Region except to the break-glass principal, and signs digests only; admin and break-glass can never sign; the confirmation is the typed plan digest plus a session of the ceremony role ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards)); the renewal role stays optional and later ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)).
- **The hardware-key proof stays described as a later option,** marked not required, not built and not checked, in [the KMS reference](/reference/kms-root/#a-later-option-a-hardware-key-sign-in). If it returns, this record is rewritten in the design phase; after the first release a new record supersedes it.
- **Card ceremonies do not change.** PIN and touch, always ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#who-signs-and-when)).

## Consequences

- Nothing in AWS now ties a signature to a person. Anyone who can assume the ceremony role can call `Sign` on any SHA-384 digest without ritueel. The typed digest is ritueel's gate, not AWS's.
- What remains is the account's access control, the single-signer key policy, the refusal of a replica and of a move of the primary Region, and the audit trail. An alarm on `Sign` is taught in the guide and not checked.
- This widens the accepted limit of [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) ("the role that uses a cloud root").
- Any operator can use a KMS root with whatever sign-in they have. There are no provider obligations, and no dry run in the audit trail.
- ADR 0004 and 0008 are reworded in place again, as the design phase before the first release allows ([decision records](/contributing/decisions/#changing-a-record)).

## Roads not taken

- **Keep the hardware-key session tag (the earlier design).** The only proof that a person with a hardware key is present, but it needs an identity provider that meets three obligations; the maintainer dropped it for now.
- **Drop the condition.** The simplest. The earlier text weighed it on 2026-11-06 and refused it as too weak for the root of a trust chain; the maintainer chose it for now.
- **A dedicated IAM user with a hardware MFA device.** `aws:MultiFactorAuthPresent` would work unchanged, but it adds a long-lived principal with an access key and a second device to keep.
- **IAM Identity Center as the provider.** People already sign in there, but its permission sets and attribute mapping stop it from carrying the tag (read 2026-11-06).
- **`aws:MultiFactorAuthPresent` with `BoolIfExists`.** It would pass federated sessions, but only because the key is absent, so it would also pass a session with no second factor.
- **Reach the ceremony role by role chaining.** No second sign-in, but `AssumeRole` takes caller-supplied `Tags`, so the tag proves nothing.
- **A tag that holds an expiry, checked against the clock.** An exact freshness, but AWS allows no policy variable in a date comparison, so it cannot be written.

## Follow-ups

None.
