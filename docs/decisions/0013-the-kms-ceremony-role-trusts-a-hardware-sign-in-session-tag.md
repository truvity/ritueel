# 0013 — The KMS ceremony role trusts a hardware-sign-in session tag

**Status:** Accepted
**Date:** 2026-11-06

## Context

[0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards) and [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) make a KMS root signable only through a ceremony role that "needs multi-factor authentication", and [the KMS reference](/reference/kms-root/#the-key-policy) writes that as the condition `aws:MultiFactorAuthPresent`. A card root has a person's PIN and touch; a KMS root has no card, so this role is the only proof that a person is present. The proposal is [issue #101](https://github.com/truvity/ritueel/issues/101).

The condition cannot be met by many operators. AWS documents that `aws:MultiFactorAuthPresent` "is not present for federated identities or requests made using access keys" (IAM global condition keys, read 2026-11-06). An organisation whose people reach AWS only through a federated sign-in, with no IAM users, can never pass it, so the root could not be used at all. The same page suggests the way out: "pass the authentication method from your identity provider to AWS as a session tag".

Three facts of AWS, read 2026-11-06, bound the design:

- **A session tag comes only from the sign-in.** The identity provider puts it in the OIDC token (the `https://aws.amazon.com/tags` claim) or the SAML assertion (`PrincipalTag:<key>`, or `AccessControl:<key>` for IAM Identity Center), and the role's trust policy must allow `sts:TagSession`. The caller of `AssumeRoleWithWebIdentity` cannot add or change it ([session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)). A session tag overrides a tag of the same key attached to the role.
- **The tag is visible to policy, not to the caller.** `aws:PrincipalTag/<key>` is in the request context of every call the session makes, so a key policy can test it. No API returns a session's own tags: `sts:GetCallerIdentity` returns the account, the ARN and the user id, and `sts:GetSessionToken` can be called only with an IAM user's or the root user's long-term credentials.
- **Freshness cannot be compared with the clock.** Policy variables cannot be used with date operators, so a tag holding an expiry time cannot be checked against `aws:CurrentTime`; `aws:TokenIssueTime` is compared only with a fixed date; `sts:DurationSeconds` does not apply to the assume-role operations. What bounds a session is the lifetime of the token it was made from, which AWS refuses once expired, and the role's maximum session duration, which is at least one hour.

## Decision

**The ceremony role is gated on a session tag that the identity provider sets after a sign-in with a hardware key.** We replace `aws:MultiFactorAuthPresent` with it, and change nothing else about the ceremony.

- **The tag.** Key `mfa`, value `hardware`. The value is set only when the sign-in that produced the token used a device-bound hardware key (a security key or a card), checked by the provider; a software or synced passkey, a one-time code or a password does not set it. A provider may add `auth_time` (seconds since 1970) for the audit trail; no policy tests it.
- **The key policy.** The `Sign` statement of the ceremony role keeps its two `kms:` conditions and gains `StringEquals` on `aws:PrincipalTag/mfa` with the value `hardware`, in place of `aws:MultiFactorAuthPresent`. The tag is a condition of the key's own policy, so it holds for every path to the role, whatever the role's identity policies say.
- **The trust policy** (the operator's, [Prepare the cloud root](/guides/prepare-the-cloud-root/)). It trusts the provider and allows `sts:TagSession`, and requires `aws:RequestTag/mfa` to be `hardware`, so that an assumption without the tag fails and a tag attached to the role itself can never stand in for the proof. Its maximum session duration is the minimum, one hour.
- **Freshness is the sum of two bounds.** The provider issues the token only after a fresh hardware-key sign-in, and with a lifetime of 5 minutes or less; the session lasts at most the role's one hour. So a proof is at most about an hour and five minutes old at its last use, and the person's chain should ask for a 15-minute session. This is a bound, not a clock check, and the page that teaches it says so.
- **Which providers can set the tag.** Any provider that can map a hardware-key sign-in to the claim or the attribute: an OIDC provider through the token claim, a SAML provider through the assertion, and IAM Identity Center through a passed-through `AccessControl:mfa` attribute. A system that holds intermediates, such as sluis, can be one when its AWS role exchange sets the tag from a policy, after a step-up (RFC 9470) to a hardware-attested sign-in; that is its own decision and is not assumed here. The proof is a standard AWS mechanism that any provider can set, so ritueel and the systems it hands intermediates to stay loosely coupled ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)); ritueel names no provider.
- **ritueel does not set, mint or read the tag.** It cannot read it: check 9 of [the KMS reference](/reference/kms-root/#the-checks) asks AWS instead, with a dry run of `Sign` under the session, which succeeds only if the key policy would allow the real one. A missing or stale proof is `kms-session`, exit code 4.
- **Card ceremonies do not change.** PIN and touch, always ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#who-signs-and-when)). The renewal role stays without a person and without the tag ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)).
- **Enforced: later.** This record fixes the design. The key policy, check 9 and the guide are built with the `aws-kms` store, against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)); until then the documentation is the target state and nothing is checked.

## Consequences

- A federated operator can run a KMS ceremony; with `aws:MultiFactorAuthPresent` they could not.
- The proof is only as good as the provider's statement. AWS cannot see how the person signed in, and a provider that sets `mfa=hardware` without checking it defeats the gate. ritueel teaches this, and the person still types the plan digest at the terminal; the tag is one barrier among those.
- A recent sign-in is a bound of about an hour, not a minute. A ceremony that needs a tighter bound asks the provider for a shorter token and the chain for a 15-minute session.
- Check 9 makes a `Sign` call with `DryRun`. It appears in the audit trail as a `Sign` by the ceremony role, so an alarm on `Sign` fires for it; the guide tells the operator to expect it at a ceremony.
- A tag name is now part of the operator's setup. A provider that spells it differently fails closed.
- The pages that said "multi-factor authentication" for the KMS role say "a hardware-key sign-in" instead; a card's PIN and touch are unchanged.

## Roads not taken

- **A dedicated IAM user with a hardware MFA device.** `aws:MultiFactorAuthPresent` would work unchanged, but it adds a long-lived principal with an access key, which is what an account reached only by federation avoids, and a second MFA device to keep.
- **Drop the condition.** The simplest, but a KMS root has no card, so the typed digest and the role's trust alone would let any session that can reach the role sign for the root; too weak for the root of a trust chain.
- **A tag that holds an expiry, checked against the clock.** An exact freshness, but AWS allows no policy variable in a date comparison, so it cannot be written; the two bounds above are what AWS gives.
- **`aws:MultiFactorAuthPresent` with `BoolIfExists`.** It would pass federated sessions, but only because the key is absent, so it would also pass a federated session with no second factor.
- **ritueel reads the tag and decides.** It would let ritueel print a better message, but no API returns the session's tags, and a check the key policy does not make is not the gate.
- **Name one provider in ritueel.** Easier to document, but it couples the products; the tag is standard, so any provider that sets it works.

## Follow-ups

- Render the `mfa` condition into the key policy, check 9 with the dry run, and the guide's trust-policy step, in the `aws-kms` store, and test it against a test account with a provider that sets the tag and one that does not ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- Track the enforcement and the wording in the pages that name the role ([issue #101](https://github.com/truvity/ritueel/issues/101)).
