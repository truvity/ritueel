# 0004 — Cloud keys are replicated keys in an account the holder chooses, one for each kind of root, created or adopted

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. The cloud keys of a root live in an account that the holder chooses. ritueel checks each root key, its key policy and its replica, and records the account; it does not rule on what else the holder keeps there. The holder should keep there only keys that are used in ceremonies, and run no workload in it.
2. A cloud root has one key for each kind of root the bundle uses: an X.509 root key, an OpenPGP primary and a break-glass SSH CA key. Each is a multi-Region key with a replica in a second Region. A replica is the same key. It covers a lost Region or a lost primary copy, and it is never counted as a second key. A company that wants a root independent of one provider gives it keys on cards too.
3. The first `apply` creates the cloud keys, born in KMS and each replicated to the declared Region, or adopts keys that already exist. Both ways leave the same checks, evidence files and ceremony records. The company's existing key may be confirmed as its OpenPGP primary.
4. A cloud root signs every year at a ceremony. It has nothing to alternate with. A cloud root key signs only in a ceremony, with a person present who confirms the plan. Nothing renews under a policy with no person.

5. The holder provides the account, an admin role, a ceremony role, a break-glass principal and a deletion principal (rule 14). The admin role creates the keys and their replicas before the key policy of rule 6 is set, and reads them; it can never sign. After that, only the break-glass principal may replicate a key or move its primary Region. The ceremony role may Sign digests and is the only principal that may sign anything new.
6. The reference key policy refuses new replicas and moving the primary Region for every principal except the break-glass principal, and it allows digests only. ritueel renders one key policy from the wanted files for each key and each replica, and checks a replica's policy on its own. A lost Region is answered by the break-glass principal, a manual logged act.
7. ritueel reads the key's description and policy back every time it signs. A changed policy is shown in the plan and confirmed by the person. A KMS key is read, never taken from a claim. A key in another account is read through a read-only role created by its owner, because GetKeyPolicy does not work across accounts. A key tag on a KMS key is read when present and is not required.
8. The KMS confirmation is the typed plan digest plus a session of the ceremony role through the caller's standard credential chain. ritueel holds no credential. The record holds the key ARN, the digest of the key policy and the role session. The Sign statement keeps the conditions kms:SigningAlgorithm = ECDSA_SHA_384 and kms:MessageType = DIGEST, and has no session-tag condition and no aws:MultiFactorAuthPresent condition.

9. ritueel neither sets, requires nor checks how the person signed in, and no hardware-key gate on a cloud root is written as a rule. The role's trust policy is the holder's, and ritueel never reads it.
10. The limit is accepted: nothing in AWS ties a signature to a person. Anyone who can assume the ceremony role can call Sign on any SHA-384 digest without ritueel. The typed digest is ritueel's gate, not AWS's. This widens the accepted limit in [record 0002](0002-where-a-key-lives.md), rule 17. An alarm on Sign is taught in the guide and not checked, and where the alarm goes is the company's own setting. Hardware keys on the cloud management account are not part of ritueel; the holder may require them of their own account.
11. A KMS key that was born and not recorded is left for the holder to schedule for deletion with the deletion principal (rule 14). ritueel never deletes a key.

12. The aws-kms store uses the AWS SDK and holds a root key and an intermediate key, each in a KMS key. Its evidence is the key's description, policy and audit trail, read from the service every time. This is not proof that the key was made in an HSM. The software store gives no evidence at all.
13. The aws-kms store, which adopts a key, is in M2, because the cloud root is the recommended path for a team with a cloud account.

14. Only one narrow principal may schedule the deletion of a key. It is not the admin role, it may do nothing else, and it can never Sign. A deletion is scheduled with a waiting period of 30 days, which is the most that the service allows and its default. The admin role may cancel a scheduled deletion; the principal that schedules a deletion still can do nothing else.
15. An alarm on scheduling a deletion and on disabling a key is taught in the guide and not checked, like the alarm on Sign (rule 10); where the alarm goes is the company's own setting.

## Why

- ritueel can read a key, its policy and its replica, so it checks them. It cannot read what else an account holds, so it does not rule on it. Every workload in the account brings more administrators near the keys, so the advice to keep only ceremony keys there stays.
- A replica covers the loss of a Region. So a second account is not needed for that loss, and a copy of the root key cannot appear in a Region where no one watches.
- A claim is verified, never trusted. So ritueel reads the key and its policy, and does not take them on a person's word.
- AWS does not set the multi-factor flag for a federated sign-in, so most operators could never pass a gate on it. The gate is the typed digest, and the accepted limit says so.
- A deleted root key is a lost root key. AWS asks to limit who can schedule a deletion, to set a waiting period of 7 to 30 days (30 by default) and to raise an alarm on deletion events (AWS Prescriptive Guidance, AWS Key Management Service best practices, published 2025-03-24); Google Cloud KMS and Azure Key Vault also hold a deleted key for a waiting period. The waiting period leaves time to notice a scheduled deletion and cancel it (rules 14 and 15).
- The holder's own infrastructure code and roles stay the holder's. ritueel asks for no particular sign-in and reads no trust policy.

## What it costs

- The AWS side has no tie between a signature and a person. The typed digest is the only gate that is ritueel's.
- The alarm on Sign, the audit trail and any hardware key on the management account are the holder's to set up. ritueel teaches them and does not check them.
- ritueel does not check the roles' permissions, only the key policy.
- A lost Region needs a manual, logged act by the break-glass principal.
- The deletion principal and the alarms of rules 14 and 15 are the holder's to set up. ritueel teaches them and does not check them.
- A cloud root has nothing to alternate with, so it signs at a yearly ceremony.
- The record needs one key policy for each key and each replica, and a read-back at every signing.
- A company that wants a root independent of one provider must give it keys on cards too.

## Roads not taken

- **A second, independent cloud key in another account.** It would give a second independent key, but it is a second account to secure, both are still on one provider, and the replica already covers the loss it answers.
- **One dedicated account that holds nothing else, as a rule.** It would keep all other work away from the keys, but ritueel cannot check what else an account holds, and the rule would refuse a holder who keeps the roots of several bundles, or the ceremony keys of another system, in one account.
- **A cloud key service as the only kind of key store.** It would give one anchor and full audit, but it means one provider, no attestation, and no use on single-board computers.
- **ritueel always creates the key.** It would give one path, but it needs key-creating rights, differs for every organisation and duplicates the holder's code.
- **Adopt without reading the policy.** It is the least work, but ritueel would trust a claim, and a claim is verified, never trusted.
- **Adopt a key whose material was imported.** It would let an old key in, but the key then existed outside its key store.
- **Allow replicas to any administrator.** It would make operations easier, but a copy of the root key could be made in a Region where no one watches.
- **Refuse replicas for every principal, break-glass included.** It would need no exception to explain, but a lost Region could never be recovered.
- **One key policy copied to the replica by the service.** It would be less to check, but a multi-Region set shares no policy, so the replica would carry the default one.
- **Verify the roles' permissions as well as the key policy.** It would be tighter, but IAM policies, boundaries and organisation policies make it a guess.
- **Keep the hardware-key session tag.** It was the only proof that a hardware-key person is present, but it needs an identity provider with three obligations, so it is not used.
- **Gate on aws:MultiFactorAuthPresent.** It looks simple, but AWS does not set it for a federated sign-in, so most operators could never pass.
- **A dedicated IAM user with a hardware MFA device.** The condition works, but it adds a long-lived principal with an access key and a second device.
- **IAM Identity Center as the provider.** It is a common provider, but its permission sets and attribute mapping cannot carry the tag.
- **aws:MultiFactorAuthPresent with BoolIfExists.** It lets federated sessions in, but only because the key is absent, so it also passes a session with no second factor.
- **Reach the ceremony role by role chaining.** It would reach the role from another one, but AssumeRole takes caller-supplied tags, so the tag proves nothing.
- **A tag that holds an expiry checked against the clock.** It would limit a session in time, but AWS allows no policy variable in a date comparison.
- **An organisation-policy lock on the keys.** It would be a second wall around the key policy, but it needs the holder's organisation to carry it, so it is not used.
- **Multi-factor authentication for a deletion.** AWS asks for it as well as for a narrow principal, but ritueel neither sets, requires nor checks how a person signed in (rule 9), and a federated sign-in does not set the flag; the narrow principal is taken and the decision on a gate for cloud key operations is not reopened.
- **The admin role may schedule a deletion.** One principal fewer, but whoever creates and reads the keys could also start the loss of a root key (rule 14).
- **An unattended renewal role.** It would keep a cloud root alive without a yearly visit, but it would be the one act with no person present, against [record 0005](0005-a-ceremony-and-where-it-runs.md), rules 1, 9 and 17, and a second principal could sign with the root key.
- **Always three keys, also for a bundle that uses one kind.** It would give one shape for every cloud account, but a bundle with an X.509 root only would hold, pay for and guard two keys it never signs with, and [record 0006](0006-bundle-history-and-trust-files.md), rule 2, already makes the kinds optional.
- **A card gate, a passkey identity or a management account behind the cards for the cloud root.** It would add a hardware gate, but a gate is not used and not proposed again; hardware keys on the cloud management account are the holder's own choice.

## Not yet proven or only proposed

- **Not yet proven.** Adoption of an existing cloud key: ritueel reads the public key, checks the key policy against its rules, fixes and records the OpenPGP creation time and writes the certificate. The key may carry an alias and be owned by the holder's own infrastructure code. It waits for a test against a real account ([#12](https://github.com/truvity/ritueel/issues/12)).
- **Not yet proven.** An adopted key must still be one born in the service; imported key material is refused; a key that fails a check is refused with its reason code. It waits for a test against a real account ([#12](https://github.com/truvity/ritueel/issues/12)).
- **Proposed.** How a cloud key takes its turn when its root also has keys on cards: the card of the year ([record 0007](0007-changing-and-losing-a-root.md), rule 16) names cards, and a cloud key has none ([#137](https://github.com/truvity/ritueel/issues/137)).
