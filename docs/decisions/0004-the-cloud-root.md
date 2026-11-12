# 0004 — Cloud keys live in one dedicated account as three replicated keys, created or adopted

**Status:** Accepted
**Date:** 2026-11-12

## Decision

1. The cloud keys live in one dedicated account that holds nothing else.
2. The account holds three keys, one for each kind of root: an X.509 root key, an OpenPGP primary and a break-glass SSH CA key. Each is a multi-Region key with a replica in a second Region. A replica is the same key. It covers a lost Region or a lost primary copy, and it is never counted as a second key. A company that wants a root independent of one provider gives it keys on cards too.
3. A cloud root signs every year at a ceremony. It has nothing to alternate with.
4. The first `apply` creates the cloud keys, born in KMS and each replicated to the declared Region, or adopts keys that already exist. Both ways leave the same checks, evidence files and ceremony records. The company's existing key may be confirmed as its OpenPGP primary.
5. The operator provides the dedicated account, an admin role, a ceremony role and a break-glass principal. The admin role creates and reads, and can never sign. Only the break-glass principal may replicate a key or move its primary Region. The ceremony role may Sign digests and is the only principal that may sign anything new.
6. The reference key policy refuses new replicas and moving the primary Region for every principal except the break-glass principal, and it allows digests only. ritueel renders one key policy from the wanted files for each key and each replica, and checks a replica's policy on its own. A lost Region is answered by the break-glass principal, a manual logged act.
7. ritueel reads the key's description and policy back every time it signs. A changed policy is shown in the plan and confirmed by the person. A KMS key is read, never taken from a claim. A key in another account is read through a read-only role created by its owner, because GetKeyPolicy does not work across accounts. A key tag on a KMS key is read when present and is not required.
8. The KMS confirmation is the typed plan digest plus a session of the ceremony role through the caller's standard credential chain. ritueel holds no credential. The record holds the key ARN, the digest of the key policy and the role session. The Sign statement keeps the conditions kms:SigningAlgorithm = ECDSA_SHA_384 and kms:MessageType = DIGEST, and has no session-tag condition and no aws:MultiFactorAuthPresent condition.
9. ritueel neither sets, requires nor checks how the person signed in, and no hardware-key gate on a cloud root is written as a rule. The role's trust policy is the operator's, and ritueel never reads it. These are removed from what ritueel asks or checks: the mfa=hardware session tag; the trust policy that names only a federated provider, and the ban on role chaining; the provider's obligations and the exclusion of IAM Identity Center; the dry-run pre-check of check 9; an organisation-policy lock.
10. The limit is accepted: nothing in AWS ties a signature to a person. Anyone who can assume the ceremony role can call Sign on any SHA-384 digest without ritueel. The typed digest is ritueel's gate, not AWS's. This widens the accepted limit in [0002](0002-where-a-key-lives.md), rule 17. An alarm on Sign is taught in the guide and not checked, and where the alarm goes is the company's own setting. Hardware keys on the cloud management account are not part of ritueel; the operator may require them of their own account.
11. A KMS key that was born and not recorded is left for the operator to schedule for deletion with the admin role. ritueel never deletes a key.
12. The aws-kms store uses the AWS SDK and holds a root key and an intermediate key, each in a KMS key. Its evidence is the key's description, policy and audit trail, read from the service every time. This is not proof that the key was made in an HSM. The software store gives no evidence at all.
13. The aws-kms store, which adopts a key, is in M2, because the cloud root is the recommended path for a team with a cloud account.

## Why

- The cloud keys are in one account that holds nothing else, so the account holds those keys and no other work.
- A replica covers the loss of a Region. So a second account is not needed for that loss, and a copy of the root key cannot appear in a Region where no one watches.
- A claim is verified, never trusted. So ritueel reads the key and its policy, and does not take them on a person's word.
- AWS does not set the multi-factor flag for a federated sign-in, so most operators could never pass a gate on it. The gate is the typed digest, and the accepted limit says so.
- The operator's own infrastructure code and roles stay the operator's. ritueel asks for no particular sign-in and reads no trust policy.

## What it costs

- The AWS side has no tie between a signature and a person. The typed digest is the only gate that is ritueel's.
- The alarm on Sign, the audit trail and any hardware key on the management account are the operator's to set up. ritueel teaches them and does not check them.
- ritueel does not check the roles' permissions, only the key policy.
- A lost Region needs a manual, logged act by the break-glass principal.
- A cloud root has nothing to alternate with, so it signs at a yearly ceremony.
- A replica is not a second key. A company that wants a root independent of one provider must give it keys on cards too.
- The record needs one key policy for each key and each replica, and a read-back at every signing.
- The aws-kms store adds work to M2.

## Roads not taken

- **A second, independent cloud key in another account.** It would give a second independent key, but it is a second account to secure, both are still on one provider, and the replica already covers the loss it answers.
- **A cloud key service as the only kind of store.** It would give one anchor and full audit, but it means one provider, no attestation, and no use on single-board computers.
- **ritueel always creates the key.** It would give one path, but it needs key-creating rights, differs for every organisation and duplicates the operator's code.
- **Adopt without reading the policy.** It is the least work, but ritueel would trust a claim, and a claim is verified, never trusted.
- **Adopt a key whose material was imported.** It would let an old key in, but the key then existed outside its store.
- **Allow replicas to any administrator.** It would make operations easier, but a copy of the root key could be made in a Region where no one watches.
- **Refuse replicas for every principal, break-glass included.** It would need no exception to explain, but a lost Region could never be recovered.
- **One key policy copied to the replica by the service.** It would be less to check, but a multi-Region set shares no policy, so the replica would carry the default one.
- **Verify the roles' permissions as well as the key policy.** It would be tighter, but IAM policies, boundaries and organisation policies make it a guess.
- **Keep the hardware-key session tag (earlier design).** It was the only proof that a hardware-key person is present, but it needs an identity provider with three obligations, so it was dropped.
- **Gate on aws:MultiFactorAuthPresent.** It looks simple, but AWS does not set it for a federated sign-in, so most operators could never pass.
- **A dedicated IAM user with a hardware MFA device.** The condition works, but it adds a long-lived principal with an access key and a second device.
- **IAM Identity Center as the provider.** It is a common provider, but its permission sets and attribute mapping cannot carry the tag.
- **aws:MultiFactorAuthPresent with BoolIfExists.** It lets federated sessions in, but only because the key is absent, so it also passes a session with no second factor.
- **Reach the ceremony role by role chaining.** It would reach the role from another one, but AssumeRole takes caller-supplied tags, so the tag proves nothing.
- **A tag that holds an expiry checked against the clock.** It would limit a session in time, but AWS allows no policy variable in a date comparison.
- **An organisation-policy lock on the keys.** It would be a second wall around the key policy, but it needs the operator's organisation to carry it, so it was dropped.
- **A card gate, a passkey identity or a management account behind the cards for the cloud root.** It would add a hardware gate, but it was dropped, and a gate is not proposed again; hardware keys on the cloud management account are the operator's own choice.

## Not yet proven or only proposed

- **Not yet proven.** Adoption of an existing cloud key: ritueel reads the public key, checks the key policy against its rules, fixes and records the OpenPGP creation time and writes the certificate. The key may carry an alias and be owned by the operator's own infrastructure code. An adopted key must still be one born in the service; imported key material is refused; a key that fails a check is refused with its reason code. It waits for a test against a real account ([#12](https://github.com/truvity/ritueel/issues/12)).
- **Proposed.** How a cloud key takes its turn when its root also has keys on cards: the card of the year ([0007](0007-changing-and-losing-a-root.md), rule 14) names cards, and a cloud key has none ([#137](https://github.com/truvity/ritueel/issues/137)).

## Replaces

0002, 0003, 0004, 0005, 0008, 0013 and 0018, in part: the cloud-root rules of each, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
