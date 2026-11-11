---
title: How a KMS key works
description: What an AWS KMS signing key is made of, what limits it, how a signature happens, how a replica works, and how it compares with a card slot.
sidebar:
  order: 12.4
---

*Design phase: ritueel is in design and has no release. The cloud root is not built yet ([the cloud root](/reference/kms-root/)), and where a page says what ritueel does, it is the design. The facts on this page were read on 2026-11-10 in AWS's documentation, and no call was made to AWS. Prices and limits change: check them before you rely on them.*

A cloud root has no card, no PIN and no touch. What keeps it from being used by the wrong person, and what happens if it is deleted? AWS KMS (Key Management Service) keeps keys that can sign but cannot be taken out. A program asks it to sign a digest, and it answers with the signature. The rules about who may ask are the whole protection, so this page spends most of its words on them.

A cloud root is link 1 of [the custody chain](/learn/custody-chain/), the way a root card is. The rare, manual use of it is [a ceremony](/learn/ceremonies/), and the steps to set one up are [Prepare the cloud root](/guides/prepare-the-cloud-root/). A deleted key or a locked account is a case for [Recover](/learn/recover/). This page is the cloud counterpart of [how a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/), and it explains the "read from the service" kind of evidence in [what a key store can prove](/learn/what-a-store-can-prove/).

## What it is made of

A KMS key is a record in an AWS account, and the account is its boundary: the roles, the policy and the trail all belong to it. The key material is inside AWS's hardware security modules (HSMs). Seven parts take part in a signature.

- **The roles.** The people and programs that call KMS do so through roles. The key policy names them.
- **The key policy.** One per key, and the first gate. It decides who may sign, read and manage.
- **The key.** A KMS key is a container for key material, named by an ARN: `arn:aws:kms:REGION:ACCOUNT:key/KEYID`. The ID is generated and has nothing to do with the material. A multi-Region key's ID starts with `mrk-`. Four things are fixed when the key is made, and none can be changed after:
  - the key spec, which is the kind of key (for example ECC_NIST_P384);
  - the use (sign and verify; each key has exactly one use);
  - where the material was born, the origin (AWS_KMS means inside KMS);
  - whether it is multi-Region.
- **The alias.** A name that points at a key. It is a separate thing: it can be moved to another key of the same key spec and use, and it is deleted with the key. A policy that names the alias matches only a request that names the alias too. So a policy or a record should name the key by its ARN.
- **A replica.** A copy of a multi-Region key in a second Region. See the table below.
- **The trail.** CloudTrail records every call to KMS, including every Sign. It belongs to the account, not to the key.
- **The alarm.** An alarm can watch the trail for a Sign and send a message.

Grants, tags and a description are separate things attached to the key. A grant can allow but never deny. Tags and aliases can be read by policies, so the right to change them is itself a power over the key.

**What a replica shares and what it does not**

| Same on the primary and the replica | Separate on each |
|---|---|
| The key ID (only the Region in the ARN differs) | The key policy |
| The key material, so the same public key | The grants |
| The origin, the key spec and the use | Whether it is enabled |
| Which one is primary | The aliases, the tags and the description |

AWS does not copy any of the right-hand column. A replica made without a policy gets the default policy. A replica is a full key: it can sign when the primary and the other replicas are disabled. It needs the primary only for rotation and for moving the primary to another Region. Only a primary can be replicated, there is one key per Region in a set, and a single-Region key can never be turned into a multi-Region key.

## What limits it

- **Key spec, use, origin and multi-Region cannot change.** To change one you make a new key. A new key has a new public key.
- **It cannot be exported.** AWS says the private key is made inside KMS and never leaves it unencrypted, and that its HSMs are validated to FIPS 140-3 Security Level 3 (KMS FAQ). Those are AWS's claims.
- **It cannot prove where it was born.** `GetPublicKey` returns the key's ARN, the public key, its spec, usage and algorithms. It returns no certificate and no signed statement about where the key was born. The FIPS validation is a claim about the service, not about this key. A card can give a certificate that names its serial number; for a KMS key you read the key's description and policy from AWS instead.
- **No PIN or touch on Sign itself, and no limit per session.** `Sign` has no field for either. The only proof of who is calling is the role session, and a session can sign many times. The sign-in that makes the session could require a hardware key, through a session tag; ritueel does not require it ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)).
- **It cannot rotate by itself.** Automatic rotation exists only for symmetric keys. For a signing key, rotating means a new key with a new ID, a new public key and a new fingerprint.
- **Nothing inside KMS protects it from whoever can write its policy.** Anyone who can change the key policy, create grants, or change the tags and aliases that policies read can give themselves the right to sign. So the protection rests on a narrow policy and on the controls around it, listed below.
- **The policy can lock you out.** By default no one, not even the account root user or the key's creator, may use a key unless a key policy, an IAM policy or a grant allows it. AWS refuses a new policy that would stop its caller from changing the policy again. That check can be switched off; AWS says not to do so lightly.
- **Speed and size.** The message is up to 4096 bytes; for more, send a digest and say so. The default quota for ECC keys is 1,000 cryptographic requests a second per account and Region, shared with Verify; it can be raised (AWS KMS request quotas; an example further down the same page gives a smaller figure). AWS publishes no signing time, so none is given here.

**Disabling and deleting**

| State | Sign | GetPublicKey | Can it come back? |
|---|---|---|---|
| Enabled | works | works | not applicable |
| Disabled | fails | works | yes, enable it again |
| Pending deletion (7 to 30 days; 30 by default; up to 24 hours longer) | fails | fails | yes: cancel before the period ends. The key then comes back Disabled and must be enabled. |
| Deleted | gone | gone | no. The key, its material, its metadata and its aliases are deleted for good. |

- AWS advises disabling instead of deleting when you are not sure. A key that was made only in KMS has no other copy. A replica in another Region may be the only surviving copy.
- A primary that has replicas waits in a state called pending replica deletion until every replica is deleted. Only then does its own waiting period start. A replica can be deleted at any time and made again from the primary. To remove a primary and keep a replica, first promote the replica.
- A deleted key can no longer sign. Its public key may live on outside KMS, and an alarm cannot see its use there.

## How a signature happens

1. **Someone signs in and takes the role.** This is where a person takes part: the sign-in, once, not each signature.
2. **The role session calls Sign** with the key's ARN, a digest and an algorithm.
3. **The key policy decides:** is this role allowed, and this algorithm? A policy can also require a digest rather than a message.
4. **KMS signs inside the HSM.** There is no PIN and no touch.
5. **KMS returns the signature,** with the key ARN and the algorithm.
6. **The call is written to the trail.** An alarm can fire on it (optional).

- The digest is made by the caller. KMS signs what it is given and cannot show what it is signing, as with a card.
- The signature is a DER object for an ECDSA key. It carries no time. Record the key and the algorithm, because verifying needs them. Anyone with the public key can verify outside KMS.
- The trail records who called (the role and the session), when, from which address, and which key. It leaves out the answer. A trail can be set to leave out KMS events altogether, so be careful who may change a trail.

## How you could use it

**A root with a replica.**

- One multi-Region key: a primary in one Region and a replica in a second.
- ritueel's design for a KMS root (not built yet): key spec P-384, use sign, born in KMS (a key with imported material is refused), no alias (the design names the key by its ARN), a separate policy on the replica, and ritueel never schedules a deletion. See [the cloud root](/reference/kms-root/) and [prepare the cloud root](/guides/prepare-the-cloud-root/).

**A delegated key with exactly one signer.**

- A key that a requester holds in its own KMS account and that the root certifies. ritueel reads the key, its policy and its public key from AWS KMS and refuses unless every statement in the key policy that allows Sign names the same one role. That check reads key policy statements only. It does not see IAM policies, grants or role chains, which is why the design denies grants (below). A key in another account is read through a small read-only role in that account.

## What a policy should say

Each rule is followed by its reason and by whose rule it is.

- **Name the key by its ARN, not by an alias.** An alias is a pointer that anyone with the right permission can move. *ritueel's design.*
- **Let as few roles sign as the job needs.** Whoever can sign can sign. *ritueel's design for a root:* the ceremony role, plus one renewal role only when a renewal policy is declared. *For a delegated key:* exactly one role (hand-off contract). Never the admin role or the account root.
- **Say what it may sign:** one algorithm (ECDSA_SHA_384) and digests only. This limits what a stolen session can do. *ritueel's design.*
- **Say how the signer got in.** AWS does not set `aws:MultiFactorAuthPresent` for a federated sign-in (IAM global condition keys, read 2026-11-10), so a hardware-key sign-in can be shown to AWS only as a session tag that the provider sets, and that proof is only as good as the provider. *ritueel's design:* it asks for no particular sign-in ([ADR 0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/)); a hardware-key session tag is a later option ([the reference](/reference/kms-root/#a-later-option-a-hardware-key-sign-in)).
- **Deny grants to everyone.** A grant can hand out Sign to anyone and cannot be denied by another grant. *ritueel's design.*
- **Keep `PutKeyPolicy` with one admin role.** A new policy can say who signs, and AWS refuses a policy that would lock out its caller, so the admin role keeps the act and has no right to sign. *ritueel's design.*
- **Alarm on every Sign, and keep the trail safe.** The call is the only trace, and a trail can leave KMS events out. These controls are the operator's.

A key policy can also limit where a replica may go, with the condition keys `kms:ReplicaRegion` and `kms:PrimaryRegion` (AWS KMS condition keys, read 2026-11-10).

## A YubiKey slot and a KMS key, side by side

| | A PIV slot | A KMS key |
|---|---|---|
| Where the key is | In the card's chip, in one slot. | In AWS's HSMs, in one Region, and in a second with a replica. |
| What guards a signature | The slot's PIN and touch rules. | The key policy and the caller's role session. |
| What proves where it was born | The card's certificate, signed under Yubico. | No certificate; AWS states FIPS validation of its HSMs. |
| What a copy means | A key born on the card has no copy. | A replica is a copy by design. |
| What a loss means | The key is gone with the card. | A deleted key is gone after 7 to 30 days. |
| What a thief needs | The card, the PIN, and a touch if the rule asks. | Permission. No physical thing. |
| What it costs | A card, bought twice. | See below. |

- **Where it is.** A PIV key never leaves the card. A KMS key never leaves unencrypted, and one session can sign many times.
- **What proves where it was born.** The card's certificate says: made on this card, with this serial, firmware and rules, and anyone can ask for it without the PIN. For a KMS key you read the description and policy from AWS, and AWS's statements are claims.
- **A copy.** One imported into a PIV slot is a copy, and attestation will not vouch for it.
- **A loss.** A card reset deletes every key, so the answer is a second, independent card. A lost AWS account makes the key unreachable, and a replica may be the only other copy.
- **A thief.** For KMS: a session of a role the policy allows, or the right to rewrite the policy, make grants or edit tags and aliases.
- **Cost of a KMS key.** USD 1 a key a month, prorated hourly; a replica is billed as a key (AWS KMS pricing, read 2026-11-10). AWS's own example, an ECC P-256 key signing 100,000 files, is USD 0.15 per 10,000 requests; AWS shows no separate figure for P-384. Asymmetric requests are outside the free tier.

## Sources

All read 2026-11-10. AWS KMS developer guide, `https://docs.aws.amazon.com/kms/latest/developerguide/`:

- [concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html);
- [key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html) and [the default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html);
- [condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html) (`kms:ReplicaRegion`, `kms:PrimaryRegion`);
- [grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html);
- [aliases](https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html);
- [multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html);
- [key states](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html) and [deleting keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html);
- [rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html);
- [request quotas](https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html);
- [CloudTrail, the Sign event](https://docs.aws.amazon.com/kms/latest/developerguide/ct-sign.html).

AWS KMS API reference, `https://docs.aws.amazon.com/kms/latest/APIReference/`: [Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html), [GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html), [PutKeyPolicy](https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html), [CancelKeyDeletion](https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html) (the key comes back Disabled), [CreateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html) and [ReplicateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReplicateKey.html) (only a primary can be replicated; a single-Region key cannot become multi-Region).

Other AWS pages: [AWS KMS pricing](https://aws.amazon.com/kms/pricing/) (USD 1 a month, prorated hourly; the P-256 example); [AWS KMS FAQ](https://aws.amazon.com/kms/faqs/) (FIPS 140-3 Security Level 3; the key never leaves unencrypted); [IAM global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) (no multi-factor flag for a federated sign-in).
