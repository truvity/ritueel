---
title: Prepare the cloud root
description: Make the AWS account, the admin role and the ceremony role that ritueel needs for a KMS root, and the controls worth adding, before the first apply.
sidebar:
  order: 0.6
---

*Design phase: not built yet. The roles and the checks are specified in [The cloud root in AWS KMS](/reference/kms-root/); the code is [issue #12](https://github.com/truvity/ritueel/issues/12), in M2. ritueel creates the keys and their policy, or adopts a key that already exists ([record 0004](../decisions/0004-the-cloud-root.md)); it does not create the account or the roles ([record 0001](../decisions/0001-what-ritueel-is.md)). Try everything in a test account first.*

A cloud root is the recommended path for a team with a cloud account ([which path is yours](/learn/key-stores/#which-path-is-yours)), and this guide is its first step. It is a permission: the key never leaves the service, so the root is as safe as the rules about who may use it. Those rules are yours to set up, once, before ritueel makes or adopts the key. This guide says what to make, in words; use whatever infrastructure tool your organisation already uses, and review the result as you would any change to who can sign for you.

## What you start with

- A cloud account for the root's keys. Keep only keys that are used in ceremonies in it and run no workload there: if the account also runs services, a service's problem becomes the root's problem. ritueel does not check this.
- Someone who can create roles in it.
- The names you will put in `ritueel.yaml`: the account id, two Regions, and the two role names. The break-glass principal is not named in `ritueel.yaml`; it is in the key policy.

## Steps

1. **Make the account, or choose one,** inside your organisation, with no workload deployed in it. Result: an account that holds only keys used in ceremonies.
2. **Make the admin role.** It may create keys, tag them and read them. It may replicate a key only before the policy that refuses replicas is in force, and it may do nothing else. It must not be able to `Sign`. Result: the role that the first `ritueel apply` uses to make the keys and their replicas, before the policy that refuses replicas is set.
3. **Make the break-glass principal.** It is the only principal that may replicate a key or move its primary Region once the key policy is in force, for example after the loss of a Region. Create it like the admin role and never name it after a person. It must not be able to `Sign`. Using it is a manual act that you log. Result: a lost Region can still be answered, and nobody else can copy the key to a Region where no one watches ([record 0004](../decisions/0004-the-cloud-root.md)).
4. **Make the ceremony role.** Its trust policy is yours to write, and ritueel never reads it. ritueel asks nothing of how the role is assumed ([record 0004](../decisions/0004-the-cloud-root.md)). Because nothing in AWS ties a signature to a person, make the role hard to assume: whoever can assume it can sign any digest. It may be given nothing but the right to use the root keys; the key policy that ritueel makes names this role as the only one that may sign anything new. Result: the role the person assumes at a ceremony.
5. **Add the controls you can.** None is checked by ritueel, all are worth having:
   - an alarm on every `Sign` by the roots, to a place you read, so a use you did not make is noticed;
   - the audit trail kept somewhere the account's own roles cannot erase.
6. **Write the names into `ritueel.yaml`** ([the block](/reference/kms-root/#ritueelyaml)). Run the drill on test keys: `ritueel new DIR` and `ritueel apply` in a test account, then the restore check.

## If the key already exists

If your own infrastructure code already owns a key, with its alias and its policy, ritueel can adopt it instead of creating one ([adopting an existing key](/reference/kms-root/#adopting-an-existing-key)). The key must have been born in the service, and its policy must pass the same checks as one ritueel renders, the refusal of new replicas and of moving the primary Region included. ritueel reads the policy at every ceremony ([record 0004](../decisions/0004-the-cloud-root.md), rule 7). Adopting a key is not yet proven: it waits for a test against a real account. Proposed, not decided: ritueel never edits the policy of an adopted key (a change is yours to make in your code), and the key is known by its ARN, not by its alias.

## How you know it worked

- You can assume the admin role and read, but a `Sign` attempt with it is denied.
- You can assume the ceremony role, and only that role can `Sign`.
- After the first `apply`, `ritueel status` lists the root, and its ceremony record holds the key policy's digest.

## When something goes wrong

- **ritueel says the policy has a principal that can sign that it does not expect** (`extra-sign-principal`). A role or user was added to the key policy. Find out why before anything else: this is the check doing its job.
- **ritueel says the session is not a session of the ceremony role, or has expired** (`kms-session`, exit code 4). Take a new session of the ceremony role and run the ceremony again.
- **The replica is refused.** The two Regions must differ, and the admin role needs the right to create keys in the second one. Once the key policy is in force, only the break-glass principal may replicate.
- **ritueel says the policy does not refuse replicas** (the reason code `kms-policy-replica` is proposed). A statement allows `ReplicateKey` or `UpdatePrimaryRegion` to a principal other than the break-glass principal. Remove it in your code.

Next: [Adopting the roots](/guides/root-adoption/).
