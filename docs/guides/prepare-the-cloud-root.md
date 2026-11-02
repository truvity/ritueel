---
title: Prepare the cloud root
description: Make the dedicated AWS account, the admin role and the ceremony role that ritueel needs for a KMS root, and the controls worth adding, before the first init.
sidebar:
  order: 0.6
---

*Design phase: not built yet. The roles and the checks are specified in [The cloud root in AWS KMS](/reference/kms-root/); the code is [issue #12](https://github.com/truvity/ritueel/issues/12), in M2. ritueel creates the keys and their policy; it does not create the account or the roles ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root)). Try everything in a test account first.*

A cloud root is a permission: the key never leaves the service, so the root is as safe as the rules about who may use it. Those rules are yours to set up, once, before ritueel makes the key. This guide says what to make, in words; use whatever infrastructure tool your organisation already uses, and review the result as you would any change to who can sign for you.

## What you start with

- A cloud account for the roots and for nothing else. If it also runs services, a service's problem becomes the root's problem.
- Someone who can create roles in it, and a hardware or app authenticator for multi-factor authentication.
- The names you will put in `ritueel.yaml`: the account id, two Regions, and the two role names.

## Steps

1. **Make the account,** inside your organisation, with nothing deployed in it. Result: an account whose only job is to hold roots.
2. **Make the admin role.** It may create keys, replicate them, tag them and read them, and nothing else. It must not be able to `Sign`. Result: the role that `ritueel init` uses to make the keys.
3. **Make the ceremony role.** It trusts your identity, and only with multi-factor authentication. It may be given nothing but the right to use the root keys; the key policy that ritueel makes names this role as the only one that may sign. Result: the role the person assumes at a ceremony.
4. **Add the controls you can.** None is checked by ritueel, all are worth having:
   - an organisation policy that stops the keys being deleted or disabled by anyone but the admin role;
   - an alarm on every `Sign` by the roots, to a place you read, so a use you did not make is noticed;
   - the audit trail kept somewhere the account's own roles cannot erase.
5. **Write the names into `ritueel.yaml`** ([the block](/reference/kms-root/#ritueelyaml)). Run the drill on test keys: `ritueel init --store aws-kms` in a test account, then the restore drill.

## How you know it worked

- You can assume the admin role and read, but a `Sign` attempt with it is denied.
- You can assume the ceremony role only after multi-factor authentication.
- After `init`, `ritueel status` lists the root, and its record holds the key policy's digest.

## When something goes wrong

- **ritueel says the policy has a second principal that can sign.** A role or user was added to the key policy. Find out why before anything else: this is the check doing its job.
- **The replica is refused.** The two Regions must differ, and the admin role needs the right to create keys in the second one.

Next: [Adopting the roots](/guides/root-adoption/).
