# 0018 — A cloud root may be an existing key that ritueel adopts

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#the-cloud-root) has ritueel create the three keys of a cloud root and render their key policy at `init`, under an admin role. Many operators keep their keys and policies in their own infrastructure code, with an alias on the key. A tool that must create the key needs key-creating rights and differs for every organisation; 0008 already weighed that ("ritueel creates the account and the roles"). The key is still born in the service and kept by it, so [principle 1](/principles/) holds.

A replica of a cloud key is a copy made by an administrator. Without a rule in the key policy, an administrator could copy the key to another Region with no alarm.

The proposal is the design round of 2026-11-10 and 11, tracked in the issue under Follow-ups. Nothing new is decided about the hardware sign-in proof: [0013](/decisions/0013-the-kms-ceremony-role-trusts-a-hardware-sign-in-session-tag/) stays the target for the ceremony role and stays "enforced later".

## Decision

### Adopting a key

- **A cloud root may be an existing key that ritueel adopts.** ritueel reads the public key, checks the key policy against its rules ([the checks](/reference/kms-root/#the-checks)), fixes and records the OpenPGP creation time, and writes the certificate. It need not create the key.
- **The key may carry an alias, and the operator's own infrastructure code may own the key and its policy.**
- **Creating the keys at `init` (0008) stays a second way.** Both ways leave the same checks, the same evidence files and the same records.
- **An adopted key must still be one born in the service.** Key material imported from outside is refused, as before. A key that fails a check is refused with its reason code.

### The reference key policy

- **The reference key policy for a cloud root refuses new replicas and moving the primary Region,** for every principal except the break-glass principal. It allows digests only.
- **The break-glass principal is the operator's,** like the admin role and the ceremony role.
- **How the first replica is made** under such a policy is written in the KMS reference when the store is built.

## Consequences

- The operator's infrastructure code and ritueel's checks must agree on one policy, so the policy lives in one package that both use (the later Go library of the roadmap).
- The OpenPGP creation time of an adopted key is kept in the directory and in the certificate. A key tag is read when it is present and is not required, so check 7 of the KMS reference is reworded.
- A lost Region is answered by the break-glass principal, which is a manual, logged act.
- "Digests only" is already in the Sign statement of the KMS reference; what is new is the refusal of replicas and of moving the primary Region.
- This is decided, not yet tried against a real account. The store is built with the cloud root.

## Roads not taken

- **ritueel always creates the key.** One path, but it needs key-creating rights, differs for every organisation and duplicates the operator's code (0008).
- **Adopt without reading the policy.** The least work, but ritueel would trust a claim, and a claim is verified, never trusted (principle 4).
- **Allow replicas to any administrator.** Easier operations, but a copy of the root key could be made in a Region where no one watches.
- **Refuse replicas for every principal, break-glass included.** No exception to explain, but a lost Region could never be recovered.
- **Adopt a key whose material was imported.** It lets an old key in, but the key then existed outside its store (principle 1).

## Follow-ups

- Build the adoption path in the `aws-kms` store, reword the checks, add the refusal of replicas and of moving the primary Region to the rendered reference policy, and test against a test account ([#12](https://github.com/truvity/ritueel/issues/12)). The Go library for infrastructure code is later and is tracked by the same issue until it has its own.
