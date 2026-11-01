---
title: Revoke
description: Revoking declares a key untrustworthy now. Why the material is made in advance, how X.509 and OpenPGP differ, and what a revocation reaches and does not reach.
sidebar:
  order: 17
---

**Revoking is the emergency exit.** It declares a key untrustworthy now, whatever date its certificate says. It is used when a key is compromised or lost, or when a key was retired and old signatures should still be believed.

## Make it before you need it

A revocation made after a key is lost cannot be made at all, and one made in a hurry is made on the worst day of the year. So the material is prepared when the key is born:

- **OpenPGP: a revocation certificate** for the master key, made at creation and stored apart from the card, in at least two places. With it the master key can be revoked even if its card and PIN are gone.
- **X.509: the means to publish a list that leaves the key out.** An intermediate is revoked by a *certificate revocation list* (CRL) signed by the root that issued it. A root is revoked by a root list signed by a surviving root, and a CA bundle without it.

## Reasons matter

| Reason | Meaning | What verifiers do with old signatures |
|---|---|---|
| **Compromised** (a hard reason) | The key was stolen or may have been. | Distrust everything it signed, before and after. |
| **Superseded** or **retired** (a soft reason) | The key was safe and has been replaced. | Believe signatures made before the revocation. |

Choose honestly. A soft reason on a stolen key tells verifiers to believe a thief's backdated signatures.

## What a revocation reaches

A revocation is only as good as the verifier that reads it.

| Verifier | What happens |
|---|---|
| Sequoia (`sqv`, `sq`) | Rejects a revoked key. |
| `gpg` | Marks the key revoked but, measured on 2026-11-01, still reports a good signature. |
| `gpgv` and apt | Ignore the revocation. |
| An X.509 client | Honours a CRL only if it loads one; many do not, so short lifetimes matter more than CRLs. |

So for apt users **the effective revocation is a new keyring package without the key.** They are protected only when it arrives. The numbers and versions are in [OpenPGP release keys](/learn/openpgp-release-keys/#revocation). Never treat the exit status of `gpg --verify` as a trust decision.

## The steps, in outline

1. **Decide.** What is revoked, and for what reason.
2. **Revoke at the source.** The revocation certificate, or the CRL, or the root list without the key.
3. **Publish new trust products without the key:** the CA bundle, the keyring package.
4. **Replace what chained only to it.** See [recover](/learn/recover/).
5. **Record it,** with what outsiders now see.

## In ritueel

`root revoke` and `intermediate revoke` carry out the X.509 side, and `init` makes the OpenPGP revocation certificates and keeps a digest of each. Both are planned. The steps and a drill are in the [guide](/guides/revoke-a-key/).
