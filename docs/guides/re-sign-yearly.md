---
title: Re-sign every year
description: The yearly ceremony in steps. Re-sign each intermediate over the same key, extend the root, publish the next trust sequence; or let a cloud root renew.
sidebar:
  order: 3
---

*Design phase: not built yet. This page is the plan that `ritueel due` and `ritueel run` will follow (M2, [issue #30](https://github.com/truvity/ritueel/issues/30)); there is no `yearly` command. `ritueel renew` for a cloud root comes later (M7). To learn why you re-sign and why yearly, and which acts may run unattended, read [Re-sign](/learn/re-sign/) first.*

There are two paths. **Card roots and real software roots** take the steps below once a year, with the card or the key file of the year, in a machine booted from the read-only offline system; nothing renews them without you. **A cloud root** can take the same steps, or let the operator's scheduler run `ritueel renew` under a declared renewal policy ([below](/guides/re-sign-yearly/#a-cloud-root-under-a-renewal-policy)).

## What you start with

- The directory, cloned and current, and `ritueel status` showing which intermediates expire when.
- The card for the year (the cards alternate), with its PIN from your password manager.
- The second card's location known, but the card not needed.
- About an hour, and a month before the first certificate expires.

## Steps

1. **Check what is due, and review the advisories.** Run `ritueel status`, then read the makers' and the cloud provider's security advisories for the cards, the firmware, the services and the algorithms in use since the last ceremony. Result: a list of intermediates, roots, root list and CRLs, with what expires when; nothing critical remains unresolved; and either no advisory touches a key, or you rotate that key instead of re-signing it ([Rotate](/learn/rotate/#when-to-rotate)). The plan that `ritueel due` writes asks whether you did, and the record keeps the answer.
2. **Make the plan.** Run `ritueel due`. Each renewal is its own action in the plan. Result: a plan that names every certificate and binding to be signed, each key's fingerprint and where it lives, and the number of touches. Nothing has been touched yet.
3. **Read the plan.** The plan holds public information only, so it can be made on any machine and carried to the offline system as a saved file. Compare the fingerprints with the directory. Result: you are sure each key is the one you expect.
4. **Confirm and sign.** Run `ritueel run PLAN --confirm DIGEST` in the offline system, with the digest the plan showed (without `--confirm`, type the first eight characters of the digest when asked), enter the PIN at the terminal, and touch the card at each prompt. Result: new certificates and bindings over the same keys, the card's own root extended, and a new trust sequence.
5. **Publish the trust products.** The new CA bundle, root list, CRLs and keyring package go out through your own pipeline.
6. **Hand the answers back.** Each system that holds an intermediate installs its new certificate or binding.
7. **Commit the directory,** push it to both remotes, and update the last-digest note.

## How you know it worked

- `ritueel records verify` passes, and `ritueel status` shows no intermediate expiring within the warning period.
- Each intermediate serves its new certificate, and a client with the old and a client with the new bundle both validate.
- No key was made: the fingerprints are the ones from before.

## A cloud root under a renewal policy

`ritueel renew` (planned for later, M7) re-signs what the directory already holds, over the same keys, as the renewal role and with no person: the intermediates the policy names, the root list and the other trust products with the same content, and the root's own certificate and primary ([renewal under a policy](/reference/kms-root/#renewal-under-a-policy)). It refuses anything new.

1. **Declare the policy** in `ritueel.yaml` under `aws_kms.renewal`: the renewal role, the intermediates it may renew, and how many days before expiry it may run. Result: the next ceremony renders a key policy with the Renew statement, which you confirm in its plan.
2. **Have the operator make the renewal role and the schedule** ([Prepare the cloud root](/guides/prepare-the-cloud-root/)). The scheduler runs `ritueel status --output json` and calls `ritueel renew` when a finding falls within the policy's days. Result: a run that is too early is refused with `too-early`, and one that is due writes a record whose confirmation is `policy`.
3. **Publish and hand back** as in steps 5 and 6 above, from the operator's pipeline. Result: each system that holds an intermediate installs its new certificate or binding.
4. **Read the alerts.** A failed run is an alert from the scheduler, and `status` keeps warning at 60, 30 and 14 days. Result: a broken schedule is noticed a month before anything expires.

A person still meets the root for everything that is not a renewal: a new key, a change of the root set, a revocation, and the yearly [restore drill](/guides/run-a-drill/).

## Drill

Run the same steps on a software test root in a scratch directory (`--test-root`), then once on test cards. A drill starts with two roots and one intermediate and ends when `status` is clean. The record shows how long each step took.
