---
title: Re-sign every year
description: The yearly ceremony in steps. Re-sign each intermediate over the same key, extend the root keys, publish the next trust sequence.
sidebar:
  order: 3
---

*Design phase: not built yet. This page is the plan that `ritueel status` and `ritueel apply` will follow (M2, [issue #30](https://github.com/truvity/ritueel/issues/30)); there is no `yearly` command. To learn why you re-sign and why yearly, and which acts may run unattended, read [Re-sign](/learn/re-sign/) first.*

There are two paths. **Card roots and software roots** take the steps below once a year, with the card or the key file of the year; nothing renews them without you. A key file is used only in the offline system, a machine booted from a read-only system. A root on cards may also use your workstation, under the four conditions of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md). **A cloud root** takes the same steps ([record 0004](../decisions/0004-the-cloud-root.md), rule 4). Nothing renews a cloud root with no person present.

## What you start with

- The bundle, cloned and current, and `ritueel status` showing which intermediates expire when.
- The card for the year (the cards alternate), with its PIN from your password manager.
- The second card's location known, but the card not needed.
- About an hour, and a month before the first certificate expires.

## Steps

1. **Check what is due, and review the advisories.** Run `ritueel status`, then read the makers' and the cloud provider's security advisories for the cards, the firmware, the services and the algorithms in use since the last ceremony. Result: a list of intermediates, roots, root list and CRLs, with what expires when; nothing critical remains unresolved; and either no advisory touches a key, or you rotate that key instead of re-signing it ([Rotate](/learn/rotate/#when-to-rotate)). The plan that `ritueel apply` writes asks whether you did, and the ceremony record keeps the answer.
2. **Start the ceremony.** Run `ritueel apply`. It finds what is due and writes the plan. Each renewal is its own action in the plan. Result: a plan that names every certificate and binding to be signed, each key's fingerprint and where it lives, and the number of touches. Nothing has been touched yet.
3. **Read the plan.** ritueel shows the plan in words with its digest. The plan holds public information only, so it can be made on any machine and carried to another one, such as the offline system, as a saved file: for that, run `ritueel apply --plan-only`. Compare the fingerprints with the bundle. Result: you are sure each key is the one you expect.
4. **Confirm and sign.** Type the first eight characters of the digest when asked (a script passes `--confirm DIGEST`), enter the PIN at the terminal, and touch the card at each prompt, one touch for each signature. A failed touch ends the ceremony. For a key file, run `ritueel apply PLAN` in the offline system, where the ceremony runs. Result: new certificates and bindings over the same keys, the card's own root key extended, and a new trust sequence.
5. **Check the result on a second device** if you ran on your workstation: compare it with the plan before you hand it over or publish it. Result: what was signed is what the plan said.
6. **Publish the trust files.** The new CA bundle, root list, CRLs and keyring package go out through your own pipeline. ritueel prints a list of next steps; [After a ceremony](/guides/after-a-ceremony/) says what to do with each.
7. **Hand the answers back.** Each system that holds an intermediate installs its new certificate or binding.
8. **Commit the bundle,** push it to both remotes, and update the note of the end of the history.

## How you know it worked

- `ritueel check history` passes, and `ritueel status` shows no intermediate expiring within the warning period.
- Each intermediate serves its new certificate, and a client with the old and a client with the new CA bundle both validate.
- No key was made: the fingerprints are the ones from before.

## Drill

Run the same steps on a software test root in a scratch bundle made by `ritueel new --test-root`, then once on rehearsal cards. A drill starts with keys A and B of one root and one intermediate and ends when `status` is clean. The drill report shows how long each step took.
