---
title: Re-sign every year
description: The yearly ceremony in steps. Re-sign each intermediate over the same key, extend the root that signs, publish the next trust sequence, and check expiry.
sidebar:
  order: 3
---

*Design phase: not built yet. This page is the plan that `ritueel yearly` will follow (M2, [issue #30](https://github.com/truvity/ritueel/issues/30)). To learn why you re-sign and why yearly, read [Re-sign](/learn/re-sign/) first.*

## What you start with

- The ledger, cloned and current, and `ritueel status` showing which intermediates expire when.
- The card for the year (the cards alternate), with its PIN from your password manager.
- The second card's location known, but the card not needed.
- About an hour, and a month before the first certificate expires.

## Steps

1. **Check what is due.** Run `ritueel status`. Result: a list of intermediates, roots, root list and CRLs, with what expires when. Nothing critical remains unresolved.
2. **Make the plan.** Run `ritueel yearly --plan-only`. Result: a plan that names every certificate and binding to be signed, each key's fingerprint and where it lives, and the number of touches. Nothing has been touched yet.
3. **Read the plan.** Compare the fingerprints with the ledger. Result: you are sure each key is the one you expect.
4. **Confirm and sign.** Run `ritueel yearly --plan FILE`, type the first eight characters of the plan's digest when asked, enter the PIN at the terminal, and touch the card at each prompt. Result: new certificates and bindings over the same keys, the card's own root extended, and a new trust sequence.
5. **Publish the trust products.** The new CA bundle, root list, CRLs and keyring package go out through your own pipeline.
6. **Hand the answers back.** Each system that holds an intermediate installs its new certificate or binding.
7. **Commit the ledger,** push it to both remotes, and update the last-digest note.

## How you know it worked

- `ritueel records verify` passes, and `ritueel status` shows no intermediate expiring within the warning period.
- Each intermediate serves its new certificate, and a client with the old and a client with the new bundle both validate.
- No key was made: the fingerprints are the ones from before.

## Drill

Run the same steps on a software test root in a scratch directory (`--test-root`), then once on test cards. A drill starts with two roots and one intermediate and ends when `status` is clean. The record shows how long each step took.
