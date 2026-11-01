---
title: Rotate a key
description: Replace an intermediate's key, or a root, on an event or after three years. A new key, a ceremony that signs it, an overlap, and the retirement of the old one.
sidebar:
  order: 4
---

*Design phase: not built yet. This page is the plan that `ritueel intermediate replace`, `root add` and `root retire` will follow (M2 and M3). Read [Rotate](/learn/rotate/) first for why and when.*

## Before you start

- A reason: an event, or a key that is about to reach three years. If the reason is a suspected compromise, also follow [Revoke a key](/guides/revoke-a-key/).
- The card for the year, and the other card's location.
- The holder of the intermediate ready to make a new key.

## Rotate an intermediate

1. **The holder makes a new key** where it will live, and a request with proof of where it lives. Result: a request file; the old key still works.
2. **Check the request.** `ritueel handoff check STEM` runs the contract's checks and signs nothing. Result: every check that ran passed.
3. **Replace.** `ritueel intermediate replace NAME`, with `--revoke` and a reason if the old key must not be trusted any more. Confirm, enter the PIN, touch. Result: a certificate or binding for the new key.
4. **Switch.** The holder installs the answer and moves to the new key. Result: for a time both certificates are valid.
5. **Retire the old key.** After the overlap, destroy it where it lived. Result: only the new key is trusted.

## Rotate a root

A root rotation is a transition. It is planned, because a root has an expiry for this reason.

1. `ritueel root add`: make the new root in its store, and have an existing root vouch for it. Result: an overlap starts.
2. Publish the trust products with both roots. Wait until your slowest client has had time to learn the new one.
3. `ritueel root retire ROOT`: remove the old root from the next trust products. Result: only the new root is shipped.

## How you know it worked

- A client with the new bundle validates a fresh certificate; a client that has not updated still works during the overlap.
- `ritueel status` lists the new key and no longer lists the old one as active.
- The record names the reason for the rotation.

## Drill

Rotate a software test intermediate in CI, then a test root, then a root on test cards. The drill ends when a client with only the old bundle fails after the overlap, as it should.
