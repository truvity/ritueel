---
title: Rotate a key
description: Replace an intermediate's key, or a root key, on an event. A new key, a ceremony that signs it, an overlap, and the retirement of the old one.
sidebar:
  order: 4
---

*Design phase: not built yet. This page is the plan that `ritueel apply` and `ritueel revoke` will follow (M4). Read [Rotate](/learn/rotate/) first for why and when.*

## Before you start

- A reason: an event, such as an advisory that affects the key, or a key in software that is about to reach three years ([Rotate](/learn/rotate/#when-to-rotate)). If the reason is a suspected compromise, also follow [Revoke a key](/guides/revoke-a-key/).
- The card for the year, and the other card's location.
- The holder of the intermediate ready to make a new key.

## Rotate an intermediate

1. **The holder makes a new key** where it will live, and a request with proof of where it lives. Result: a request file; the old key still works.
2. **Check the request.** `ritueel check request STEM` runs the contract's checks and signs nothing. Result: every check that ran passed.
3. **Replace.** Put the request in `requests/STEM/` and run `ritueel apply`. If the old key must not be trusted any more, also run `ritueel revoke` with a reason ([Revoke a key](/guides/revoke-a-key/)). Confirm, enter the PIN, touch. Result: a certificate or binding for the new key.
4. **Switch.** The holder installs the answer and moves to the new key. Result: for a time both certificates are valid.
5. **Retire the old key.** After the overlap, destroy it where it lived. Result: only the new key is trusted.

## Rotate a root

A root key rotation is a transition. It is planned, because a root key has an expiry for this reason.

1. Write the new key in the wanted root file, with what it replaces and until when, and run `ritueel apply`: the new key is made in its store, and an existing root key vouches for it. Result: an overlap starts.
2. Publish the trust files with both root keys. Wait until your slowest client has had time to learn the new one.
3. When the date you wrote has come, run `ritueel apply`: it leaves the old root key out of the next trust files. Result: only the new root key is shipped.

## How you know it worked

- A client with the new CA bundle validates a fresh certificate; a client that has not updated still works during the overlap.
- `ritueel status` lists the new key and no longer lists the old one as active.
- The record names the reason for the rotation.

## Drill

Rotate a software test intermediate in CI, then a test root, then a root on rehearsal cards. The drill ends when a client with only the old CA bundle fails after the overlap, as it should.
