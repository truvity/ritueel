---
title: Rotate
description: Rotating replaces a key with a new one. It is needed on an event or after three years at most, not sooner or later, and it asks work of everyone who trusts it.
sidebar:
  order: 16
---

**Rotating means a new key replaces the old one.** It is a larger event than [re-signing](/learn/re-sign/), because everything that trusted the old key has to learn about the new one.

## When to rotate

| Reason | Example |
|---|---|
| **An event** | A suspected compromise; a change of key store (from a file to a card); a change of algorithm; a change of who holds the key. |
| **Age** | After at most three years, whatever else happened. |

Three years is the top of the cryptoperiod that NIST SP 800-57 Part 1 gives a private signing key. A forced rotation also keeps the rotation path practised: a path used only in an emergency is a path that has never been tested.

## Why not every year

A key that is sound and in good hands gains nothing from being replaced. Every rotation asks every holder and every verifier to do something, and each of those is a chance to get it wrong. So sound keys are re-signed, not replaced.

## Why not never

A key that is never replaced is exposed for longer, runs on algorithms that age, and leaves the replacement procedure a mystery for the day it is needed in a hurry.

## What rotation looks like

For an intermediate:

1. The holder makes a new key where it will live, and sends a request with proof of where it lives.
2. At a ceremony the root signs it.
3. The system switches to the new key. For a time both certificates exist.
4. The old intermediate is retired, or revoked if the reason was compromise.

For a root, rotating is a [transition](/learn/transitions/): create the new root, have the old one vouch for it, overlap, supersede. A root rotation is the biggest ritual there is; it is planned years ahead, which is why a root has an expiry and the warning that goes with it.

For OpenPGP subkeys, make a new subkey, bind it, and let the old one expire or revoke it with a soft reason (*superseded*), so old signatures stay valid. Rotating the master key means a new identity: everyone who recorded your fingerprint must record the new one, so it is the most expensive rotation.

## The rule

> **Re-sign yearly. Rotate on an event, or after at most three years.** ([principle 3](/principles/))

## What can go wrong

- **The overlap is too short.** Clients that have not yet learned the new key stop working. The overlap must last as long as the slowest client you care about needs.
- **The old key is left trusted.** After the switch, retire it. A key you no longer use but still trust is a free gift to an attacker.
- **A rotation used as a reaction to a compromise without revoking.** The new key does not stop the old key from being used. Rotate and revoke.

## In ritueel

`intermediate replace` certifies a new key for a registered intermediate; `root add` and `root retire` carry out a root transition. Both are planned (M2, M3). The steps and a drill are in the [guide](/guides/rotate-a-key/).
