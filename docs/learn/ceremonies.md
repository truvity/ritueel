---
title: What a ceremony is
description: A ceremony is the rare, deliberate use of a root by a person. Why it is manual, what a good one shows and records, and what a tool may safely do for you.
sidebar:
  order: 4
---

A **ceremony** is a root being used. A person is present, they look at what is about to be signed, they confirm, a key signs, and a record is written. In older PKI practice it involved a locked room, several witnesses and a script read aloud. For one holder with a card, it can be a few commands at a desk. The idea is the same.

## Why a ceremony is manual

Manual is not the same as slow. It means that **a person decides, at the moment of signing, with the facts in front of them.**

- A root is used rarely, so the cost of a manual step is small.
- A mistake is expensive and slow to undo, so the value of a human check is high.
- Automation that signs without a person is exactly what an attacker wants to reach. If a script can use the root, so can whatever controls the script.

So the rule is: **a person only where a person adds safety.** Reading the facts, typing a confirmation and touching a card need a person. Everything else, such as building a plan, checking a request, verifying a result and writing the record, can be done for the person, and should be.

## What a good ceremony does

Whatever the tool, a good ceremony does these things, in an order that keeps the person in charge:

- Every byte that will be signed is fixed in advance, in a plan: which key, which name, which lifetime, which serial number. A plan that cannot change during the ceremony cannot be swapped during it.
- The person compares the plan with what they expected and confirms it. A confirmation that is just a key press becomes a habit; a confirmation that needs typing a short digest of the plan does not.
- An attempt is written down before any key is born or signed. If the run stops, the attempt shows signatures may exist.
- The key signs. With a card, the PIN stays on the card and a touch is the proof that someone is there.
- Each result is checked with code that did not sign it.
- What was done is recorded: with which keys, in which store, and what outsiders now see. The record holds no secret.

ritueel does all of this in one command, `apply`, and it is the same in every key store ([the tools](/tools/cli/), [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).

## What a tool may do, and what it may not

| A tool may | A tool should not |
|---|---|
| Build the plan, check the request, and show the facts in a readable form. | Confirm for you, or offer a "yes to all" for irreversible steps. |
| Ask for the PIN at the terminal and pass it to the card. | Store the PIN, or retry a wrong one until the card blocks. |
| Check the result and write the record. | Treat a check that did not run as a check that passed. |
| Warn you well before a root expires. | Take a decision that belongs to you, such as revoking a root. |

The rituals you will meet are: [create](/learn/life-of-a-root/#create), sign an intermediate or a subkey, record, back up, re-sign, rotate, revoke and recover. Each is a ceremony or follows one. Revoke is its own command, done at once outside [`apply`](/glossary/).

Next: [layered trust](/learn/layered-trust/).
