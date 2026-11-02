---
title: Run a drill
description: Practise a recovery on test keys, run the restore check on your real ledger and read the report, so that the first real recovery is not the first.
sidebar:
  order: 7
---

*Design phase: not built yet. The command and the scripts are specified in [Drills and the restore check](/reference/drill/) ([issue #68](https://github.com/truvity/ritueel/issues/68), [issue #20](https://github.com/truvity/ritueel/issues/20)); the reasons are in [ADR 0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/). The ideas are in [The ledger](/learn/the-ledger/).*

A ceremony happens about once a year, so nobody is practised, and the day you need a recovery is the worst day to learn it. A drill is a practice with a known start and a known end, on test keys, in which a mistake costs nothing. There are two kinds, and you run both: the **walk-through**, on test keys, and the **restore check**, on your real ledger.

## What you start with

- The ritueel repository, or the drill scripts from it, and a scratch directory.
- For a walk-through on cards: two test cards, prepared as in [Prepare a root card](/guides/prepare-a-root-card/), whose serials you put in the environment. Never a card that holds or will hold a real root.
- For the restore check: a clean machine, the ledger cloned, your revocation files in reach, the last record's digest from where you kept it, and your signers file.

## Steps: a walk-through

1. **Pick the drill.** The list is in [the reference](/reference/drill/#walk-throughs): start with the lost-card drill.
2. **Set up.** `drills/lost-card/setup.sh` makes a scratch directory with two test roots and one intermediate. Result: the start state, and nothing real.
3. **Run it.** `drills/lost-card/run.sh` runs the steps of [A lost root card](/guides/lost-root-card/). On test cards, add `--cards` and give the serials; it pauses at every PIN and every touch. Result: a card is out of use, a replacement root is added, and the intermediate is certified again.
4. **Check it.** `drills/lost-card/check.sh` checks the end state against the checks of the guide, and writes a report with how long each ceremony took, from the records. Result: pass or fail, and a time from loss to refusal.

## Steps: the restore check

1. **Run it.** `ritueel drill restore --expect-last DIGEST --allowed-signers FILE --revocation-dir DIR`. Result: a table of seven checks, each `passed`, `failed` or `not-run`.
2. **Read every line.** A check that did not run is not a check that passed. Give it what it lacked (the card, the credentials, the file), or accept it by name if it cannot run on this machine.
3. **Commit the report** under `drills/` in the ledger.

## How you know it worked

- The walk-through ends with `check.sh` passing, in CI and once on test cards.
- The restore check exits 0, with no step left `not-run` that you did not accept.
- The report says how long each step took. Write the total next to the date: that is what a real loss costs.

## When something goes wrong

- **A revocation file is missing or its digest differs.** Find the right copy now. This is the failure the drill exists to find; it costs nothing today and everything on the day.
- **The signers file does not verify the history.** Someone committed with a key you do not list, or you listed the wrong one. Find out which before you trust the ledger.
- **A card is not connected.** Check 5 cannot run for it. Fetch the card from its place: that also tells you whether you can.

## Drill

Run the lost-card walk-through twice: once in CI-style on test roots, and once on test cards. Then run the restore check on a copy of your ledger with one revocation file deleted, and read how it fails.
