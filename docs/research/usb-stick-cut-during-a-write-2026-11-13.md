---
title: A cut during a write on a real USB stick (2026-11-13)
description: What cutting the data connection of one real USB stick during a ceremony write did to the bundle, in 30 cut moments, and what was not tested.
sidebar:
  order: 11
---

## Question

When the connection of a real USB stick is cut during the write of a ceremony, does the bundle on its exFAT partition stay whole?

## When

2026-11-13, from 00:34 to 01:51 UTC.

## Verdict

**No. In 4 of 30 cut moments the bundle was broken. In each, one 512-byte sector held the content of the write just before it, in place of its own. The checker found all four.** The writer and the order of its flushes are not the cause.

## Method

One cheap 32 GB USB stick with one exFAT partition ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 31). The writer and the virtual machine of [the trial on a stick image](/research/exfat-power-cut-2026-11-12/), with the stick passed to the machine. The stick's data connection was switched off at a chosen step, plus 0 to 20 ms. Each cut was followed by a check of the bundle.

## What the setup over- and under-counts

- **The stick kept its power.** This is not a test of a loss of power.
- One stick of one cheap model. The test path (host, hub, passed-through commands) cannot be excluded as a cause. The cause is read from four cases and is not proven.

## Numbers

| Try | What was different | Cuts | Broken |
|---|---|---|---|
| First | none | 10 | 2 |
| Repeat | none, the same plan | 20 | 2 |
| Pause | 1 second after every flush | 20 | 2 |

The three tries used 30 different moments. The same two moments broke the bundle again in the repeat and in the pause try. 4 of 30 is 13 percent; the true share may be 4 to 30 percent. The stick rejects the cache-flush command: a try that turned it on stopped before its first cut ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 33).

| What the sector held | What was lost |
|---|---|
| A ceremony folder had the content of a journal file | The way to its files; no signature existed yet |
| A journal file had the content of its folder | Two flushed journal lines |
| The bundle's top folder had the content of a probe folder | The way to every file of an older, complete bundle |
| A request folder had the content of its parent | The way to its two files |

## How to read it

exFAT rewrites a folder's sector in place at every flush, and each appended journal line rewrites the journal's last sector. A write that goes wrong destroys the older data in that sector with the new, and no order of flushes prevents that. A stick image could not show it: there a sector is written whole or not at all.

## Limits

Not tested: a real loss of power, a file system with a journal, another stick.

## What this decides, and what blocks

It decides nothing. It blocks the choices in [#181](https://github.com/truvity/ritueel/issues/181): what ritueel does with such a stick ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), line 10 of "Not yet proven or only proposed", proposes a refusal and a refresh from the repository), the file system of the stick, and what is kept if a ceremony is interrupted. Next come a real loss of power, a file system with a journal, and another stick. Record 0005 cites this note in lines 9 and 10 of the same section.
