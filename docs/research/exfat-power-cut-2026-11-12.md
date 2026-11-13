---
title: A power cut during a ceremony write, on a stick image (2026-11-12)
description: What a cut of the power does to a bundle on ext4 and on exFAT, tried in a virtual machine on a stick image, and what a long temporary name costs on exFAT.
sidebar:
  order: 10
---

## Question

When the power goes during the write of one ceremony to the stick, does the bundle stay whole, on ext4 and on exFAT?

## When

2026-11-12. Run 1 from 21:20 to 22:10 UTC, run 2 from 22:42 to 23:34 UTC.

## Verdict

**With the write steps of [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 31, no cut left a broken bundle, on either file system. On exFAT, a file renamed from a long temporary name kept a wrong checksum in its folder entry after a cut. A temporary name of at most 15 characters, or one more flush after each rename, removed it.**

## Method

A virtual machine (QEMU) with AirgapOS 2026.07.0 and a stick image. The writer wrote one ceremony. The machine was ended at a chosen step, plus 0 to 20 ms. A second machine then read the stick and checked the bundle. The host checked each image with `fsck.exfat` (exfatprogs 1.3.2) and `e2fsck` (e2fsprogs 1.47.2). Run 1 had 756 cuts, with the correct writer and three wrong writers. Run 2 had 792 cuts with the correct writer and two changes of it.

## What the setup over- and under-counts

- A sector in the image is written whole or not at all. A real stick does not promise that, so the trial under-counts the damage. [The measurement on a real stick](./usb-stick-cut-during-a-write-2026-11-13.md) shows it.
- The cut is the end of a process, not a loss of power. One kernel, one image.

## Numbers

Run 2, exFAT, as cut. "Not clean" means that `fsck.exfat` calls an entry corrupted.

| Writer | Cuts | Broken bundles | Not clean |
|---|---|---|---|
| The correct writer | 126 | 0 | 115 |
| Temporary names of at most 15 characters | 126 | 0 | 0 |
| One more flush after each rename | 144 | 0 | 0 |

On ext4, the same three writers had 0 broken bundles in 396 cuts, and the check was clean after the journal was replayed. In run 1, the correct writer had 0 broken bundles in 252 cuts. The three wrong writers were found.

## How to read it

An exFAT folder entry has a checksum over its parts. A long temporary name needs two name entries and a short final name one. After the rename the checksum still covers the old, longer set. The entry is right again only when the system writes it again. Linux reads such a file without a complaint, so no bundle was broken. The check tool calls it corrupted and, in repair mode, offers to delete it.

## Limits

- Not tested: a real stick, a real loss of power, Windows and macOS with such an entry, a program started from an exFAT partition.

## What this decides, and what blocks

It supports the short temporary name of [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 32, which costs no extra write. It does not show that a real stick keeps a bundle whole: that stays open in [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), line 8 of "Not yet proven or only proposed" ([#30](https://github.com/truvity/ritueel/issues/30)), and [record 0006](../decisions/0006-bundle-history-and-trust-files.md), line 8 of the same section ([#8](https://github.com/truvity/ritueel/issues/8)), and the measurement on a real stick, made later, shows damage that this trial could not.
