---
title: The trace area on the stick
description: The trace area of the stick: its layout, how a trace record is written and read after a cut, and the checks before the first write.
sidebar:
  order: 17
---

*Not built yet. This is the layout that the code of the ceremony on the stick writes ([issue #181](https://github.com/truvity/ritueel/issues/181)); the rules are [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 36 to 41, and [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 31, 33 and 34. Version 1 of the layout changes in place until the code is written. A number marked "starting value" is fixed after the test on a real stick. Nothing was written to a real stick for this page.*

On a real stick, a cut during a write left one 512-byte sector with the content of the write before it ([the measurement](../research/usb-stick-cut-during-a-write-2026-11-13.md)). On exFAT that destroyed journal lines that were already confirmed, and a folder's list of names. The trace area answers it: while a ceremony runs on the stick, its attempt and its journal entries are written to a small area with no file system, in sectors that are never written again.

A cite such as (0005 rule 37) names the rule that decides the statement. A statement marked Proposed is not decided and names its open issue.

## Words

- A **sector** is the smallest piece a stick reads or writes. This page says S for its size: 512 bytes, or 4096.
- The **trace area** is a partition of the stick that has no file system. Only ritueel writes it. It is never mounted.
- A **trace record** is one entry of the attempt or of a journal, or one note about an act, written into the area. Example: the attempt of a ceremony is trace record 0. In the trace area this page says "record" for it. The ceremony record of a ceremony folder is a different file ([the ceremony files](/reference/ceremony-record/)).
- A **slot** is the place of one trace record: one sector. Example: slot 1 holds trace record 1 of the first ceremony after the area is prepared.
- **Confirmed** is defined [below](/reference/trace-area/#how-a-trace-record-is-written). Example: "trace record 7 confirmed" on the screen means that record 7 is in both copies and was read back.
- A **cut** is the loss of the stick's connection, or of its power, during a write.

## The layout of the stick

The image of the offline system leaves one free entry in the partition table of sector 0. That entry becomes one **extended partition**, which holds two **logical partitions**: the trace area first, then the files partition (0005 rules 29, 31 and 36).

| Where | What | Type | Size |
|---|---|---|---|
| Sector 0 | The table. Entries 1 to 3 and the boot code are those of the image. Entry 4 is the extended partition. | 0x0F for entry 4 | Starts after the image (below) and runs to the end of the stick |
| The image of the offline system | Unchanged, except sector 0. | | 320.3 MiB for 2026.07.0 |
| Logical partition 5 | The trace area. | 0xDA | 64 MiB (starting value) |
| Logical partition 6 | The files partition, exFAT: the program, the bundles, the key files (0005 rules 30 and 31). | 0x07 | The rest of the stick |

- The start of the extended partition is the size of the image rounded up to 1 MiB, plus 1 MiB. For 2026.07.0 this is 322 MiB, sector 659456. The trace area comes first and has a fixed size, so its place does not depend on the size of the stick.
- Writing the image to the stick again rewrites sector 0 and loses entry 4. The partitions behind the image stay. Writing entry 4 again with the same start brings them back.
- The kernel of the offline system lists the logical partitions and makes a device for each. A desktop system may show them in other ways; this is [not proven](/reference/trace-area/#what-is-decided-what-is-a-starting-value-and-what-is-not-proven). Type 0xDA is not recognised by Windows and is not hidden by a Linux desktop (read, 2026-11-13).
- The types 0x0F, 0xDA and 0x07 are starting values: they are kept or changed after the tries on desktop systems.

:::note[Proposed]
If a desktop system refuses the logical partitions, the layout is reviewed ([issue #181](https://github.com/truvity/ritueel/issues/181)). The road kept as a fallback is the trace area in the tail of the exFAT partition, behind the end of the file system. It needs no second partition, but a raw write would go through the device of a mounted file system.
:::

## The header

The header is in the first block of the trace area, and a copy is in the last block. Each is one write of S bytes, made when the area is prepared and never again. Numbers are big-endian. The rest of the block stays zero.

| Offset | Bytes | Member | Value |
|---|---|---|---|
| 0 | 8 | `magic` | `RTLAREA` and a zero byte |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `sector_size` | 512 or 4096 |
| 12 | 4 | `stride` | 16384: the distance between two slots (starting value) |
| 16 | 16 | `area_id` | 128 random bits, made when the area is prepared |
| 32 | 4 | `slots` | 2047: the slots in one half (starting value) |
| 36 | 4 | `volume_serial` | The serial of the exFAT volume (bytes 100 to 103 of its boot sector) |
| 40 | 8 | `total_bytes` | The size of the partition: 67108864 (starting value) |
| 48 | 8 | `first_offset` | 16384: where slot 0 of the first half starts |
| 56 | 8 | `half_offset` | 33538048: the distance from a slot in the first half to its second copy (starting value) |
| 64 | 8 | `header_copy_offset` | 67092480: where the copy of the header sits |
| 72 | 8 | `area_lba` | The first sector of the partition on the stick (661504 for the image of 2026.07.0) |
| 80 | 64 | `text` | `ritueel trace area v1; no file system; do not write here by hand`, then zeros |
| S - 32 | 32 | `digest` | SHA-256 of bytes 0 to S - 33 |

- The text lets a person with a hex viewer see what the area is.
- `volume_serial` ties the area to the exFAT volume beside it. An exFAT volume that is formatted again has a new serial, so the area is refused until it is prepared again. This is on purpose.
- The header and its copy must be equal and valid, or the area is refused.

## Where the slots are

The area is 4096 blocks of 16 KiB. Block 0 is the header and block 4095 its copy. Blocks 1 to 2047 are the **first half** and blocks 2048 to 4094 the **second half**. Slot `i` (0 to 2046) has two places:

- the first copy at `16384 + i * 16384`;
- the second copy at the first copy plus `half_offset`, which is 32 MiB (starting value).

Only the first S bytes of a block are written. The rest stays zero.

- **Why one record in each 16 KiB.** A flash chip programs whole pages, often 4 to 16 KiB. If a cut harms more than one sector, the harm is probably inside one page, and one record in each 16 KiB means that a harmed page holds at most one record. The page size of a real stick is not known: this is an inference, not a measurement.
- **Why the second copy is 32 MiB away.** Two copies in one erase block could die together. The distance is read from the header, so the test can try other values with no new code.

## A trace record

A trace record is one slot, S bytes, big-endian. `n` counts the records of one ceremony, from 0.

| Offset | Bytes | Member | Meaning |
|---|---|---|---|
| 0 | 8 | `magic` | `RTLREC` and two zero bytes |
| 8 | 2 | `version` | 1. A reader refuses any other value. |
| 10 | 1 | `kind` | 1 attempt, 2 birth line, 3 signature line, 4 intent, 5 end |
| 11 | 1 | reserved | 0 |
| 12 | 4 | `slot` | The index `i` of this slot. The same in both copies. |
| 16 | 16 | `area_id` | The area's id |
| 32 | 16 | `ceremony_id` | 128 random bits made when the ceremony starts. It is not in `attempt.json`. |
| 48 | 8 | `g` | A number for the whole area, from 1, plus 1 for every slot ever written. It is never reused. |
| 56 | 4 | `n` | The number of this record in its ceremony. The attempt is 0. |
| 60 | 2 | `frag_i` | The index of this fragment of its entry, from 0 |
| 62 | 2 | `frag_n` | How many fragments the entry has: 1 for most |
| 64 | 4 | `plen` | The bytes of payload in this slot |
| 68 | 4 | `elen` | The bytes of the whole entry |
| 72 | 32 | `prev` | The `digest` of record `n - 1` of this ceremony; 32 zero bytes when `n` is 0 |
| 104 | `plen` | payload | The bytes of the entry, or of one fragment of it, exactly as the program made them |
| | | zeros | Padding |
| S - 32 | 32 | `digest` | SHA-256 of bytes 0 to S - 33: every byte of the record, padding included |

- **The payload is the exact bytes.** For the attempt it is the bytes of `attempt.json` (canonical JSON, no newline). For a birth line or a signature line it is the line with its newline. So the files are made byte for byte, and `attempt.json`, `births.jsonl` and `signatures.jsonl` do not change. The number and the chain exist only in the area.
- **What each part catches.** A slot that holds the content of another slot fails, because `slot` differs. A record of an old ceremony fails the chain, because `ceremony_id` and `prev` differ. A damaged or half-written slot fails the digest. A record cannot be taken out or put in without breaking the next one.
- **Capacity.** A slot holds S - 136 bytes of payload: 376 for S = 512, 3960 for S = 4096.
- **Fragments.** An entry longer than the capacity is cut into `frag_n` records, each in its own slot, written one after the other. Each fragment is a whole record with its own digest and second copy, and none is written again. An entry is complete only when its last fragment is confirmed. The longest entry is 4096 bytes; a longer one is refused and nothing is written for it. A KMS key ARN is at most 2048 characters, so no line of the plan reaches the limit.

### The kinds

| Kind | Holds | Becomes |
|---|---|---|
| 1 attempt | The bytes of `attempt.json`. | `attempt.json` |
| 2 birth line | One line of `births.jsonl`: the result of a key birth. | A line of `births.jsonl` |
| 3 signature line | One line of `signatures.jsonl`: the result of a signature. | A line of `signatures.jsonl` |
| 4 intent | What ritueel is about to do: a key birth or a signature. | Nothing: it stays in the area |
| 5 end | That the files of the ceremony were made from the area and are on the stick ([below](/reference/trace-area/#the-end-record)). | Nothing |

### The record before each act

Before each key birth and each signature, ritueel writes an intent. It then does the act and writes the result, a birth line or a signature line (0005 rule 38). So the order of the chain for one act is: intent, act, result.

- An intent names the act with what the plan already fixes: for a birth, the label, the purpose and the key store; for a signature, its place in the plan's list of signatures.
- After a cut, an intent that no result follows means that the act may have happened: a key may exist, a signature may have been made. `status` and `close` show it. The holder deletes the slot of a half-born key or schedules the cloud key for deletion, as the [birth journal](/reference/ceremony-record/#the-birth-journal) says today.
- The files do not carry intents. When a ceremony ends normally, every intent has its result, and the files hold the results only.

:::note[Proposed]
The members of an intent are fixed with the code ([issue #181](https://github.com/truvity/ritueel/issues/181)). The example below shows one proposal. Whether a ceremony on the workstation, which has no trace area, writes a record before each act, and where, is open ([issue #181](https://github.com/truvity/ritueel/issues/181)).
:::

## How a trace record is written

One function writes every trace record. There is no other write path.

1. Cut the entry into fragments of at most S - 136 bytes. Refuse an entry longer than 4096 bytes. Check that all the slots needed are free or reusable and lie inside the half.
2. For each fragment, build the record (`slot`, `g`, `n`, `prev`, payload, `digest`).
3. Write it to the first copy: one write of exactly S bytes. Any other result stops ritueel.
4. Flush the device. An error stops ritueel.
5. Read the first copy back. It must equal the record, or ritueel stops.
6. Only then write the second copy in the same way (steps 3 to 5). The two writes are never in flight together.
7. Print the line that the record is confirmed.

The device is opened once for the whole ceremony, for reading and writing, with direct I/O, a synchronous write and an exclusive claim. Buffers are aligned to 4096 bytes. The exclusive claim makes the open fail when anything else holds the device, which also stops a second ritueel.

**Confirmed** means: both copies were written, each write returned the full length with no error, each flush returned with no error, and both copies read back equal to what was written (0005 rule 37). It does not mean that the data survives a loss of power. The test stick answers a write without a real flush, so "flushed" means only that the stick said it was done. ritueel never says "safe to remove".

The screen line is printed after the last fragment of an entry is confirmed, and not before. It shows the number of the record, its kind, its slot and the first eight characters of its digest, for example `trace record 7 confirmed (birth), slot 6, both copies, chain 1d781cec`. The holder can note or photograph it. After a cut, the number on the screen is compared with the number the reader finds.

On a failed write, a failed flush, a short write or a read-back that differs, ritueel stops at once and does not retry (0006 rule 33). It prints what failed, the last confirmed record, and the whole trace it holds in memory, with the unconfirmed record marked. So a cut of the stick's connection with the machine alive loses nothing that the holder cannot copy from the screen.

:::note[Proposed]
ritueel copies itself into memory before the first write and runs from the copy, so that it keeps running when the stick goes away. That a program that runs from the stick dies when the stick vanishes is inferred, not measured ([issue #181](https://github.com/truvity/ritueel/issues/181)).
:::

## The end record

An end record (kind 5) says that the files of the ceremony were made from the area and are on the stick. Its payload is JSON and is not made into a file:

```json
{"ceremony":"<name>","outcome":"completed","record_sha256":"<digest>","files":[{"path":"history/<name>/attempt.json","sha256":"<digest>","size":186}]}
```

It has the `ceremony_id` of its ceremony, `prev` is the digest of the ceremony's last record, and `n` continues the numbering. A ceremony with an end record is **ended**. A ceremony without one is **open**. The word "closed" is kept for the closing record that `close` writes into the history (0005 rule 15).

## The ring

Slots are used in order, 0, 1, 2 and so on, and then again from 0. The **head** is the slot after the one with the largest `g`.

- A ceremony takes the next free slots in order. It is admitted only when all R slots from the head to the end of the half are free or reusable, with R = 2 x (births + signatures) + 10 (starting value). Otherwise the head moves to slot 0 and the test is made there. A ceremony never wraps in the middle.
- A slot is **reusable** only when the newest record in it belongs to an ended ceremony whose files on the stick match its end record. ritueel reads the files and compares the digests. Everything else is protected: the slots of an open ceremony, the slots of an ended ceremony whose files are missing or differ, and slots with data ritueel does not understand.
- When the slots it needs are protected, ritueel refuses to start and says which ceremony to close or join. It never overwrites (0005 rule 41).
- Reuse is the one case in which a sector that once held confirmed data is written again. The content also exists as files on the stick and, after the join, in the repository, so the sector in flight then holds old data that exists elsewhere.

How many ceremonies fit (starting values). A ceremony with five acts, two births and three signatures, is 12 records: the attempt, two for each act, and the end record. That is 24 writes. A pass of 2047 slots holds about 170 such ceremonies. The first `apply` of two roots is larger; its count is not made yet.

## How the area is read after a cut

For every slot `i`, ritueel reads the copy in the first half and the copy in the second half, S bytes each, with direct reads. It classifies each copy:

| State of one copy | How it is told |
|---|---|
| never written | All S bytes are zero. |
| whole | `magic`, `version` and `digest` are valid; `slot` is `i`; `area_id` is the header's. |
| holding another record | `magic` and `digest` are valid, but `slot` is not `i`, or `area_id` differs. This is the sign of the measured fault. The copy is ignored, and the report says which slot's record it holds. |
| torn | Not zero, and `magic` or `digest` is invalid. |
| stale | Whole, but its ceremony or `g` is older than the chain being followed: an old pass of the ring. |

It then joins the two copies of a slot:

| First copy | Second copy | Result |
|---|---|---|
| whole | whole, same bytes | good |
| whole | whole, other bytes | the two disagree: follow the one that fits the chain (`ceremony_id`, `n`, `prev`); when both fit, stop and report; never guess |
| whole | anything else | good with one copy; the report says "second copy lost" |
| anything else | whole | good with one copy; the report says "first copy lost" |
| not whole, never written | not whole, never written | empty |
| otherwise | | a hole: damaged in both places, or damaged in one and empty in the other |

To rebuild a ceremony, take its attempt (`n` is 0) and follow `slot`, `n` and `prev` in order. Stop at the first hole, empty slot or broken chain.

- **Confirmed records** are the records of the chain up to the last good one. An entry with fragments is complete only when all its fragments are good. An incomplete last entry is dropped and reported as "entry cut at record `n`".
- **The record in flight** at the cut may be present, whole in one copy, or absent. Both are correct: it was not confirmed on the screen. When it is present, ritueel keeps it and marks it unconfirmed, because an event may have happened.
- **Islands.** After the first hole, ritueel looks at the following slots for whole records of the same ceremony with a larger `n`. If one exists, a confirmed record was lost in the middle. This must not happen under the measured fault. It is reported as "damaged in both places" and counts as a loss in the tests.
- **The report** prints the ceremony's name, the last good record and its chain (eight characters), to compare with the screen; every hole, island, disagreement or lost copy; and whether the ceremony has an end record.

## How the files are made

At the end of a ceremony, and in `close` after a cut, ritueel makes the files from the good records (0005 rule 39):

1. `attempt.json` is the payload of the attempt, byte for byte. Its SHA-256 is the digest that a closing record names, so there is no new serialising.
2. `births.jsonl` is the payloads of the birth lines in order, and `signatures.jsonl` those of the signature lines. Each payload already ends with a newline. A journal is made when it has at least one line, or when the plan lists births or signatures. Intents are left out.
3. Each file is written by the [steps of the bundle page](/reference/bundle/#how-a-file-is-written).
4. A file that already exists with the same bytes is left alone. A file that exists with other bytes stops ritueel, which shows both digests. The area is the evidence, and nothing is replaced.
5. Each file is read back and its digest compared with the digest computed from the area. A difference stops the ceremony before the ceremony record is written.
6. The transcript, the artifacts and the ceremony record are written as the [order of writes](/reference/ceremony-record/#the-order-of-writes) says, and last the end record, with the digests of the files.

A cut at any step leaves the area whole. The next command makes the files again and skips what is there. The artifacts and the ceremony record are as exposed to the fault as before: the trace area does not cover them.

`status` lists every ceremony in the area. An open ceremony is critical (exit code 12), as an attempt with no ceremony record is. `close` makes the missing files, prints the attempt, the journals and each act that has an intent and no result, and writes the closing record into the history as it does today. `join` makes the missing attempt and journal files from the area first, then adds the files of its source (0006 rule 35). A bundle that was never on a trace area works as before.

:::note[Proposed]
Which command prepares the trace area, and the spelling of the flag that names a copy of it, are open. The page uses `--area SOURCE` for `status`, `close` and `join`, where SOURCE is the device of the area or a file that holds a copy ([issue #181](https://github.com/truvity/ritueel/issues/181)).
:::

## The checks before the first write

Each check is a refusal that says which fact failed. After a refusal nothing has been written. The checks run in this order; a ceremony on the stick that finds no area that passes them does not start and never falls back to files (0005 rule 40).

1. **The device can be opened.** If the open fails with a permission error, ritueel says so and stops. It runs no `sudo` and changes no permission.
2. **The bundle's volume.** `--dir` is on a mounted exFAT file system, on a device that is a partition.
3. **The disk.** The parent disk of that partition is a SCSI disk reached through USB, not removed, not read-only, and not the disk of the root file system, a swap area, a loop, device-mapper, RAID or NVMe device. A USB hard disk passes this check, because ritueel cannot tell it from a stick; the next checks decide.
4. **The table.** Sector 0 and the extended boot records are read. Entry 4 is an extended partition that holds exactly two logical partitions: the first of type 0xDA, the second of type 0x07 and the partition of check 2. Entries 1 to 3 are those of the image. The start of the area equals `area_lba` in its header.
5. **The area device.** It is the first logical partition of the same disk, a sibling of the volume of check 2, not a whole disk. Its size equals `total_bytes`.
6. **The sector size.** It equals `sector_size` in the header and is 512 or 4096.
7. **The header.** Both copies are read. `magic`, `version` and `digest` are valid, the two copies are equal, `area_id` is not zero, and `stride`, `slots`, `first_offset`, `half_offset` and `header_copy_offset` agree with `total_bytes`.
8. **The exFAT serial.** Sector 0 of the exFAT partition is read: "EXFAT" at offset 3, and its volume serial equals `volume_serial` in the header. This ties the area to the volume of the bundle, so the area of another stick fails.
9. **The exclusive open.** The device is opened with the exclusive claim. A device that is mounted or in use refuses it.
10. **The same device again.** Through the open handle: its device number is the expected one, its size equals `total_bytes`, and the header read again equals the header of check 7. This closes the gap between checking a path and opening it.
11. **The scan.** Every slot is read. A whole record with an `area_id` that is not the header's stops ritueel.
12. **The show.** ritueel prints one block: the device, its size, that it is USB, the exFAT serial, the area id, the ceremony, and the records and slots it will write. The holder already confirmed the plan (0005 rule 9), so a ceremony has no extra prompt.

The area is always the sibling of the bundle's own partition. It is never found by scanning for a header. A clone of a stick, with the same ids on two sticks, cannot be detected: the holder does not plug in two clones.

**In the code.** All writes to the device go through one function, which accepts only an offset on the grid above, a length of exactly S and a record that was encoded. A separate function writes the header and the zeros, and only the preparing of the area calls it. Offsets are computed from the header and never from the command line, and no flag takes a device, an offset or a length. No `ioctl` that writes or discards is used. A workstation opens the area for reading only.

## What the holder does after a stopped ceremony

When the offline system stopped or crashed and the stick is plugged into the workstation:

1. The desktop mounts the exFAT partition, if it can. The trace area has no file system, and nothing mounts it.
2. **Save a copy of the area first**, before anything can touch it. ritueel prints the line for it when it cannot open the device, for example `sudo dd if=DEVICE of=area.img bs=1M`, and never runs `sudo` itself. When the holder's user may read the device, `--area DEVICE` reads it directly. The workstation never writes the area. If a desktop damaged the partition, for example by an answer "Initialize" to a prompt, the copy is the only trace. For Windows no tool that saves a partition to a file was found; a Linux live system works. This was not tried.
3. `ritueel status --area area.img --dir BUNDLE` shows the open ceremony and its last confirmed record.
4. `ritueel close CEREMONY --reason "..." --area area.img --dir BUNDLE` makes the files in the bundle and closes the ceremony.
5. `ritueel join /path/to/stick` adds what the stick's exFAT holds.
6. The holder keeps `area.img` with the bundle until the next ceremony on the stick has reconciled the area. Reconciling writes the end record of a ceremony whose files are complete but whose end record was not yet written.

## Preparing a stick

The holder prepares a stick once, on the workstation. ritueel does not partition: it prints the commands, and checks the result (0005 rule 40). Proposed text for the image of 2026.07.0:

```text
sfdisk --append DEVICE <<EOF
start=659456, type=f
start=661504, size=131072, type=da
start=794624, type=7
EOF
mkfs.exfat -L RITUEEL DEVICE-PART6
```

After the image is written again, the first line alone brings the partitions back. ritueel then checks the table and that partition 6 holds an exFAT boot sector, and reads the whole area.

- If the area already holds a valid header, ritueel stops and changes nothing.
- If it holds anything else that is not zero, ritueel shows the first offset that is not zero and a short hex dump, and asks the holder to type the exFAT volume serial to confirm that the 64 MiB are erased.
- It writes zeros over the whole area, flushes, reads all back and checks that they are zero. Zero is how "never written" is told from "damaged" later. It then writes the header, flushes and reads it back, and the same for the copy. It prints the area id.

A cut during the preparing leaves an area with no valid header. Every later command refuses it, and the holder prepares it again.

## A worked example

The area id is `5c1e9a47d3b04f2a8e6171c0a9d2f4b3` and the ceremony id `0b7e41d9c6a84e35b2f09a1d77e3c8a6`. S is 512. The ceremony makes one cloud key.

| Slot | `kind` | `n` | `g` | `prev` (first eight) | `digest` (first eight) | Payload |
|---|---|---|---|---|---|---|
| 0 | 1 attempt | 0 | 1 | `00000000` | `1d781cec` | `{"ceremony":"20261120T100000Z-apply-48ea4ca7","plan_sha256":"48ea4ca7c0…86ff2","root":"A","started_at":"2026-11-20T10:00:03Z","version":1}` (186 bytes) |
| 1 | 4 intent | 1 | 2 | `1d781cec` | `fa4b2330` | `{"act":"birth","at":"2026-11-20T10:01:10Z","label":"A","purpose":"root-x509","store":"aws-kms"}` and a newline (96 bytes) |
| 2 | 2 birth line | 2 | 3 | `fa4b2330` | `c0576259` | `{"at":"2026-11-20T10:01:12Z","label":"A","place":"arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555","public_key_sha256":"0310b053…f2ec","purpose":"root-x509","store":"aws-kms"}` and a newline (258 bytes) |

Slot 0 is at byte 16384 of the area and again at byte 33554432. Slot 1 is at 32768 and 33570816, and slot 2 at 49152 and 33587200. Nothing else is written between the two copies of a slot. The full digests of the three records:

```text
1d781cec333fcb5d3021f0fe9901eda7f2ce0d00d66e6f5c3767b87654ba6daa
fa4b233097219d7ddb2d074e8c05ab1d163613fbc500035c545d5bb1647afe41
c05762597e5399966828397c7a7cd553adfe42377030f227cb52f094bcd8f480
```

If a cut leaves the sector of slot 2 with the content of the write before it, that content is record 1: its `slot` is 1, not 2, so the reader marks the copy "holding another record" and ignores it. Record 2 is then absent in that copy and the intent in slot 1 has no result: the key may exist.

## What is decided, what is a starting value, and what is not proven

| Point | State | Where |
|---|---|---|
| The stick's free entry holds an extended partition with the trace area and the files partition | Decided; the desktop systems are not tried | 0005 rules 29 and 36 |
| The trace area has no file system, is never mounted and is written by ritueel only | Decided | 0005 rules 36 and 37 |
| One trace record in a sector of its own, written once, numbered, chained, checksummed, in two copies far apart | Decided | 0005 rule 37 |
| A trace record is confirmed when both copies are written and read back; the screen shows its number | Decided | 0005 rule 37 |
| A write or a flush that fails stops ritueel at once | Decided | 0006 rule 33 |
| A trace record before each key birth and each signature, then the act, then its result | Decided | 0005 rule 38 |
| The files are made from the area at the end, byte for byte; `status`, `close` and `join` read the area first | Decided | 0005 rule 39 |
| The checks before the first write; no fall back to files; no `sudo` | Decided; the list of checks is this page | 0005 rule 40 |
| The ring and its reuse rule | Decided | 0005 rule 41 |
| The header, the members of a trace record, the kinds, the read after a cut | Layout of version 1; changes in place until the code is written | This page |
| Size of the area, 64 MiB; one record in each 16 KiB; the second copy 32 MiB away; R = 2 x acts + 10 | Starting values; fixed after the test on a real stick | Proposed ([issue #181](https://github.com/truvity/ritueel/issues/181)) |
| The types 0x0F, 0xDA and 0x07 | Starting values; fixed after the tries on desktops | Proposed ([issue #181](https://github.com/truvity/ritueel/issues/181)) |
| The members of an intent; the command that prepares the area; `--area`; the copy of the program in memory; a record before each act on the workstation | Proposed | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| A trace record written once survives a cut on a real stick; the test has about 360 cuts and passes when none loses a confirmed record or accepts a wrong one; with 360 cuts and no loss the true share of loss is at most about 1 percent at 95 percent confidence | Not yet proven | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| A real loss of power | Not yet proven; the measurement kept the stick's power | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| What Windows, macOS and a Linux desktop show for the layout | Not yet proven | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| A session of the offline system on real hardware can write the trace area as root | Not yet proven; a virtual machine showed it | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| A stick with 4096-byte sectors | The layout allows it; it is not tested, and such a stick does not boot the image | [issue #181](https://github.com/truvity/ritueel/issues/181) |
| A rename that makes a name longer is safe on exFAT under a cut | Not yet proven; not measured | [issue #181](https://github.com/truvity/ritueel/issues/181) |

The test on a real stick runs the old writer first, with the same plan and the same cuts, as a control: it must show the fault again, or the test says nothing. It then runs the new writer, counts the confirmed records that the reader does not return (L) and the records it accepts with wrong content (X), and passes when both are zero in every cut. It also tries other values of the distance between two records. The test does not cover another stick model, Windows or macOS, or the artifacts at the end of a ceremony.

## Follow-ups

- The code, the test vector of the example above as a file, and the tests with a model of the stick: [issue #181](https://github.com/truvity/ritueel/issues/181).
- The tries on three desktop systems and on the offline system on real hardware, and the real-stick test: [issue #181](https://github.com/truvity/ritueel/issues/181).
