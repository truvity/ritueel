---
title: One sector of one cheap USB stick held the write before it, in 4 of 30 cut moments of its connection (2026-11-13)
description: Cutting the data connection of one cheap exFAT USB stick during a ceremony write broke the bundle in 4 of 30 cut moments. One sector held the write before it.
sidebar:
  order: 15
---

## Question

Can a cheap USB stick keep the files of a ceremony whole when its connection is cut during a write? The question has two parts. First, what does a trial on a stick image in a virtual machine show? Second, what does one real stick show?

Words used the same way throughout. A **ceremony** is one run of ritueel that makes keys or signatures. A **bundle** is the folder of files that a ceremony adds to ([the bundle](../reference/bundle.md)). A **sector** is the 512 bytes in which a stick is written and read. A **cluster** is the group of sectors that exFAT gives to a file. A **journal** is a file to which lines are only added. A **flush** is a request to the system to write data to the stick now. The **cache-flush command** is the matching command to the stick (SCSI SYNCHRONIZE CACHE).

## When

Image trials: 2026-11-12 (run 1 from 21:20 to 22:10 UTC, run 2 from 22:42 to 23:34 UTC). Real stick: 2026-11-13, from 00:34 to 01:51 UTC. This note brings together two earlier notes, [the trial on a stick image](./exfat-power-cut-2026-11-12.md) and [the real stick](./usb-stick-cut-during-a-write-2026-11-13.md) (the title of the first says "power cut"; in that trial a virtual machine was ended and no power was cut). It adds the counts and the follow-up tries that those notes leave out.

## Verdict

**No. On one real stick, 4 of 30 cut moments left a broken bundle. In each of the four, one 512-byte sector was found that held the content of the write just before it, in place of its own content.** Three times the sector was the list of names of a folder. Once it was a data sector of a journal file. The same moments broke the bundle again when the plan was run again. A pause of one second after every flush changed nothing. The stick answered the one cache-flush command it was sent with an error. The checker called all four bundles BROKEN and gave a reason each time.

**This is not a power-loss test.** The data connection of the stick was cut by switching its USB port off in software. The stick kept its power the whole time. What a loss of power does to this stick is not tested.

The trials on a stick image (756 and 792 cuts) found no broken bundle with the right writer. They could not show this fault, because in an image a sector is written whole or not at all.

## What was tested

| Item | Value |
|---|---|
| Stick | USB id `048d:1234`. The public USB id list names this id "Chipsbank CBM2199 Flash Drive". It is a cheap stick of one model. One piece was tested. |
| Size | 61,440,000 sectors of 512 bytes (29.3 GiB) |
| Format | Made on the host before the first run: one partition (a classic MBR partition table, type 7) from sector 2048 to the end, `mkfs.exfat` with no options except a label. The stick was not formatted again between the four tries. |
| Cache | The kernel reads no caching mode page from the stick and logs `No Caching mode page found` and `Assuming drive cache: write through`. With that setting the kernel sends no cache-flush command. |
| Host | Linux 7.0. The host never mounted the stick. It checked the partition read only with `fsck.exfat -n` (exfatprogs 1.3.2). |
| Virtual machine | QEMU 10.2.1 with KVM. The guest (the system that runs inside the virtual machine) is AirgapOS 2026.07.0, an offline Linux system ([the AirgapOS note](./airgapos-with-added-partitions-2026-11-13.md)), kernel 7.0.0airgap, no network, a boot disk that is thrown away at the end. The stick is given to the guest as a USB device, so the guest sends its own commands to the stick. |
| exFAT driver | The one in the guest kernel. The tools print no separate version. Mount options: `rw,relatime,fmask=0022,dmask=0022,iocharset=utf8,errors=remount-ro`. |
| Writer | The ritueel writer for one ceremony, with the rules of [record 0006](../decisions/0006-bundle-history-and-trust-files.md): a file is written whole or not at all (rule 31) under a temporary name of at most 15 characters (rule 32). The steps are those of [how a file is written](../reference/bundle.md): write, flush the file, rename, flush the folder. The two flush steps are marked "proposed" on that page. A ceremony is 63 steps. |
| Checker | The ritueel check of a bundle. After a cut it puts the bundle in one class: OLD (the ceremony changed nothing yet), INCOMPLETE (planned or started, and it can be finished), NEW (finished) or BROKEN (a state that no cut of this writer may leave: for example a file is lost, out of order or torn, or a journal line is gone). |

## Method

1. A guest writes one ceremony into a new folder of the stick. The writer stops before each of its 63 steps and waits for the host.
2. The host picks one step at random and a delay of 0 to 20 ms. It lets the writer go on from that step. After the delay it writes `1` to the kernel's `disable` file of the stick's USB port. The stick disconnects at once. The host stops the guest.
3. After 2 seconds the host writes `0` to the same file. The stick comes back. The host checks the partition read only. A second guest mounts the stick, runs the checker on the folder of the run and unmounts it.
4. The next run writes into a new folder. Nothing is formatted between runs, so the folders of earlier runs stay.

A **cut moment** is one step plus one delay. Four tries ran, each after an uncut run that must end NEW:

- **Try 1:** 10 cuts, nothing changed.
- **Try 2:** 20 cuts, a new plan, nothing changed.
- **Try 3:** the 20 moments of try 2 again, with a pause of 1 second after every flush that returns.
- **Try 4:** the 20 moments of try 2, with the kernel told that the stick has a write cache, so that it sends a cache-flush command at every flush. Only the kernel's setting changes. No command goes to the stick to change its cache.

The 50 cuts of tries 1 to 3 used 30 different cut moments. Try 3 repeats the moments of try 2.

## What the setup over- and under-counts

Most limits of the setup are listed in "What this does not show". One more is given here.

- **The stick holds the damage of earlier tries.** It was not formatted between tries. The host's file-system check is therefore cumulative and is not given per cut.

## Numbers

### What is counted

A run is one write of a ceremony. A cut is a run that was cut. Uncut runs are calibration runs (they list the steps of a writer) and baselines (they must end NEW). This note counts **cuts**, never uncut runs.

| Trial | Runs in total | Uncut runs | Cuts |
|---|---|---|---|
| Image, run 1 | 774 | 18 (8 calibration runs and 10 baselines) | 756 |
| Image, run 2 | 808 | 16 (6 calibration runs and 10 baselines) | 792 |
| Real stick, tries 1 to 3 | 53 | 3 (one before each try) | 50 |
| Real stick, try 4 | 1 | 1 (it ended with an error) | 0 |

### The real stick, four tries

| Try | What was different | Cuts | BROKEN | INCOMPLETE | OLD |
|---|---|---|---|---|---|
| 1 | nothing | 10 | 2 | 8 | 0 |
| 2 | nothing, a new plan of 20 moments | 20 | 2 | 17 | 1 |
| 3 | the plan of try 2, a pause of 1 s after every flush | 20 | 2 | 17 | 1 |
| 4 | the plan of try 2, the kernel sends the cache-flush command | 0 | | | |

- 4 of the 30 different moments broke the bundle. That is 13 percent. If the 30 moments are taken as random draws, the exact 95 percent interval for 4 of 30 is 3.8 to 30.7 percent, so about 4 to 31 percent. With 30 moments, read the interval as a rough size only.
- Tries 2 and 3 broke the bundle at the same two moments, with the same checker result. The other 18 cuts had the same class in both. The fault came back at the same moments on the same stick, so it does not look like chance.
- Try 4 stopped before its first cut. Its uncut run failed in the step that prepares the stick, at the first flush, before the ceremony writer took its first step. The stick answered the cache-flush command (SCSI operation code 0x35) with an error. The error has the SCSI codes sense key `0x5` (illegal request) and additional sense code `0x24`, qualifier `0x0`. The kernel returned an I/O error and the preparation stopped. This is one answer to one command. With the kernel setting "write through" the kernel sends no flush, and tries 1 to 3 ran with that setting.

### The four broken bundles

The sector was read from the stick, read only, after the cut.

| Try, cut | Step (of 63), delay | The sector that was wrong | What it held | What the checker said |
|---|---|---|---|---|
| 1, cut 4 | 27, 7 ms | The first sector of the ceremony folder (its list of names) | The first sector of the data of the birth journal (162 bytes) | No usable attempt after event 2. No signature existed yet. The files themselves were on the stick and whole. |
| 1, cut 8 | 36, 5 ms | The first data sector of the signatures journal | A copy of the first sector of its own folder | The journal tail is not a prefix of the expected line. 2 whole journal lines after event 5 were lost. They had been flushed and confirmed. |
| 2, cut 9 | 2, 5 ms | The first sector of the top folder of the bundle | The first sector of the probe folder that the writer made just before | 22 items lost, 2 unexpected. The way to every file of an older, complete bundle was gone. The cut came at step 2 of a new ceremony, when it made its first folder. |
| 2, cut 13 | 58, 7 ms | The first sector of a request folder | The first sector of its parent folder | 8 unexpected items. The folder lists itself, and its own two files cannot be reached. |

In try 3, the same two moments of try 2 gave the same checker result (the same lost and unexpected items). The sectors were read from the stick for tries 1 and 2, not for try 3. In cut 4 the files were read from the stick and were whole. In cut 9 the list of the next folder down was read and was intact. In cut 13 the files were not read; the checker found them unreachable. In the journal case (cut 8), two confirmed journal lines were lost.

### The time the stick needed to come back

The time runs from the moment the stick left the USB bus to the moment it was back at the same port. It includes the fixed wait of 2 seconds between the two commands.

| Group | Cuts | Time to return, range | Median |
|---|---|---|---|
| Broken bundle | 6 (two in try 1, two in try 2, two in try 3) | 29.8 to 30.2 s | 30.0 s |
| Not broken | 44 | 8.9 to 9.4 s | 9.1 s |

The 6 broken cuts are all the long ones, and none of the 44 others is long. This is a sign seen from outside, on one stick. The long time is not tested as a way to detect the fault.

### The trials on a stick image

Run 1 (756 cuts) and run 2 (792 cuts) wrote to an image of the stick's partition and are described in [the earlier note](./exfat-power-cut-2026-11-12.md). The right writer left no broken bundle in either run.

## How to read it

### Measured

- At 4 of 30 moments, one sector was found that held the content of the write just before it. No second wrong sector was found in the places that were read: the folder and journal sectors, the clusters next to them, and the allocation bits of the files' clusters. The allocation bitmap was not compared sector by sector.
- The same two moments broke the bundle in tries 2 and 3, with the same checker result. The sectors were read for tries 1 and 2, not for try 3. A pause of 1 second changed no result, cut by cut.
- The stick answered the one cache-flush command it was sent with an error. With the kernel's own setting for this stick, the kernel sends no such command.
- The stick needed about 30 seconds to come back after each of the 6 broken cuts and about 9 seconds after each of the other 44.

### Inferred

This is a reading of four cases on one stick. It is not proven.

- At a flush, the kernel sends two commands. In cut 4 it sent the data sector of a file and then the folder's sector. In cut 8 it sent the folder's sector of the flush before and then a data sector. The cut fell inside the second command. The stick stored, at the address of the interrupted command, the data it still held from the command before.
- The fault is most likely in the stick's controller. The test path (the guest's commands passed through, the host's USB controller, the hub) cannot be excluded.
- A pause cannot help, because the damage is the write that is in flight at the cut. It is not an earlier write that had not settled.
- No order of flushes seems able to prevent it. exFAT rewrites a folder's sector in place at every flush of a file in that folder. Every appended journal line rewrites the last sector of the journal. A write that goes wrong destroys the older, confirmed data of that sector together with the new data. Only one order of flushes, with and without a pause, was tried.

## What an image trial can show, and what it cannot

An image file under a virtual machine writes a sector whole or not at all. A real stick does not promise that. So an image trial cannot show a sector that holds the content of another write. That is why the image trials found no broken bundle and the real stick did.

An image trial can show faults of the writer and of the file system's own rules. In run 2, `fsck.exfat` called an entry corrupted after 115 of 126 exFAT cuts with the writer as it was, after 0 of 126 with temporary names of at most 15 characters, and after 0 of 144 with one more flush after each rename. The project chose the short temporary name ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 32). The details are in [the earlier note](./exfat-power-cut-2026-11-12.md).

## What the project did with this finding

The project decided that, while a ceremony runs on the stick, its attempt and its journals go to a trace area with no file system. Each trace record has a sector of its own, is written once and is written a second time far from the first copy ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 36 to 41, and [the trace area](../reference/trace-area.md)). This is decided, it is not built, and it is not proven. A test on a real stick, with about 360 cuts, must lose no confirmed trace record and accept none with wrong content, and the old writer, run first as a control, must show the fault again. The discussion is in [issue 181](https://github.com/truvity/ritueel/issues/181).

## What a reader can do

This is advice from one stick. It is not a result.

- Do not treat a cheap stick as the only copy of anything that matters. Keep the bundle in another place, and refresh the stick from it.
- Use a checker that reads every file and compares it with its digest, and that notices a missing file, a journal that lost lines, and a folder that lists the wrong names. The checker used here gave a reason for each of the 6 broken runs.
- After a write that was interrupted, check the stick before the next ceremony.

## What this does not show

- **A loss of power.** The stick kept its power. A real power cut, with a programmable power switch or by hand, was not done.
- **More than one stick.** One stick of one cheap model, 30 cut moments, 4 broken. The share of broken moments may be 4 to 31 percent for this stick. Another piece of the same model, another model, or the same stick on another day may differ. A USB id does not prove which chip is inside, so another stick with the same id may hold another chip.
- **The cause.** The mechanism (one sector takes the content of the write before it) is read from four cases. The test did not write to the stick from the host without the virtual machine, so a fault of the test path is not excluded.
- **Another file system.** ext4, or any file system with a journal, was not tried on the real stick. Whether such a journal repairs this fault is not measured.
- **Other operating systems.** Windows and macOS were not tried, neither with a wrong checksum in a folder entry nor with a damaged folder.
- **The long temporary name on a real stick.** The real stick was written with short temporary names only.
- **A pause shorter or longer than 1 second, or a cache flush that the stick obeys.** The stick answered its one cache-flush command with an error, so a stick that obeys it was not tried.
- **Other moments.** Each cut came 0 to 20 ms after the host let the writer begin a step. Moments later inside a step were not sampled. A cut in between, or by pulling the stick by hand, was not tried.
- **Cuts that the checker passed.** The sectors were read from the stick only for the broken cuts. A cut that the checker passed and that holds a wrong sector was not searched for. The host's file-system check is the only second view of the other cuts. The same holds for the four broken cuts: the stick was not read sector by sector, so a second wrong sector in them is not excluded.
- **Every fault the host's check saw.** The host's `fsck.exfat` check is cumulative on this stick and is not counted per cut. After the 20 cuts of try 2 it also named, for the cut at step 44, 18 ms, a file in a leftover temporary folder that shares a cluster with another file. That is the same kind of message as for the two folder cases of that try. In try 3 the count of corrupted files rose by one at the same moment; the text of its messages was not saved. The checker did not call either bundle broken and the sector was not read, so a fifth case of the same fault is possible. The cause was not examined.
- **How many runs.** The numbers of runs are in the table "What is counted". The differences between the totals and the cut counts are only uncut runs. No difference is left unexplained.
