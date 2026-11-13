---
title: Of the partitions added to an AirgapOS 2026.07.0 stick only FAT32 is mounted, and writing the image again drops the new table entry (2026-11-13)
description: A session runs as root, added partitions get device nodes, only FAT32 is mounted by itself, and writing the image again loses the new table entry.
sidebar:
  order: 16
---

## Question

A person wants to carry data or a program on the same USB stick as the offline system AirgapOS. What does the stock image do with partitions added behind it, and what does the added table entry change?

Some terms, used the same way throughout. The **ISO** is the image file `airgap.iso` that is written to the stick. A **device node** is a file under `/dev` that stands for a disk or a partition, for example `/dev/sda1`. **Sector 0** is the first 512 bytes of a disk. The **MBR** is the classic partition table in sector 0. It has 4 entries. The **GPT** is a newer partition table that sits after sector 0. A **protective entry** is an entry of type 0xEE in sector 0 that marks a disk as GPT. One MBR entry can be an **extended partition**, a container that holds more partitions, called **logical partitions**. A **flush command** is the command (SCSI SYNCHRONIZE CACHE) that asks a stick to write its cache out.

## When

2026-11-13.

## Verdict

**The stock image gives a device node to every added partition and leaves it alone, except a FAT32 partition, which it mounts.** A session runs as root and can open the node of a partition. The partition table of the image has one free entry. So a second and a third partition must be logical partitions inside one extended partition, if the three entries of the image stay. Writing the image again removes the new entry, and the data behind the image stays. The documented check of the first bytes of the media no longer matches once the entry exists.

## What was tested

- AirgapOS 2026.07.0, commit `6b9a6555db9de10b7fd510d1940d6edf11c005f8` on the branch `main` of `https://git.distrust.co/public/airgap` (the repository has no tag for this release). The file `dist/airgap.iso` has 335,884,288 bytes and the SHA-256 `203b8e09ecc5faa957dad2d1aaa19cc3f513617e7e0d8dda72d6947b621ad1f1`, equal to `dist/manifest.txt`. The signatures of the release were not checked.
- Kernel `7.0.0airgap`; the block-layer source of Linux tag v7.0.
- A virtual machine (VM): QEMU 10.2.1 with KVM, 2 GB of memory, no network, the image on a virtual USB disk, BIOS boot.
- Image files made with `sfdisk` (util-linux 2.41.3) and changed with GNU `dd` 9.7.

A label in the last column says how a row is known: **read** (in a source file), **VM** (measured in the virtual machine) or **file** (measured on an image file, no VM).

## Numbers

| # | Question | What was found | Label |
|---|---|---|---|
| 1 | Which user runs a session? | root. `/etc/inittab` starts `bash` on the serial line and `tmux` on the console, with no login (lines 26 and 27). `id` printed `uid=0(root)`. The prompt shows `$` although the user is root; the cause was not checked, so use `id -u`. | read, VM |
| 2 | Can a program open a partition's node? | Yes, as root. The nodes have mode `brw-rw---- root root`. A read and a write of 512 bytes with `dd` and the flags `iflag=direct` and `oflag=direct` worked on a raw partition, and the write read back equal. Whether `dd` of this image really used direct I/O is not known (see the bullet about the 1-byte write in "What this does not show"). A write past the end of the partition stopped at the end (`No space left on device`, 1 of 2 blocks written). Another user was not tried: `su` in the image failed. | VM |
| 3 | Is the root file system in memory? | Yes. README line 25: "Immutable and Diskless: runs from initramfs". In the VM the first mount is `rootfs / rootfs rw`. | read, VM |
| 4 | What is the partition table of the image? | Kind `dos` (MBR) with 3 of 4 entries used: type 0x00 (the ISO, bootable), 0xEF (EFI, 2880 sectors from sector 140), 0x0B (FAT32 `USER`, 10 MiB from sector 634880). **Entry 4 is free.** The image also holds a GPT with room for 248 entries and 3 used. The MBR has no protective entry. | file |
| 5 | Which table does the kernel read? | The MBR. The GPT counts only if sector 0 holds a protective entry (`block/partitions/efi.c`, lines 140 to 151 and 596 to 607). The boot log listed `sda: sda1 sda2 sda3 sda4 < sda5 sda6 sda7 sda8 >`. | read, VM |
| 6 | Why logical partitions? | The MBR holds 4 entries and 3 are used. The free entry becomes an extended partition (type 0x0F), and the other partitions sit inside it as logical partitions. | VM |
| 7 | Which nodes appear? | One per partition: `/dev/sda5` to `/dev/sda8` for four logical partitions, and `/dev/sda4` for the extended partition (1 KiB). The name `sda` is that of the VM. | VM |
| 8 | What mounts by itself? | The rule file `sdcard-autorun.rules` handles `sd[a-z][0-9]` and sets mount options for `vfat` only (line 9). In the VM the added FAT32 partition (type 0x0C) was mounted under `/media` (`rw,nosuid,nodev,noexec`). The exFAT (0x07), ext4 (0x83) and raw (0xDA) partitions were not; the rule made an empty folder under `/media` for each. The cause was not checked. | read, VM |
| 9 | What does writing the image again do? | `dd` of the ISO writes its first 335,884,288 bytes. Sector 0 is replaced, so entry 4 is gone. Nothing else changed (10 bytes differ, all in entry 4). The data behind the ISO stays, but the kernel no longer lists the partitions: booting the rewritten image gave `sda: sda1 sda2 sda3`. | file, VM |
| 10 | How is the entry put back? | Writing only the extended entry with `sfdisk --append` blanked the header of the first logical partition (sector 659456 here), and the logical partitions did not appear. Writing all the lines again, or copying back the 16 bytes of entry 4 (offsets 494 to 509), gave an image equal to the one before. Only `sfdisk` 2.41.3 on one image was tried. | file |
| 11 | Does `dd` write past the ISO? | With `bs=1M conv=sync` (README line 72) the last block is padded. 336,592,896 bytes are written, so 1,384 sectors after the ISO are overwritten (a marker at sector 657000 was erased, one at 657500 was not). With `bs=4M conv=fsync` ([the Distrust guide](https://trove.distrust.co/generated-documents/level-1/provision-airgapos.html)) nothing is written past the ISO. | file |
| 12 | Does the published check still match? | No. README line 78 compares `head -c <ISO size> /dev/sda \| sha256sum` with the ISO. With entry 4 present the digests differ. | read, file |
| 13 | What would a check that leaves entry 4 out compare? | Bytes 0 to 493 and 510 to the end of the ISO. It gave one digest for the ISO and for three images with an added entry, and another digest when one byte changed in entry 1, in entry 3 or elsewhere. | file |
| 14 | Does the image still boot? | An earlier test booted it in BIOS and UEFI (QEMU) with one extra primary ext4 partition; the bytes after sector 0 were unchanged after three boots. README line 144: Secure Boot must be off. Not repeated here; no public record. | VM |
| 15 | Can the disk identifier tell two sticks apart? | No. `sfdisk -d` prints `label-id: 0xc8e0e6ee` for the ISO and for 16 image files made from it, with and without added partitions. The identifier is stored in sector 0 (bytes 440 to 443). Writing the ISO writes it again, so every stick written from this image carries the same identifier. | file |

## What a real stick showed

No real computer booted AirgapOS. A real cheap 32 GB stick, with one exFAT partition and no AirgapOS on it, was passed to the AirgapOS VM as a second USB disk.

| What | Result | Label |
|---|---|---|
| Cache type | For the real stick the kernel in the guest printed `No Caching mode page found` and `Assuming drive cache: write through`. The virtual USB disk of the image tests reports `write back`. | VM |
| Flush | After a command in the guest set the kernel's cache type of the stick to `write back`, the first flush command was answered with an error (SCSI sense key 0x5, additional sense code 0x24), and the write that needed it failed. | VM |
| A program on the partition | A small static test program started from the exFAT partition in each of the 3 tries in which the write step worked. In the fourth try the write step failed at the flush, and the program was not tried. The test mounted the partition with `mount -t exfat`; the options had no `noexec`. | VM |

The same stick is the subject of [a cut during a write on a real USB stick](./usb-stick-cut-during-a-write-2026-11-13.md).

## How to repeat

`/dev/sdX` is an example. Work on image files first.

- **Rows 4, 12, 13, 15.** `sfdisk -d airgap.iso`. Check without entry 4: `{ head -c 494 X; tail -c +511 X | head -c $((N-510)); } | sha256sum`, with `X` the stick `/dev/sdX` or a file and `N` the ISO size. The digests of the ISO and of the stick must be equal.
- **Rows 6 to 11.** Copy the ISO to `stick.img` and run `truncate -s 520M stick.img`. Run `sfdisk --append stick.img` with the lines `start=659456, type=f`, `start=661504, size=131072, type=da` and `start=794624, type=7`. Rewrite with `dd if=airgap.iso of=stick.img bs=4M conv=fsync,notrunc` and compare with `cmp -l`. On a device, name it `/dev/sdX` and leave out `notrunc`. Not tried on a device.
- **Rows 2, 7 and 8** were measured with four logical partitions of 48 MiB each: raw (type da, a marker text in its first sector), exFAT (type 7), FAT32 (type c) and ext4 (type 83), the last three made with `mkfs`. The three lines above make two partitions with no file system.
- **Rows 1 to 3, 5, 7, 8.** Boot the file: `qemu-system-x86_64 -enable-kvm -m 2048 -nic none -display none -serial stdio -drive if=none,id=s,format=raw,file=stick.img -device qemu-xhci -device usb-storage,drive=s,bootindex=0`. A shell is on the serial line. Run `id`, `cat /proc/partitions`, `lsblk -o NAME,FSTYPE,PARTTYPE,MOUNTPOINT`, `cat /proc/mounts`, `ls /media`, and for row 2 `dd if=/dev/sda5 bs=512 count=1 iflag=direct`.

## What this does not show

- One image version, one kernel, mostly one VM. No real computer booted the added layout, so device names and the user on real hardware are not measured.
- No desktop system (Windows, macOS, a Linux desktop) was tried with the layout.
- A GPT layout was not tried.
- Why exFAT and ext4 are not mounted was not checked. For each mounted folder, `/usr/local/bin/autorun` (called by line 11 of the rule file) runs `autorun.sh` in two cases. For `/media/USER`, it runs if the partition is mounted read-only (lines 7 to 16). For any other folder, it runs if `gpg --verify` of `autorun.sh.asc` succeeds (lines 17 to 27). This was read, not tried. Which keys the `gpg` of the image trusts was not checked.
- The image's `dd` accepted a 1-byte direct write, while the kernel source (`block/fops.c`, lines 39 to 44) refuses writes that are not a multiple of the block size. Not explained. So the word "direct" in row 2 is not proven.
- A real loss of power, and a stick pulled while a program runs from it, were not tried.

## What this decides

It decides nothing. It gives facts for [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rules 29, 31, 33 and 36, and for [the trace area page](../reference/trace-area.md). These are facts about a stick with added partitions, not a review of AirgapOS.

Row 10 is the measured reason for a correction of that page. The page said that writing entry 4 again with the same start, or "the first line alone", brings the partitions back. With `sfdisk` 2.41.3 on an image file, adding only the extended line blanks the header of the first logical partition (the extended boot record at sector 659456), and the partitions do not appear. Copying the 16 bytes of entry 4 back, or writing all three lines again, restores an equal image. Another tool was not tried.
