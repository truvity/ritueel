---
title: A YubiKey 5 Nano with firmware 5.8.0 signs about 7 times a second over PIV, and what a second program does to it (2026-11-13)
description: Time per PIV operation on a YubiKey 5 Nano (firmware 5.8.0), one operation at a time, and what a second program does to a program that holds the card.
sidebar:
  order: 12
---

## Question

How long does one operation take on a YubiKey 5 Nano in its PIV application (the smart-card part that holds keys in numbered slots)? What happens when several callers, or a second program, use the same card at the same time?

## When

Measured on 2026-10-30 and again on 2026-11-02 by the sister project [sluis](https://github.com/truvity/sluis). The figures below are restated from its public issue comments, in ritueel's terms. One older ritueel note adds a figure from 2026-10-31 and 2026-11-01. This note was written on 2026-11-13. ritueel did not repeat the sluis runs.

## Verdict

**The card is the slow part, and it works on one operation at a time.** A P-384 signature takes about 147 ms (about 7 a second). A P-256 signature takes about 80 ms. RSA-3072 takes about 0.72 s. Four callers on one card get the same total rate as one caller, and each waits about four times longer. **In these runs, a second program disturbed the holder (the program that already uses the card) only when the holder did not hold the card exclusively.** With piv-go (a Go library for PIV) the holder lost no operation in 5 of 5 runs. With ykcs11 (Yubico's PKCS#11 module) the holder lost one or two operations in 5 of 5 runs on 2026-11-02, and failed in 3 of 5 runs on 2026-10-30, where one run did not recover.

## Method

Hardware and software, as stated in the sources:

| Item | Value |
|---|---|
| Card | YubiKey 5 Nano, firmware 5.8.0. The comments do not say whether both days used the same device. |
| Host | An arm64 board with four Cortex-A55 cores and 2 GB of memory, Ubuntu 22.04. The 2026-11-02 comment adds kernel 5.10.160. The comments do not say whether both days used the same board. |
| PC/SC service | pcsc-lite 1.9.5 (PC/SC is the system service through which programs talk to a card) |
| Go | piv-go v2.6.0. The Go version is given only for 2026-11-02: 1.27.0. |
| Rust | cryptoki 0.12.1 over Yubico ykcs11 and libykpiv 2.7.3 (ykcs11 is Yubico's PKCS#11 module, a standard interface to a key store). The 2026-11-02 run used Rust 1.99.1 and the arm64 build from Yubico's package archive. |
| Key policy | PIN once per process, touch never (stated for 2026-10-30; not stated for 2026-11-02) |
| Card state | PIV in factory state before the 2026-11-02 run (default PIN, PUK and management key); reset to factory state after both runs |

**Speed run (2026-10-30).** Each cell is 200 operations in a loop through one library, unless the table says otherwise. A software verifier that was independent of both libraries checked every signature. The two ECDH results agreed with a software implementation.

**Repeat (2026-11-02).** The same programs, 20 to 100 operations per cell. The source gives one median per cell for this run and does not give the count of each cell.

**Callers on one card (2026-11-02).** Four callers, each 10 P-384 signatures. A caller is one thread (ykcs11) or one goroutine (piv-go; a goroutine is a Go thread of execution).

**A second program (2026-11-02).** A holder program signs every 200 ms for 22 s. After 5 s a second client appears. Client A is another ykcs11 process that signs three times. Client B is `ykman piv info`. Five runs for each holder. The `ykman` version is not stated.

In the tables, p50 is the median. p95 and p99 are the values that 95 and 99 percent of the operations stayed below. With 200 operations, p99 is close to the second slowest operation.

## What the setup over- and under-counts

- **The host is a slow board.** The source says the libraries add 1 to 3 ms and "the card is the cost". On a faster host the total would be a few milliseconds lower at most. This was not measured on another host.
- **The keys needed no touch and one PIN check per process.** A key with touch always, or PIN always, adds the time of the person and of the check for every signature. These runs do not measure that. The ritueel card note gives 14.6 s for a missed touch ([card libraries note](./card-libraries-and-tooling-2026-11-01.md)).
- **Every cell is one run.** The sources give no repeat of a cell on the same day, so the spread is only the p95 and p99 inside a cell. The 2026-11-02 run is a second look at the same cells, with a different count.
- **The loop does nothing else.** A real program adds its own work between signatures.

## Numbers

### Time per operation, 2026-10-30

| Operation | ykcs11 p50 / p95 / p99 (ms) | Rate | piv-go p50 / p95 / p99 (ms) | Rate |
|---|---|---|---|---|
| ECDSA P-384, slot 9c | 146.0 / 147.0 / 147.0 | 6.8 a second | 147.9 / 149.4 / 152.2 | 6.8 a second |
| ECDSA P-384, retired slot 84 | 146.8 / 147.0 / 147.2 | 6.8 a second | 148.1 / 149.2 / 150.3 | 6.8 a second |
| ECDSA P-256, slot 9a | 78.9 / 79.9 / 80.0 | 12.7 a second | 80.9 / 82.0 / 83.3 | 12.4 a second |
| ECDH P-384, slot 9d | 143.0 / 143.1 / 143.3 | 7.0 a second | 144.5 / 145.8 / 146.5 | 6.9 a second |
| X25519 ECDH, slot 83 | 82.9 / 83.1 / 83.2 | 12.1 a second | 84.0 / 85.2 / 86.1 | 11.9 a second |
| Ed25519, slot 9e, 64-byte message | 87.8 / 88.1 / 88.2 | 11.4 a second | 83.4 / 85.0 / 88.0 | 12.0 a second |
| Ed25519, 1 KiB message (20 operations) | 186.1 / 188.8 / 188.8 | 5.4 a second | not given | |
| RSA-3072 PS256, slot 82 | 715.5 / 719.9 / 723.1 | 1.4 a second | 717.9 / 723.3 / 724.8 (50 operations) | 1.4 a second |

ECDH is key agreement: the card combines its private key with a public key from outside and returns a shared secret. Ed25519 in PIV needs firmware 5.7 or newer, as the sluis record says. Ed25519 and X25519 worked on 5.8.0, with attestation (the card's signed statement about a key it made).

### Other timings

| What | Result | Date and library |
|---|---|---|
| 50 P-384 signatures in a burst | 7.3 s; p99 was p50 plus 1 ms; no drift over 200 operations | 2026-10-30; the comment does not name the library |
| First signature from a new process | 1.8 to 2.0 s with ykcs11; 0.17 s with piv-go | 2026-10-30 |
| First signature from a new process, repeat | 1.96 to 2.6 s with ykcs11; 0.11 to 0.20 s with piv-go | 2026-11-02 |
| P-384 ECDSA, p50, repeat | 145.9 ms ykcs11; 149.1 ms piv-go | 2026-11-02 |
| ECDH P-384, p50, repeat | 141.9 ms ykcs11; 144.0 ms piv-go | 2026-11-02 |
| ECDSA P-256, p50, repeat | 78.0 ms (ykcs11) | 2026-11-02 |
| X25519, p50, repeat | 82.9 ms (ykcs11) | 2026-11-02 |
| Ed25519, p50, repeat, 64 bytes / 3,061 bytes | 86.9 ms / 423.0 ms (ykcs11); 84.8 ms for 64 bytes (piv-go) | 2026-11-02 |
| RSA-3072 PS256, p50, repeat | 716.1 ms ykcs11 (digest in); 719.0 ms piv-go | 2026-11-02 |
| Key generation | RSA-3072: 56 s. EC key: 0.35 to 0.95 s. The number of runs is not given. | 2026-10-30 |

Two readings from the table. The ykcs11 start-up time is long because its first `C_OpenSession` call (the call that opens a session on the token) builds one attestation for each key on the card (8 keys in the sources); the sources do not say how long it takes with fewer keys. Ed25519 here is the pure kind, where the whole message goes to the card, and the time grows with the message: On 2026-10-30 the time grew by about 0.10 ms for each further byte between 64 and 1,024 bytes (87.8 to 186.1 ms). On 2026-11-02 it grew by about 0.11 ms for each further byte between 64 and 3,061 bytes (86.9 to 423.0 ms). These are this note's own calculations. The 3,061 bytes is the largest message that ykcs11 accepted. ECDSA signed a digest or, with the `_SHA384` mechanism, a message hashed inside the caller's process, and both took 145.9 ms.

### Several callers on one card

| Setup (2026-11-02 unless noted) | Result |
|---|---|
| P-256, 1, 2 or 4 callers (2026-10-30) | Total rate stays near 12.7 a second; each caller waits about N times 80 ms |
| ykcs11, one session per thread, 4 callers | 40 of 40 signatures; p50 146 ms; **p99 3.07 s**; 6.85 a second |
| ykcs11, 4 callers, session per caller (2026-10-30) | p99 6.0 s (algorithm not stated) |
| ykcs11, one session behind an application lock, 4 callers | 40 of 40; p99 146 ms |
| ykcs11, one shared session without a lock, 4 callers | 10 of 40 worked; 30 failed with `CKR_OPERATION_ACTIVE` |
| ykcs11, a 17th session | Refused; 16 sessions is the limit |
| piv-go, 4 goroutines on one handle | 40 of 40; p50 597 ms; p95 896 ms; maximum 903 ms; 6.68 a second |
| piv-go, 4 goroutines (2026-10-30) | p50 322 ms; the comment does not name the algorithm, and the size fits P-256 (4 times about 80 ms) |

### A second program on the card, 2026-11-02

| Holder | Client A (another ykcs11 process) | Client B (`ykman piv info`) | What the holder lost |
|---|---|---|---|
| piv-go | found no token | failed to connect | Nothing: 63 of 63 operations succeeded in 5 of 5 runs |
| ykcs11 | signed 3 of 3 | read the card | 1 or 2 operations ("not logged in") in each of 5 runs; it recovered within 0.6 s each time |

On 2026-10-30 the same test with the ykcs11 holder failed in 3 of 5 runs, first with `CKR_FUNCTION_NOT_SUPPORTED` and then with `CKR_DEVICE_REMOVED`. In one run the card was reset, and the holder stayed broken until it was started again. On 2026-11-02 no run failed that way. The failure of a ykcs11 holder therefore differs from day to day. The difference between the two libraries did not.

Client A, through ykcs11, did more than disturb the holder: it signed with the card, using the default PIN of the factory-state card. Two ykcs11 processes on one card take turns, but the turns are not fair, and a tight loop in one process starves the other.

## How to read it

These are conclusions, not measurements.

1. **Plan on the card's time.** On a P-384 key the card allows about 7 signatures a second, and a second thread or a second process does not raise it. A step that signs many things in a row, for example a certificate with three signatures, costs the sum of them. The card note measured about 450 ms for such a certificate, and about 150 ms for one P-384 signature with piv-go v2.6.0 on firmware 5.8.0 ([card libraries note](./card-libraries-and-tooling-2026-11-01.md); that note gives no count of runs). It agrees with the 148 ms measured here.
2. **One program should own the card.** In these runs, two programs that shared the card through ykcs11 disturbed each other. piv-go connects to the card exclusively (the source's word; PC/SC has an exclusive and a shared way to connect), and the second client then failed instead of breaking the first. The card note saw the same with a system OpenPGP service: `scdaemon` holding the card stopped piv-go from opening it, and the reverse, and nothing was damaged. `gpgconf --kill scdaemon` freed the card.
3. **A reset by one client affects all.** The sister project's reading is that libykpiv, after an error, reconnects with a card reset (`SCARD_RESET_CARD`), and that this resets the card for every client. The same project reports (its record 0006, "Exclusive card access", measured 2026-10-31, no counts given) that the PIN state belongs to the powered card, not to one connection. In a ceremony this means: close other card programs before the step that needs the PIN.
4. **ykcs11 does not choose a reader.** The source reports that it connects to every reader that the PC/SC service lists and has no filter by reader or serial number. No run behind this is in the comments.

The sister project built its own card driver and cache after these runs. Its figures for that driver (161 to 166 ms for P-384, 143 ms for ECDH) include its own overhead and are in [its record 0006](https://github.com/truvity/sluis/blob/c2c15f18beef908a0f6c2279326a6e126e9869e3/docs/decisions/0006-keys-and-sealing.md), sections "Keys per board", "DataKeyWrap" and "Exclusive card access".

## What this does not show

- **One card model and one firmware.** A YubiKey 5 Nano with firmware 5.8.0. No other firmware, and no other model. This note gives no figure for any firmware older than 5.8.0.
- **One host type.** An arm64 board with pcsc-lite 1.9.5. No desktop host, no Windows or macOS smart-card service, no other pcsc-lite version.
- **Touch and PIN always.** Not measured. The runs used touch never and PIN once.
- **Algorithms not run:** RSA-2048. RSA-3072 was measured with PSS padding only.
- **How many runs.** One speed run on 2026-10-30 and one repeat on 2026-11-02 with a smaller count. The second-program test has 5 runs for each holder on 2026-11-02, and 5 runs of the ykcs11 holder on 2026-10-30; the piv-go holder is not reported for 2026-10-30. The sources give no confidence interval, and a rare failure of piv-go in this test would not show in 5 runs.
- **Only signing during a second program.** Key generation, a PIN change or a management-key action while another program is on the card was not tried.
- **Other second programs.** Only a ykcs11 process, `ykman piv info` and (in the card note) `scdaemon`.
- **Raw logs.** The test programs were throwaway and are not in a repository. The sources are summaries in comments.

## Changes made

Test cards only. The card was in PIV factory state before the 2026-11-02 run and was reset to factory state after it. After the 2026-10-30 run it was reset (PIV and OpenPGP). The OpenPGP application was not touched on 2026-11-02.

## Sources

- sluis issue [#879](https://github.com/truvity/sluis/issues/879), the [comment of 2026-10-30](https://github.com/truvity/sluis/issues/879#issuecomment-6535498471).
- sluis issue [#942](https://github.com/truvity/sluis/issues/942), the comments of [2026-10-30](https://github.com/truvity/sluis/issues/942#issuecomment-6535498740) and [2026-11-02](https://github.com/truvity/sluis/issues/942#issuecomment-6572363120).
- sluis [record 0006](https://github.com/truvity/sluis/blob/c2c15f18beef908a0f6c2279326a6e126e9869e3/docs/decisions/0006-keys-and-sealing.md), "Exclusive card access" (PIN state belongs to the card).
- ritueel [card libraries and tooling (2026-11-01)](./card-libraries-and-tooling-2026-11-01.md).
- For the PC/SC sharing modes: the [pcsc-lite API documentation](https://pcsclite.apdu.fr/api/group__API.html).
