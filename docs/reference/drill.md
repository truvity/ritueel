---
title: Drills and the restore check
description: What a ritueel drill is, the restore check and its steps and report, the drill scripts that run in CI on test keys, and how often a drill is due.
sidebar:
  order: 13
---

*Not built yet. This is the page that [ADR 0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/#drills) leaves for the command, the report and the scripts; the code is [issue #68](https://github.com/truvity/ritueel/issues/68) for the restore check and [issue #20](https://github.com/truvity/ritueel/issues/20) for the scripts, in M3. The ideas are taught in [The ledger](/learn/the-ledger/) and the guides [Back up and restore](/guides/back-up-and-restore/) and [Run a drill](/guides/run-a-drill/).*

A restore you have never practised is a hope. A drill is a practice run with a known start and a known end, on test keys, so that the first real run is not the first run. There are two kinds: a **check** that reads the real state and signs nothing, and a **walk-through** that runs ceremonies on test roots.

## The restore check

```sh
ritueel drill restore [--dir DIR] [--expect-last DIGEST] [--allowed-signers FILE] [--revocation-dir DIR] [--accept-not-run CHECK]... [--output json]
```

Run it on a clean machine with the ledger cloned. It signs nothing, writes only its report, needs no person, and prints no certificate, key or PIN.

| # | Check | Passes when | Cannot run when |
|---|---|---|---|
| 1 | The records | `records verify` passes: the hash chain is whole. | never |
| 2 | The last digest | The newest record's digest equals `--expect-last`, the note the holder kept apart ([The ledger](/learn/the-ledger/)). | `--expect-last` is not given |
| 3 | The signed commits | Every commit of the ledger verifies against `--allowed-signers` (the holder's own signers file; `git verify-commit` does the check). | `--allowed-signers` is not given |
| 4 | The roots and what expires | `status` lists the roots, the root list, the CRLs and the SSH CA key list, with nothing critical and no unresolved attempt. | never |
| 5 | Each root against its holder | For a card: the serial is the registry's, the keys have the recorded fingerprints, and the attestation chain verifies again. For a KMS root: [the checks](/reference/kms-root/#the-checks) read the key, its policy and its replica from the service. | the card is not connected; the credentials are not available; the root is in software |
| 6 | The revocation signatures | For every root and every reason in the ledger, a file in `--revocation-dir` passes `revocation check` and has the ledger's digest. A missing file fails; it is not skipped. | `--revocation-dir` is not given |
| 7 | The trust products | The newest root list verifies, is not expired, and names exactly the active roots; the bundle, the CRLs and the SSH CA key list agree with it. | never |

A check that cannot run is reported `not-run`, never `passed` ([principle 4](/principles/)). **The drill exits 0 only when every check ran and passed.** It exits 3 if one failed or did not run; `--accept-not-run CHECK` (by number) lets one pass that the holder knows cannot run on this machine, as in CI with software roots, and the report says it was accepted.

### The report

`drills/<time>-restore.json`, one canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)); `<time>` is `YYYYMMDDThhmmssZ`. It is not part of the hash chain and not a ceremony record: a drill signs nothing. The holder commits it to the ledger.

| Member | Meaning |
|---|---|
| `version`, `kind` | `1`, and `restore` (a walk-through writes its own kind, below). |
| `started_at`, `finished_at` | UTC. |
| `ritueel` | The version and the commit of the tool. |
| `steps` | One object for each check: `{ "n", "name", "result", "started_at", "duration_ms", "reasons", "accepted" }`. `result` is `passed`, `failed` or `not-run`; `reasons` are the codes of the check; `accepted` is true for a `not-run` the holder accepted. |
| `outcome` | `passed`, `failed` or `incomplete` (nothing failed, something did not run and was not accepted). |

The report holds no secret, no revocation signature and no path.

## Walk-throughs

A walk-through is a guide that can also be run as a script. It lives in the ritueel repository under `drills/<name>/` with three files that call only public commands:

| File | Does |
|---|---|
| `setup.sh` | Makes the starting state on test keys: a scratch directory, `ritueel.yaml`, test roots, and the intermediates the drill needs. |
| `run.sh` | Runs the steps of the guide. With `--cards` it pauses at each prompt and each touch, on test cards named in the environment by serial. |
| `check.sh` | Checks the end state, and writes `drills/<time>-<name>.json` with the duration of every ceremony, taken from the `started_at` and `finished_at` of the records. |

The drills, in the order they are built: the lost-card drill (two roots and an intermediate, a card out of use, `root revoke`, `root add`, a `yearly` re-certification), a routine yearly renewal, an expiring root with an overlap, a stale root list, the adoption drill ([issue #48](https://github.com/truvity/ritueel/issues/48)), and one for each transition guide ([issue #19](https://github.com/truvity/ritueel/issues/19)).

- **CI runs every drill with test roots** (`--test-root`) and fails when a drill's check fails. The restore check runs there with `--accept-not-run 5` and `--accept-not-run 3`, because a software root has no holder to compare and the CI ledger has no signer.
- **A drill never needs a real key or a real account.** The scripts use test roots, or test cards chosen by serial from the environment; a card whose registry row is not in the drill's own directory is refused.
- **A drill on test cards runs once**, by the holder, and its report says how long each step took.

## When it is due

Once a year, with the yearly ceremony, and after any change to where the ledger or the revocation signatures live. `status` raises a notice (exit code 10, kind `drill`) when the newest restore report is older than 13 months, or when there is none and a yearly ceremony has been recorded. The yearly rhythm is ritueel's own policy, chosen to match the yearly ceremony.

## Follow-ups

- The restore check and its report ([issue #68](https://github.com/truvity/ritueel/issues/68)).
- The drill scripts and the CI job ([issue #20](https://github.com/truvity/ritueel/issues/20)).
