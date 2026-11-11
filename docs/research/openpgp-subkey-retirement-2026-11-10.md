---
title: Retiring an OpenPGP subkey (2026-11-10)
description: What gpgv, sqv and git verify-tag do with signatures from a subkey that was revoked as superseded, as compromised, or has expired. Measured on test keys.
sidebar:
  order: 7
---

## Question

A subkey that is replaced has to end. What do the verifiers that people have do with the signatures that subkey made, when it ends by a revocation with the reason "superseded", by a revocation with the reason "compromised", or by expiry?

## When

2026-11-10. The time of day was not recorded.

## Verdict

**A "superseded" revocation keeps the old signatures valid in `sqv` and in `gpgv`; a "compromised" revocation does not in `sqv`; and `git verify-tag` fails for a revoked and for an expired key alike.**

- After a revocation with the reason "superseded", `sqv` accepts signatures dated before the revocation and rejects later ones. `gpgv` accepts all of them.
- After a revocation with the reason "compromised", `sqv` rejects all signatures, before and after.
- After expiry, `sqv` and `gpgv` accept signatures made before it.
- `git verify-tag` fails for a revoked key and for an expired key alike.

So a replaced subkey is retired by a "superseded" revocation dated on the day of the switch, or by expiry; "compromised" is for compromise only. [record 0008](../decisions/0008-a-persons-own-key.md) (earlier ADR 0017) decides that.

## Method

Throwaway P-384 keys, made for this test. The signatures of a subkey that had been revoked or had expired were checked with each tool below. The commands of the run, and how the revocation reason and the signature dates were set, were not saved, so someone else cannot repeat the run from this page yet. A rerun with the commands saved is a follow-up, and it also fixes the time of day, in UTC.

| Tool | Version |
|---|---|
| GnuPG (`gpg` and `gpgv`) | 2.4.7 |
| `sqv` (Sequoia) | 1.3.0 |
| git | 2.47.3 |

## What the setup over- and under-counts

- Two verifiers and git only. apt and rpm were not tried, so the table says nothing about how a package manager reacts.
- `sqv` 1.3.0 is not the 1.5.0 of the [verifier matrix](/research/openpgp-verifier-matrix-2026-11/), so a newer `sqv` may differ.
- The result for `gpgv` after a "compromised" revocation was not recorded.
- Throwaway keys have no history of certifications, so the run says nothing about a key that others have certified.

## Numbers

What each verifier did with a signature, for each way the subkey ended.

| The subkey ended by | Signature dated | `sqv` 1.3.0 | `gpgv` 2.4.7 |
|---|---|---|---|
| Revocation, reason "superseded" | before the revocation | accepts | accepts |
| Revocation, reason "superseded" | after the revocation | rejects | accepts |
| Revocation, reason "compromised" | before or after | rejects | not recorded |
| Expiry | before the expiry | accepts | accepts |
| Expiry | after the expiry | not recorded | not recorded |

`git verify-tag` (git 2.47.3) failed for a tag signed by a revoked key and for a tag signed by an expired key. The reason of the revocation and the date of the signature were not recorded for git.

Consistent with the [verifier matrix](/research/openpgp-verifier-matrix-2026-11/): there `gpgv` also ignored a revocation, and `sqv` rejected a soft-reason revocation for later signatures only.

## Roads not taken

- **apt and rpm.** Not tried. They are the consumers that matter for release keys; [issue #25](https://github.com/truvity/ritueel/issues/25) covers them.
- **A key that others have certified.** Not tried; the keys were made for the run.

## Open questions

None for the decision. The gaps in the table (`gpgv` after "compromised", both verifiers after expiry for later signatures, `sqv` 1.5.0) are for a later run and do not change what [record 0008](../decisions/0008-a-persons-own-key.md) (earlier ADR 0017) decides.

## Changes made

Throwaway test keys only.

## Raw logs

Not published. The table above is the record of the run.
