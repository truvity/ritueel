---
title: Re-sign
description: Re-signing gives the same key a new validity, once a year. Why it is cheap, why it is done on a schedule, and how it differs from rotating a key.
sidebar:
  order: 15
---

*The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

**Re-signing is the ordinary yearly ritual.** The key stays the same. Its authority is signed again with a later end date.

## What happens

| Chain | What is re-signed |
|---|---|
| X.509 intermediate | A new certificate over the same public key and the same subject, with a new validity. |
| X.509 root | The root certificate is issued again over the same key and subject, extended by about three years. |
| OpenPGP subkey | A new binding signature from the primary key, with a later expiry. |
| OpenPGP primary key | A new self-signature that moves its expiry. |

With GnuPG, `gpg --quick-set-expire <fingerprint> <expiry> [subkeys]` moves the expiry; it needs the primary secret key, which is why it is a ceremony.

Nothing that holds the key has to change. The intermediate keeps its private key where it lives; only a new certificate arrives. Anyone who pinned the public key still has the right pin.

## Why every year

Short validity is a safety feature. A key whose authority lasts 13 months and then ends unless somebody renews it cleans up after itself: a lost or forgotten key ages out. The yearly ceremony also keeps the people and the tool practised, so the day you need the root urgently is not the first time you have touched it in three years.

The overlap is built in. A certificate that lasts about 13 months, renewed each year, means two certificates are valid for about a month, so there is no cliff on a particular day.

## The rule

> **Re-sign yearly. Rotate on an event; a key in software also after at most three years.** ([principle 3](/principles/))

If nothing has gone wrong, no advisory touches the key, and a key in software is not three years old, re-signing is the right ritual. See [rotate](/learn/rotate/) for the other case.

## What can go wrong

- **It is forgotten.** The certificate expires and the service stops. The answer is to be warned well before: a tool that reports what expires when, with enough notice to run the ceremony.
- **The wrong key is re-signed.** If the request is not checked, you extend the authority of a key you should have retired. A ceremony shows the key's fingerprint and where it lives before the touch.
- **It is used to paper over a compromise.** Re-signing extends trust in a key. If the key may be stolen, re-signing it is the opposite of what you want.

## What may run unattended

A renewal changes nothing about who is trusted, which is why it can be automated where the key store allows it ([principle 7](/principles/)). The test that separates the routine from the decisions: **if every byte the root will sign is fixed by the bundle and the clock, it is routine; if any byte names a key, a subject or a constraint the bundle does not already hold, a person decides.**

| Act | Card roots | Cloud root | Why |
|---|---|---|---|
| Make a root; add, retire or revoke one | Ceremony | Ceremony: the ceremony role and the typed plan digest | It changes who is trusted ([root transitions](/reference/transitions/)). |
| Certify a new intermediate key, bind a new subkey, list a new SSH CA key | Ceremony | Ceremony | A person compares the fingerprint and the evidence of a key nobody has seen before. |
| Re-sign the same intermediate key or subkey binding, within its profile, before it expires | Ceremony: the PIN and the touch are physical. `status` reminds at 60, 30 and 14 days. | Ceremony now; unattended under a declared renewal policy, run by the operator's scheduler, later (M7) | Every byte is fixed by the bundle and the clock. |
| Re-sign the root list, the SSH CA key list or a CRL with the same content, and rebuild the CA bundle | Ceremony | Ceremony now; unattended later (M7), as above | The same: a new validity and the next trust sequence. |
| Extend the root's own certificate and primary over the same keys | Ceremony | Ceremony now; unattended later (M7), as above | The same. |
| Revoke an intermediate or a subkey | Ceremony | Ceremony | A revocation is a decision. |
| Issue a leaf certificate, or an SSH user or host certificate | Never | Never | ritueel holds no online key ([record 0001](../decisions/0001-what-ritueel-is.md)). |

A cloud root's renewal will run (later, M7) under a second role that can sign only what the bundle already holds, so it can extend trust but never create it ([The cloud root](/reference/kms-root/#renewal-under-a-policy)). A card root cannot be left to a machine: its PIN and touch are the protection, so its holder comes once a year, and the long warning is what keeps that from being forgotten.

## In ritueel

There is no `yearly` command: renewals are separate actions. `ritueel due` writes the plan for what is due, which re-signs every registered intermediate with the root of the year, extends that root, and writes the next trust sequence, and `ritueel run PLAN` executes it after you type the first eight characters of its digest. It is planned for M2. For a cloud root, `ritueel renew` does the same unattended under a declared policy, planned for later (M7). The steps and a drill are in the [guide](/guides/re-sign-yearly/), and the details of validity and extension are in [the command line](/tools/cli/#root-validity-and-its-extension).
