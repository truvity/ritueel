---
title: Re-sign
description: Re-signing gives the same key a new validity, once a year. Why it is cheap, why it is done on a schedule, and how it differs from rotating a key.
sidebar:
  order: 15
---

**Re-signing is the ordinary yearly ritual.** The key stays the same. Its authority is signed again with a later end date.

## What happens

| Chain | What is re-signed |
|---|---|
| X.509 intermediate | A new certificate over the same public key and the same subject, with a new validity. |
| X.509 root | The root certificate is issued again over the same key and subject, extended by about three years. |
| OpenPGP subkey | A new binding signature from the master key, with a later expiry. |
| OpenPGP master key | A new self-signature that moves its expiry. |

With GnuPG, `gpg --quick-set-expire <fingerprint> <expiry> [subkeys]` moves the expiry; it needs the master secret key, which is why it is a ceremony.

Nothing that holds the key has to change. The intermediate keeps its private key where it lives; only a new certificate arrives. Anyone who pinned the public key still has the right pin.

## Why every year

Short validity is a safety feature. A key whose authority lasts 13 months and then ends unless somebody renews it cleans up after itself: a lost or forgotten key ages out. The yearly ceremony also keeps the people and the tool practised, so the day you need the root urgently is not the first time you have touched it in three years.

The overlap is built in. A certificate that lasts about 13 months, renewed each year, means two certificates are valid for about a month, so there is no cliff on a particular day.

## The rule

> **Re-sign yearly. Rotate on an event, or after at most three years.** ([principle 3](/principles/))

If nothing has gone wrong and the key is not three years old, re-signing is the right ritual. See [rotate](/learn/rotate/) for the other case.

## What can go wrong

- **It is forgotten.** The certificate expires and the service stops. The answer is to be warned well before: a tool that reports what expires when, with enough notice to run the ceremony.
- **The wrong key is re-signed.** If the request is not checked, you extend the authority of a key you should have retired. A ceremony shows the key's fingerprint and where it lives before the touch.
- **It is used to paper over a compromise.** Re-signing extends trust in a key. If the key may be stolen, re-signing it is the opposite of what you want.

## In ritueel

The `yearly` command re-signs every registered intermediate with the root of the year, extends that root, and publishes the next trust sequence. It is planned for M2. The steps and a drill are in the [guide](/guides/re-sign-yearly/), and the details of validity and extension are in [the command line](/tools/cli/#root-validity-and-its-extension).
