---
title: Your own OpenPGP key
description: Make your own OpenPGP primary offline and a daily signing subkey on a card, bind one to the other, and keep both alive, with a drill on a test card first.
sidebar:
  order: 9
---

*Design phase: not built yet. This page is the plan that `ritueel init --kind personal` and `ritueel personal subkey add` will follow ([issue #18](https://github.com/truvity/ritueel/issues/18), M4); the record behind it, [ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/), is still `Proposed`. The files are in [Personal OpenPGP](/reference/personal-openpgp/). Read [the OpenPGP custody chain](/learn/chain-openpgp/) first for why a master key and a daily subkey are two keys.*

You want to sign commits and releases, and maybe log in, with a key that cannot be copied off your computer, and a master key you can lose a card without losing. The answer is two keys: a **master key** (the primary) that signs rarely and stays offline in an encrypted file, and a **daily subkey** that is born on a card and does the signing.

## What you start with

- A card for daily use, with an OpenPGP applet and firmware 5.7 or later. Not a root card: a root card is used for nothing else ([Prepare a root card](/guides/prepare-a-root-card/)).
- A place offline for the key directory, such as an encrypted drive, and a second one for a copy.
- Two places apart from both for the revocation files.
- Your password manager, with an entry for the master key's passphrase and one for the card's PIN.

## Steps

1. **Write `ritueel.yaml`** with `kind: personal`, your name and address, and one intermediate called `daily` ([the file](/reference/personal-openpgp/#the-directory)). Result: a directory under version control.
2. **Make the master key.** `ritueel init --kind personal --store software --backend file --key-dir DIR --revocation-dir DIR2`. ritueel asks for a passphrase, twice, without echo. Result: the master key in an encrypted file, two revocation signatures in the second directory (one for *compromised*, one for *superseded*), and a first public certificate. It tells you plainly that the master key can be copied.
3. **Store the revocation files** apart from the key directory and from each other, as in [Revoke a key](/guides/revoke-a-key/). Result: you can revoke the master key even if the key directory is lost.
4. **Make the daily subkey on the card.** `ritueel personal subkey add daily --card SERIAL`. Read the plan, type the first eight characters of its digest, type the card's PIN at the terminal, and give the master key's passphrase when asked. Result: a subkey born on the card, bound by the master key for about 13 months, with the card's attestation recorded.
5. **Use the certificate.** `gpg --import` the file in `products/`, then follow [Sign git commits and tags](/guides/openpgp-sign-git/) or [An authentication subkey for SSH](/guides/openpgp-ssh-authentication/). Result: `gpg` signs with the card.
6. **Back up.** Copy the key directory to the second drive and commit the directory. Run [the restore drill](/guides/run-a-drill/). Result: you know the copy opens.

## Every year

`ritueel yearly` binds the subkey again for another 13 months and extends the master key. `ritueel status` warns at 60, 30 and 14 days before the binding ends, and at 6 months, 3 months and 30 days before the master key does.

## How you know it worked

- `gpg --list-keys` shows the master key with the subkey, and `gpg --card-status` shows the subkey on the card.
- Unplug the card and signing fails.
- `ritueel revocation check` accepts both stored files, and `ritueel drill restore` passes.

## When something goes wrong

- **The card is lost.** Without the PIN it is locked after three tries. Use the master key to revoke the subkey and bind a new one on a new card; remove the old public key from every service that lists it ([Revoke a key](/guides/revoke-a-key/)).
- **The master key's file is lost.** Open the copy. If every copy is gone, only the stored revocation signature remains: publish it, and start again with a new key.
- **The master key is stolen.** The passphrase is all that stands in the way. Publish the *compromised* revocation signature and make a new key.

## Drill

Make a throw-away master key with `--test-root`, bind a subkey on a test card, import the certificate into a scratch `gpg` home, sign and verify a file, then revoke the subkey and see the signature fail to verify with `sqv`. Nothing real is touched.
