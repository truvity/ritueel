---
title: Your own OpenPGP key
description: Make your own OpenPGP primary offline and a daily signing subkey on a card, bind one to the other, and keep both alive, with a drill on a rehearsal card first.
sidebar:
  order: 9
---

*Design phase: not built yet. This page is the plan that `ritueel new` and `ritueel apply` will follow ([issue #18](https://github.com/truvity/ritueel/issues/18), M3 for stage one); the record behind it, [record 0008](../decisions/0008-a-persons-own-key.md), is `Accepted`: a signing subkey and an authentication subkey on each day-to-day card, an encryption subkey made in software, and a software primary replaced at most every three years. This page describes the signing subkey and gains the rest with [issue #18](https://github.com/truvity/ritueel/issues/18). The files are in [Personal OpenPGP](/reference/personal-openpgp/). Read [the OpenPGP custody chain](/learn/chain-openpgp/) first for why a primary key and a daily subkey are two keys.*

You want to sign commits and releases, and maybe log in, with a key that cannot be copied off your computer, and a primary key you can lose a card without losing. The answer is two keys: a **primary key** that signs rarely and stays offline in an encrypted file, and a **daily subkey** that is born on a card and does the signing.

## What you start with

- A card for daily use, with an OpenPGP applet and firmware 5.7 or later. Not a root card: a root card holds only root keys ([Prepare a root card](/guides/prepare-a-root-card/)).
- A place offline for the key directory, such as an encrypted drive, and a second one for a copy.
- Two places apart from both for the revocation files.
- Your password manager, with an entry for the card's PIN and, if you have no root cards, one for the key file's passphrase.

## Steps

1. **Make the bundle.** Run `ritueel new --template personal DIR` (the template name is proposed); it writes `kind: personal`. Then run `ritueel want`: set your name and address, and write one delegation called `daily` ([the file](/reference/personal-openpgp/#the-bundle)). Result: a bundle under version control.
2. **Make the primary key.** `ritueel init --kind personal --store software --backend file --key-dir DIR --revocation-dir DIR2`. The key file is opened as [record 0002](../decisions/0002-where-a-key-lives.md) says; a passkey on each root card is the default way (decided, not yet proven on a card: milestone M1); with no root cards, ritueel asks for a passphrase, twice, without echo. Result: the primary key in an encrypted file, two revocation signatures in the second directory (one for *compromised*, one for *superseded*), and a first public certificate. It tells you plainly that the primary key can be copied. A key file is opened only in the offline system, except for a test root ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 17).
3. **Store the revocation files** apart from the key directory and from each other, as in [Revoke a key](/guides/revoke-a-key/). Result: you can revoke the primary key even if the key directory is lost.
4. **Make the daily subkey on the card.** Write the wanted card file of your daily card with `ritueel want`, name that card in the delegation `daily`, then run `ritueel apply`. Read the plan, type the first eight characters of its digest, type the card's PIN at the terminal, and open the key file as in step 2. Result: a subkey born on the card, bound by the primary key for about 13 months, with the card's attestation recorded.
5. **Use the certificate.** `gpg --import` the certificate file of the newest trust set, then follow [Sign git commits and tags](/guides/openpgp-sign-git/) or [An authentication subkey for SSH](/guides/openpgp-ssh-authentication/). Result: `gpg` signs with the card.
6. **Back up.** Copy the key directory to the second drive and commit the bundle. Run [the restore drill](/guides/run-a-drill/). Result: you know the copy opens.

## If you already have a primary

Planned for stage one (M3): an existing primary may be adopted as it is, with its history, as a software key in a key file. It is marked adopted, may be RSA-4096 and without expiry on arrival, gets an expiry at adoption, and is replaced within three years of adoption or moved to stage two, where card-born primaries replace it ([record 0008](../decisions/0008-a-persons-own-key.md), rule 5).

## Day-to-day subkeys

Planned: a signing subkey and an authentication subkey are born on each day-to-day card, one set per card. An encryption subkey is made in software and loaded onto each card, with a wrapped backup in the bundle, so that a lost card does not lose the mail it decrypted. The touch setting of each key is your choice; what each choice costs is written here when stage one is built ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Every year

`ritueel apply` renews what is due: it binds the subkey again for another 13 months and extends the primary key. `ritueel status` warns at 60, 30 and 14 days before the binding ends, and at 6 months, 3 months and 30 days before the primary key does.

## Change your name or address

Adding a new user ID and retiring the old one is a ceremony, not a new key: the primary certifies the new user ID, and the old one gets a revocation that says it is no longer valid. Your fingerprint and everyone's trust in it stay. Planned for M3; the wanted file of the user IDs is proposed ([issue #18](https://github.com/truvity/ritueel/issues/18)). You edit the wanted user IDs and run `ritueel apply`; it writes the plan, and you type the first eight characters of its digest. A user ID you published cannot be withdrawn; see [After a ceremony](/guides/after-a-ceremony/).

## How you know it worked

- `gpg --list-keys` shows the primary key with the subkey, and `gpg --card-status` shows the subkey on the card.
- Unplug the card and signing fails.
- `ritueel check material FILE` accepts each of the two stored files, and `ritueel check restore` passes.

## When something goes wrong

- **The card is lost.** Without the PIN it is locked after three tries. Use the primary key to revoke the subkey and bind a new one on a new card; remove the old public key from every service that lists it ([Revoke a key](/guides/revoke-a-key/)).
- **You replace a subkey that is safe.** Retire it with a revocation for the reason "superseded", dated on the day of the switch, or let it expire; use "compromised" only for compromise. Keep the old key in your keyring: `git verify-tag` fails for a revoked and for an expired key alike (measured 2026-11-10, [the measurements](/research/openpgp-subkey-retirement-2026-11-10/)). How to check old tags is not yet measured.
- **The primary key's file is lost.** Open the copy. If every copy is gone, only the stored revocation signature remains: publish it, and start again with a new key.
- **The primary key is stolen.** The passphrase is all that stands in the way. Publish the *compromised* revocation signature and make a new key.

## Drill

Make a throw-away bundle with `ritueel new --test-root`, make its primary with `ritueel apply`, bind a subkey on a rehearsal card, import the certificate into a scratch `gpg` home, sign and verify a file, then revoke the subkey with the reason "compromised" and see the signature fail to verify with `sqv` (a "superseded" revocation fails only the signatures dated after it). Nothing real is touched.
