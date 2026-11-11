---
title: The history
description: The history is the write-once record of what you did with your roots. Where to keep the bundle that holds it, how to back it up, and what must never be in it.
sidebar:
  order: 13
---

*Design phase: the layout described here is what the first version will write ([the bundle](/reference/bundle/)). The advice is ritueel's opinion; the reasons are in [record 0001](../decisions/0001-what-ritueel-is.md) and [record 0006](../decisions/0006-bundle-history-and-trust-files.md).*

Every ceremony changes what outsiders can trust, and in a year nobody remembers what was done. ritueel keeps the written memory in one **bundle**, a directory of plain files with a fixed structure, that says which roots exist, where each lives, what was signed, and when. Its write-once part is the **history**, the folder `history/`: one sub-folder for each ceremony, holding its plan, record and transcript, each naming the one before it ([ceremony files](/reference/ceremony-record/)). Nothing needs git. This page is about how to keep the bundle, because the history alone is not enough.

One bundle is one trust domain: the roots, the history and the cards of one organisation or one person. A person who also runs a company keeps two bundles, in two repositories, and backs up and restores each of them on its own.

## What is in it, and what must not be

| In the bundle | Never in the bundle |
|---|---|
| The configuration: your name, the policy, the intermediates you certify. | A private key in clear. |
| For each root: its certificate or public key, where it lives, and the evidence of where it was born. | A PIN you type, a passphrase or a token. |
| The OpenPGP creation time of each key. | A revocation certificate itself. The bundle holds only its digest. |
| One file you write, `ritueel.yaml`. | Anything you would not show an auditor. |
| The history: one record per ceremony, chained by hash. | |
| The trust files, one numbered set in `trust/<number>/` each time they change. | |
| Requests, each with its answer beside it, in `requests/<name>/`. | |
| The inventory of your cards, and the secrets ritueel made for them (management key, PUK), **sealed** to your recipients. | |
| For a person's own key, the wrapped backup of the encryption subkey. | |

The creation times matter more than they look. An OpenPGP fingerprint depends on the key's creation time, and a card does not store that time. Lose the bundle and you can lose the ability to reproduce the fingerprint of a key that is still safe on its card. That is why the bundle is part of every key's identity, and why it is backed up like a key.

The sealed files are not public. A copy that leaks is safe only as long as the keys that open them are: the unlock key and the recovery key ([record 0002](../decisions/0002-where-a-key-lives.md), [record 0003](../decisions/0003-root-cards.md)).

## Where it should live: ritueel's opinion

1. **In a git repository of its own.** ritueel needs no git, but plain files and a history are what the bundle needs, and a repository that holds nothing else is easy to back up and easy to audit.
2. **With a remote on a service you control, and a second copy elsewhere.** Two different providers, or one provider and one machine of your own. The bundle holds public material and sealed secrets, so a copy that leaks is not a compromise while your recipients' keys are safe. What you protect it against is loss, and against a quiet edit.
3. **Signed commits, and review before they land.** An attacker who can rewrite the bundle can mislead you at the next ceremony: a different root, a different expiry. A signed history and a second pair of eyes (or, for one holder, the delay of a pull request) catch it.
4. **The digest of the last record, kept apart.** The records are a hash chain. Write the latest digest somewhere that is not the repository, such as a note in the password manager. Anyone who later rewrites the history cannot reproduce it. ritueel also puts the digest into each signed root list, which anchors the chain without using the root again.
5. **Not only on the machine of the ceremony.** The offline system, where a key that can be copied is used, keeps nothing: the bundle is brought onto it on the stick, used, and taken back. Key files sit beside the bundles on the stick, never inside one ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).

## What else must be backed up, and where

The bundle is only half. The other half is what it deliberately does not hold.

| Item | Why it is kept | Where |
|---|---|---|
| **Revocation certificates** of the OpenPGP primary keys, made when each key was born, one for each of two reasons (compromised and superseded). | They are the only way to revoke a primary key whose card and PIN are gone. | Apart from the cards, in at least two places: for example printed and sealed, and in the password manager. A third place is not wasteful. |
| **The PINs you type**, one entry per card, and the passphrase of the recovery key. | Without the PIN a card is a locked box; three wrong tries block it. The PUK and the management key are made and sealed by ritueel, so you do not keep them. | The password manager, never in the bundle. |
| **The recovery key**: an age identity in a passphrase-protected file. | If all the cards named to open the file are lost as well, the key files cannot be opened without it. | Apart from the cards, and apart from its passphrase: the file and the passphrase never sit in the same place. |
| **Software keys,** if any. | A software key is a copy by nature. | In the software store you chose, whose own replication is the backup (see [where a key lives](/learn/key-stores/)). |
| **The second card.** | A card cannot be copied. | A second, independent card, in a second place. |

## Backing up a card, a cloud key and a software key

- **A card** is not backed up. You have two cards. The second root is a different key, made on a different card; it is not a copy.
- **A cloud key** is not exported. You have a replica in another Region, which the service keeps for you.
- **A software key** is as safe as its store. In an encrypted file, a backup is another copy, which is a danger as well as a safety. In a synced password manager, the sync is the backup. In the system keyring, there is none.

None of these is a backup in the sense of "a copy I can restore from". It is redundancy against loss, and per [layered trust](/learn/layered-trust/), redundancy does not answer compromise.

## Restoring, and practising it

A restore you have never practised is a hope. The restore drill is the practice:

1. Start on a clean machine with nothing but the bundle's remote and the password manager.
2. Clone the bundle, verify the hash chain, and list the roots and what expires when.
3. Compare each root with its card or cloud key: the serial, the fingerprint, the attestation.
4. Walk through the loss of one card with its revocation certificate.

It ends when every check passes, and the record says how long each step took. The drill runs on test keys first, then once on the real ones. This is planned as its own command ([the drills](/guides/)).
