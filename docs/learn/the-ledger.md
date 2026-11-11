---
title: The ledger
description: The ledger is the write-once record of what you did with your roots. Where to keep the directory that holds it, how to back it up, and what must never be in it.
sidebar:
  order: 13
---

*Design phase: the layout described here is what the first version will write ([the directory](/reference/bundle/)). The advice is ritueel's opinion; the reasons are in [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/).*

Every ceremony changes what outsiders can trust, and in a year nobody remembers what was done. ritueel keeps the written memory in one **directory** of plain files that says which roots exist, where each lives, what was signed, and when. Its write-once part is the **ledger**: one sub-folder for each ceremony, holding its plan, record and transcript, each naming the one before it ([ceremony files](/reference/ceremony-record/)). Nothing needs git. This page is about how to keep the directory, because the ledger alone is not enough.

## What is in it, and what must not be

| In the directory | Never in the directory |
|---|---|
| The configuration: your name, the policy, the intermediates you certify. | A private key in clear. |
| For each root: its certificate or public key, where it lives, and the evidence of where it was born. | A PIN you type, a passphrase or a token. |
| The OpenPGP creation time of each key. | A revocation certificate itself. The directory holds only its digest. |
| Requests and answers: what an intermediate asked for, what it got. | Anything you would not show an auditor. |
| The ledger: one record per ceremony, chained by hash, and the trust products published. | |
| The inventory of your cards, and the secrets ritueel made for them (management key, PUK), **sealed** to your recipients. | |
| For a person's own key, the wrapped backup of the encryption subkey. | |

The creation times matter more than they look. An OpenPGP fingerprint depends on the key's creation time, and a card does not store that time. Lose the directory and you can lose the ability to reproduce the fingerprint of a key that is still safe on its card. That is why the directory is part of every key's identity, and why it is backed up like a key.

The sealed files are not public. A copy that leaks is safe only as long as the keys that open them are: the unlock key and the recovery key ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/)).

## Where it should live: ritueel's opinion

1. **In a git repository of its own.** ritueel needs no git, but plain files and a history are what the directory needs, and a repository that holds nothing else is easy to back up and easy to audit.
2. **With a remote on a service you control, and a second copy elsewhere.** Two different providers, or one provider and one machine of your own. The directory holds public material and sealed secrets, so a copy that leaks is not a compromise while your recipients' keys are safe. What you protect it against is loss, and against a quiet edit.
3. **Signed commits, and review before they land.** An attacker who can rewrite the directory can mislead you at the next ceremony: a different root, a different expiry. A signed history and a second pair of eyes (or, for one holder, the delay of a pull request) catch it.
4. **The digest of the last record, kept apart.** The records are a hash chain. Write the latest digest somewhere that is not the repository, such as a note in the password manager. Anyone who later rewrites the history cannot reproduce it. ritueel also puts the digest into each signed root list, which anchors the chain without using the root again.
5. **Not on the machine you use for the ceremony only.** A card root or a real software root is used only in a machine booted from a read-only system made for the purpose (the offline system), which keeps nothing. The directory is brought onto it, used, and taken back ([ADR 0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#where-a-plan-runs)).

## What else must be backed up, and where

The directory is only half. The other half is what it deliberately does not hold.

| Item | Why it is kept | Where |
|---|---|---|
| **Revocation certificates** of the OpenPGP master keys, made when each key was born, one for each of two reasons (compromised and superseded). | They are the only way to revoke a master key whose card and PIN are gone. | Apart from the cards, in at least two places: for example printed and sealed, and in the password manager. A third place is not wasteful. |
| **The PINs you type**, one entry per card, and the passphrase of the recovery key. | Without the PIN a card is a locked box; three wrong tries block it. The PUK and the management key are made and sealed by ritueel, so you do not keep them. | The password manager, never in the directory. |
| **The recovery key**: an age identity in a passphrase-protected file. | If both root cards are lost as well, the key files cannot be opened without it. | Apart from the cards, and apart from its passphrase: the file and the passphrase never sit in the same place. |
| **Software keys,** if any. | A software key is a copy by nature. | In the software store you chose, whose own replication is the backup (see [where a key lives](/learn/key-stores/)). |
| **The second card.** | A card cannot be copied. | A second, independent card, in a second place. |

## Backing up a card, a cloud key and a software key

- **A card** is not backed up. You have two cards. The second root is a different key, made on a different card; it is not a copy.
- **A cloud key** is not exported. You have a replica in another Region, which the service keeps for you.
- **A software key** is as safe as its store. In an encrypted file, a backup is another copy, which is a danger as well as a safety. In a synced password manager, the sync is the backup. In the system keyring, there is none.

None of these is a backup in the sense of "a copy I can restore from". It is redundancy against loss, and per [layered trust](/learn/layered-trust/), redundancy does not answer compromise.

## Restoring, and practising it

A restore you have never practised is a hope. The restore drill is the practice:

1. Start on a clean machine with nothing but the directory's remote and the password manager.
2. Clone the directory, verify the hash chain, and list the roots and what expires when.
3. Compare each root with its card or cloud key: the serial, the fingerprint, the attestation.
4. Walk through the loss of one card with its revocation certificate.

It ends when every check passes, and the record says how long each step took. The drill runs on test keys first, then once on the real ones. This is planned as its own command ([the drills](/guides/)).
