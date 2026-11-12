---
title: Choosing where a root lives
description: Questions that pick where a root lives (a key file, a pair of root cards or a cloud key), how a key file opens, and what each costs you in a year.
sidebar:
  order: 12.45
---

*Design phase: ritueel is in design and has no release, and none of the three stores is built ([roadmap](/roadmap/)). Everything said here about ritueel is what an accepted decision record says on 2026-11-12, and where a record says "decided, not yet proven", so does this page. The AWS price was read on 2026-11-11; prices change, so check it before you rely on it.*

You are about to make a root, and the first question is where it will live. The answer is hard to undo: a key never moves from one store to another. A new key in the new store is made, an old key vouches for it, and the two overlap ([moving from one root to another](/learn/transitions/)). So choose with some care.

This page sits at the first link of [the custody chain](/learn/custody-chain/): the store that holds the root. It helps you choose; the pages under "Where to go next" explain the stores.

ritueel has three stores for a root ([record 0002](../decisions/0002-where-a-key-lives.md), [record 0003](../decisions/0003-root-cards.md), [record 0004](../decisions/0004-the-cloud-root.md)). They arrive in different milestones, as the table below shows:

- **A software key in an encrypted key file.**
- **A pair of root cards,** two independent hardware tokens.
- **A cloud key,** one key in a cloud key service, which ritueel creates or adopts.

## Two questions to pick, two to follow up

Questions 1 and 2 pick the store. Ask them in order; the first answer that fits is your store. Questions 3 and 4 follow from the store you picked: question 3 if it is a cloud key, question 4 if the root, or the secrets of a root card, are kept in a key file.

### 1. Will other people or systems rely on this root?

If no, because it is for practice, a drill or development, use **a software key in an encrypted key file.** The records allow these uses and refuse one: the software store never holds a root that others rely on ([record 0002](../decisions/0002-where-a-key-lives.md), [the software store](/reference/software-store/#the-backends)). A person's own OpenPGP primary is the one exception the records allow, because it stays offline in the file ([record 0008](../decisions/0008-a-persons-own-key.md)); it is not a root a company relies on.

The reason is in the key. A software key can be copied and read without a trace, and it gives no evidence of where it lives. Every ceremony record of a software root says so. If yes, go on to question 2.

### 2. Can your organisation set up a separate cloud account used only for the root?

If yes, the usual choice is **a cloud key.** It is one key that the service keeps, with a replica in a second Region (a geographic area where the provider runs its data centres). There are no cards to alternate and no card to lose. [Where a key lives](/learn/key-stores/#which-path-is-yours) gives this as the first choice for a team with a cloud account.

If no, use **two root cards.** This is the path for a person or a lab with no cloud account. It asks more of you, and the rest of this page shows how much.

A root can have keys in the cloud and on cards. A company that wants a root that does not depend on one provider gives it card keys too ([record 0004](../decisions/0004-the-cloud-root.md)).

### 3. If it is a cloud key: does the key already exist?

If no key exists, let ritueel create it. If your own infrastructure code (for example Terraform) already makes the key, let ritueel **adopt** it ([record 0004](../decisions/0004-the-cloud-root.md)). When it adopts a key, ritueel reads the public key and the key policy and runs its checks on them. The key policy is the set of rules, kept by the service, about who may do what with the key; [how a KMS key works](/learn/how-a-kms-key-works/) explains it.

Two rules matter most when you adopt a key. The key must have been born in the service: key material imported from outside is refused. And the key policy must refuse new replicas and moving the primary Region for everyone except the break-glass principal (the one account role kept for emergencies), and must let the key sign only a hash of the data (a "digest"), never the data itself. A key that fails a check is refused, with the reason. The full list of checks is on [the cloud root](/reference/kms-root/#the-checks) page ([adopting a key](/reference/kms-root/#adopting-an-existing-key)). Adoption is decided, and has not yet been tried against a real account.

### 4. How will the key file be opened?

ritueel keeps the key of a software root in a file encrypted with age, a small file-encryption format. An age file can be locked to more than one secret (each is a "recipient"), and any one of them opens it alone. This question is for a software key, and also for the secrets that ritueel makes for a card and seals (encrypts) in the bundle, the directory of plain files with a fixed structure where ritueel keeps its records ([the bundle](/reference/bundle/)). Those are opened the same way ([record 0002](../decisions/0002-where-a-key-lives.md)).

- **You have root cards:** the default is **a passkey on each root card.** A passkey is a key pair that lives on the card and is opened with the card's PIN and a touch ([how passkeys work](/learn/how-passkeys-work/#passkeys-in-brief)). Any one of the cards named for the file opens it, and a file may name more than two. The next section says what that means.
- **You have no cards:** use **a passphrase.** A passphrase file has no second way in: the age format says a passphrase recipient must be the only recipient (age v1, read 2026-11-11, [C2SP age.md](https://github.com/C2SP/C2SP/blob/main/age.md)). Lose the passphrase and you lose the file.
- **With the passkey default,** a recovery key is the second recipient: an age identity in a passphrase-protected file, kept apart from the cards. Its file and its passphrase never sit in the same place. The recovery passphrase is the break-glass and may live in a password manager; keep the file it protects somewhere else. A passphrase-only file has no recovery key, so keep the passphrase safe.

## How a passkey opens the file

The file is locked to an unlock key and a recovery key. A secret from the passkey on any card named for the file opens the unlock key, and the unlock key opens the file. Each such card has its own passkey and all open the same unlock key, so any one card is enough. Opening needs the card, the card's PIN for the passkey and a touch. Locking a new file needs only the public part of the unlock key, so it needs no card. ([How a passkey opens a key file](/learn/how-passkeys-work/#a-passkey-that-opens-a-key-file) shows the steps.)

Three ways are not supported, each with its reason in [record 0002](../decisions/0002-where-a-key-lives.md): a **synced passkey** (it puts a root-level file behind a cloud account), **unlocking in ritueel's browser page, which runs on your own machine** (the browser would hand the secret to the page, and the offline system has no browser), and **a day-to-day card as the unlocker** (it is carried and used every day). For now a password-manager passkey or unlock item is not offered either; the recovery passphrase kept in the manager gives the same.

**Decided, not yet proven.** Whether this works with PIN and touch over USB is tried first on a rehearsal card (milestone M1 in the [roadmap](/roadmap/)). If it fails, a key in a slot of the card's PIV application (slot 9d) opens the file instead. Both outcomes are decided, so only the result is waited for; [how passkeys work](/learn/how-passkeys-work/#a-passkey-that-opens-a-key-file) has the full account.

## The three stores side by side

The rows that decide are below. Where a key is born, whether it can be copied, redundancy and evidence are compared on [where a key lives](/learn/key-stores/) and [what a key store can prove](/learn/what-a-store-can-prove/).

| | Software key in a file | Two root cards | Cloud key |
|---|---|---|---|
| **May hold** | Test roots, drills, development, a person's own primary. Never a root that others rely on. | The root keys of the holder's bundles, on a pair of cards, a row for each bundle. | One dedicated account with three keys. |
| **A ceremony runs on** | A key that can be copied is used only in the offline system. A test root: any machine that can open the file, or a rehearsal card; the key is in memory while it signs. | Your workstation, under four conditions (a touch for every signature, the number of signatures stated in the plan, no retry of a failed touch, a check on a second device), or the offline system. | Your workstation, through the ceremony role, with the typed plan digest and the role session. There is no touch. The stated number of signatures, no retry and the check on a second device apply as for cards ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 18). |
| **When the key ends** | Replaced at most every three years, because it can be copied. | On an event: an advisory, a lost card, a compromise, a change of store. Not on a date. | The same events. |
| **Built in** | M2 (the file). | M6, after the first signed release. | M2 (the store), and adoption is drilled in M4. |

Sources of the rows: [record 0002](../decisions/0002-where-a-key-lives.md), [record 0003](../decisions/0003-root-cards.md), [record 0004](../decisions/0004-the-cloud-root.md), [the software store](/reference/software-store/), [root cards](/reference/cards/), [the cloud root](/reference/kms-root/) and the [roadmap](/roadmap/).

## What it costs you each year

Money is easy to count. Time and care are not, so the table lists both.

| | Software key in a file | Two root cards | Cloud key |
|---|---|---|---|
| **Money** | None for the store. | The two cards, bought up front; a lost card or one that reaches end of life is bought again. No yearly fee. Prices are on [which keys to buy](/learn/which-keys-to-buy/). | USD 1 for each key each month, and a replica counts as a key. About USD 72 a year for the three keys of the cloud root page (an X.509 root, an OpenPGP primary and a break-glass SSH CA key), each with a replica, before request fees. |
| **The yearly ceremony** | None for a practice root. A person's own primary follows [personal OpenPGP](/reference/personal-openpgp/). | One, from your workstation, or in the offline system if you choose it, which costs a boot. The cards alternate: A one year, B the next. | One, from your workstation. A cloud root has nothing to alternate with, so it signs every year. |
| **Checks you repeat** | A restore drill each year, for a real bundle. | A card check and a proof of life every six months. A restore drill each year. | A restore drill each year. |
| **What you keep safe** | The file, and what opens it: root cards with a recovery key, or a passphrase. | Two cards in two places. One PIN per card, in your password manager. A recovery key. | An account to secure, and the roles around the key. |
| **If it is lost** | The key is gone unless a copy exists, and a copy is the danger. | Lose a card: the other key exists, and you revoke the lost one with the revocation signature stored apart. | Lose a Region: the break-glass principal recovers it, a manual and logged act. |

How to read the table:

- **The price.** AWS lists each KMS key at USD 1 a month, prorated hourly, and counts each primary and each replica multi-Region key (AWS KMS pricing, read 2026-11-11, [aws.amazon.com/kms/pricing](https://aws.amazon.com/kms/pricing/)). The cloud root page lists three keys: an X.509 root, an OpenPGP primary and a break-glass SSH CA key ([the cloud root](/reference/kms-root/#what-ritueel-creates)). Six keys at USD 1 for twelve months is USD 72. A root without the SSH CA key costs USD 48. That is arithmetic, not a quote from AWS. A request costs extra: AWS's own example prices an ECC 256 signing key at USD 0.15 per 10,000 requests, and a root signs rarely. The root keys are P-384, and the pricing page lists no request price for P-384, so treat USD 0.15 as the example only.
- **The words in the table.** A *revocation signature* is made when the key is born and kept apart; it cancels the key if its card is lost ([revoke](/learn/revoke/)). The *break-glass principal* is the one account role kept for emergencies. A *restore drill* is a yearly test that the backup brings the bundle back ([the history](/learn/the-history/)). A *proof of life* is a short test that a card still works for its holder.
- **The yearly ceremony and the checks** come from [record 0007](../decisions/0007-changing-and-losing-a-root.md). A drill is due once a year, with the yearly ceremony. ritueel teaches the rhythm and does not enforce it. `ritueel apply` renews what is due ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 11).
- **The advisory review** is a step of every yearly ceremony, whatever the store, and the ceremony record says it was done; a practice software root has no yearly ceremony, so no review. A missed advisory is the one event a holder can fail to notice ([record 0007](../decisions/0007-changing-and-losing-a-root.md)).
- **A renewal role for a cloud root** is planned for later (M7) ([record 0002](../decisions/0002-where-a-key-lives.md), rule 17).
- **Firmware.** A card with firmware older than 5.7.4 cannot hold a root ([record 0003](../decisions/0003-root-cards.md)).

## The limit every choice accepts

Whoever has your key and what opens it can sign for you. For a software key that is the file and its passphrase or card. For a root card it is the card and its PIN. For a cloud root it is the role that may sign. They can sign until you revoke the key and the update reaches everyone who trusts it. No standard tool can require several people to agree (an "m of n" rule). A second root card holds a second, independent key of the same root, never a copy and not a spare, and the custody is one holder's, not a two-person control. A replica is the same key, not a second root. A compromise is answered by revocation and a transition, never by a second copy ([record 0002](../decisions/0002-where-a-key-lives.md)).

Two more limits apply when a root is used on the workstation. If you are tricked into one extra touch, one unknown signature exists, and a card keeps no log of it ([record 0002](../decisions/0002-where-a-key-lives.md), rule 17). For a cloud root, nothing in AWS ties a signature to a person: anyone who can assume the ceremony role can sign any digest without ritueel, and its audit trail records it ([record 0004](../decisions/0004-the-cloud-root.md), rule 10; [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 19).

## Where to go next

- The stores in plain words: [where a key lives](/learn/key-stores/).
- What each store can prove about itself: [what a key store can prove](/learn/what-a-store-can-prove/).
- The hardware and the cloud service opened up: [how a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/) and [how a KMS key works](/learn/how-a-kms-key-works/).
- Why two root cards and how they alternate: [two roots in practice](/learn/two-roots/).
- Which cards to buy: [which keys to buy](/learn/which-keys-to-buy/).
- The steps: [prepare a root card](/guides/prepare-a-root-card/) and [prepare the cloud root](/guides/prepare-the-cloud-root/).
- Replacing a root later: [moving from one root to another](/learn/transitions/).

## Sources

- The records named above, accepted on 2026-11-12.
- AWS, [AWS KMS pricing](https://aws.amazon.com/kms/pricing/): USD 1 a month for each key, prorated hourly, each primary and each replica counted; the ECC 256 example at USD 0.15 per 10,000 requests. Read 2026-11-11.
- age, [the age v1 specification](https://github.com/C2SP/C2SP/blob/main/age.md): a passphrase recipient must be the only recipient of a file. Read 2026-11-11, the sentence "An scrypt stanza, if present, MUST be the only stanza in the header".
