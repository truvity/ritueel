---
title: Choosing where a root lives
description: Questions that pick where a root lives (a key file, a pair of root cards or a cloud key), how a key file opens, and what each costs you in a year.
sidebar:
  order: 12.45
---

*Design phase: ritueel is in design and has no release, and none of the three stores is built ([roadmap](/roadmap/)). Everything said here about ritueel is what an accepted decision record says on 2026-11-11, and where a record says "decided, not yet proven", so does this page. The AWS price was read on 2026-11-11; prices change, so check it before you rely on it.*

You are about to make a root, and the first question is where it will live. The answer is hard to undo: a root never moves from one store to another. A new root in the new store is made, the old one vouches for it, and the two overlap ([moving from one root to another](/learn/transitions/)). So choose with some care.

This page sits at the first link of [the custody chain](/learn/custody-chain/): the store that holds the root. It does not explain the stores. [Where a key lives](/learn/key-stores/) compares them, [how a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/) and [how a KMS key works](/learn/how-a-kms-key-works/) open the hardware and the cloud service, and [what a key store can prove](/learn/what-a-store-can-prove/) says what evidence each gives. This page only helps you choose.

ritueel's first version has three stores for a root ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/), [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)):

- **A software key in an encrypted key file.**
- **A pair of root cards,** two independent hardware tokens.
- **A cloud key,** one root in a cloud key service, which ritueel creates or adopts.

## Four questions

Ask them in order. The first answer that fits is your store.

### 1. Will other people or systems rely on this root?

If the root is for practice, a drill or development, or it is a person's own OpenPGP primary, use **a software key in an encrypted key file.** The records allow these uses and refuse one: the software store never holds a root that others rely on ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold), [the software store](/reference/software-store/#the-backends)).

The reason is in the key. A software key can be copied and read without a trace, and it gives no evidence of where it lives. Every record of a software root says so. If you cannot name one of the uses above, go on to question 2.

### 2. Does your organisation have a cloud account that can hold a dedicated root account?

If yes, the usual choice is **a cloud key.** It is one root that the service keeps, with a replica in a second Region. There are no cards to alternate and no card to lose. [Where a key lives](/learn/key-stores/#which-path-is-yours) gives this as the first choice for a team with a cloud account.

If no, use **two root cards.** This is the path for a person or a lab with no cloud account. It asks more of you, and the rest of this page shows how much.

A cloud root and a card root can also sit side by side. ADR 0002 says a company that wants a root that does not depend on one provider adds a card root.

### 3. If it is a cloud key: does the key already exist?

ritueel can create the key, or **adopt** one that already exists ([ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/)). Adopt when your own infrastructure code already owns the key, its alias and its policy. When ritueel adopts a key, it reads the public key and the key policy and runs its checks on them.

Two rules hold either way. The key must have been born in the service: key material imported from outside is refused. And the key policy must refuse new replicas and moving the primary Region for everyone except the break-glass principal, and allow digests only. A key that fails a check is refused, with the reason ([the cloud root](/reference/kms-root/#adopting-an-existing-key)). Adoption is decided, and has not yet been tried against a real account.

### 4. How will the key file be opened?

This question is for a software key, and also for the secrets that ritueel makes for a card and seals in the directory, which are opened the same way ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/)).

1. **Do you have root cards?** If yes, the default is **a passkey on each root card.** Any one card of the pair opens the file. The next section says what that means.
2. **If you have no cards,** use **a passphrase.** A passphrase file has no second way in: the age format says a passphrase recipient must be the only recipient (age v1, read 2026-11-11, [age-encryption.org/v1](https://age-encryption.org/v1)). Lose the passphrase and you lose the file.
3. **Whichever you pick, keep a recovery key** where the default is used: an age identity in a passphrase-protected file, kept apart from the cards. Its file and its passphrase never sit in the same place.

## How a passkey opens the file

The key file is encrypted to two recipients: an **unlock key** and the recovery key. A passkey on each root card gives a secret that unwraps the private half of the unlock key. The unlock key then opens the file. Opening needs the card, the card's PIN for the passkey and a touch. Writing a new file needs no card, because the unlock key's public half is a recipient. ([How a passkey gives a secret](/learn/how-a-yubikey-holds-keys/#a-passkey-that-opens-a-key-file) shows it step by step.)

Three ways are refused, each with a reason in ADR 0015: a **synced passkey** (it puts a root-level file behind a cloud account), **unlocking inside the local page** (the browser would hand the secret to the page, and the offline system has no browser), and **a day-to-day card as the unlocker** (it is carried and used every day).

**Decided, not yet proven.** Whether a passkey secret works with PIN and touch over USB from a static binary, and whether the offline system reaches the card's passkey side, is tried on a rehearsal card first (milestone M1). If the proof fails, the fallback is a key-agreement key in PIV slot 9d of each root card. Both outcomes are decided, so only the result is waited for.

## The three stores side by side

| | Software key in a file | Two root cards | Cloud key |
|---|---|---|---|
| **May hold** | Test roots, drills, development, a person's own primary. Never a root that others rely on. | The roots of one holder, up to five on a pair of cards, each in its own row. | One dedicated root account with one root. |
| **Born where** | In memory, written straight into the file. | On the card. Each card makes its own keys, and the two are never copies. | In the service. Key material imported from outside is refused. |
| **Can it be copied?** | Yes. Every record says so. | No. | No. The service keeps a replica of the same key in a second Region. |
| **Redundancy** | A copy, which raises the chance of theft. | A second, independent root on the other card. | The replica. It covers a lost Region or a lost primary copy, and is never counted as a second root. |
| **Evidence of where it lives** | None. | An attestation chain to the maker's root. | The key's description, policy and audit trail, read from the service. Not that it was made in a hardware module. |
| **A ceremony runs on** | The machine that opens the file. The key is in memory while it signs. | A machine booted from a read-only system made for the purpose (the offline system). | Your workstation, through the ceremony role. |
| **When the key ends** | Replaced at most every three years, because it can be copied. | On an event: an advisory, a lost card, a compromise, a change of store. Not on a date. | The same events. |
| **Built in** | M2 (the file). | M6, after the first signed release. | M2 (the store), and adoption is drilled in M4. |

Sources of the rows: [ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/), [ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/), [ADR 0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/), [the software store](/reference/software-store/), [root cards](/reference/cards/), [the cloud root](/reference/kms-root/) and the [roadmap](/roadmap/).

## What it costs you each year

Money is easy to count. Time and care are not, so the table lists both.

| | Software key in a file | Two root cards | Cloud key |
|---|---|---|---|
| **Money** | None for the store. | The two cards, bought once. No fee a year. Prices are on [which keys to buy](/learn/which-keys-to-buy/). | USD 1 for each key each month, and a replica counts as a key. About USD 72 a year for a root of three keys with replicas, before request fees. |
| **The yearly ceremony** | None for a practice root. A person's own primary follows [personal OpenPGP](/reference/personal-openpgp/). | One, on the offline system. It costs a boot. The cards alternate: A one year, B the next. | One, from your workstation. A cloud root has nothing to alternate with, so it signs every year. |
| **Checks you repeat** | A restore drill each year, for a real directory. | A card check and a proof of life every six months. A restore drill each year. | A restore drill each year. |
| **The advisory review** | At each yearly ceremony. | At each yearly ceremony. | At each yearly ceremony. |
| **What you keep safe** | The file, and what opens it: root cards with a recovery key, or a passphrase. | Two cards in two places. One PIN per card, in your password manager. A recovery key. | An account to secure, and the roles around the key. |
| **If it is lost** | The key is gone unless a copy exists, and a copy is the danger. | Lose a card: the other root exists, and you revoke the lost one with the revocation signature stored apart. | Lose a Region: the break-glass principal recovers it, a manual and logged act. |

How to read the table:

- **The price.** AWS lists each KMS key at USD 1 a month, prorated hourly, and counts each primary and each replica multi-Region key (AWS KMS pricing, read 2026-11-11, [aws.amazon.com/kms/pricing](https://aws.amazon.com/kms/pricing/)). A cloud root has three keys: an X.509 root, an OpenPGP primary and a break-glass SSH CA key ([the cloud root](/reference/kms-root/#what-ritueel-creates)). Six keys at USD 1 for twelve months is USD 72. That is arithmetic, not a quote from AWS. A request costs extra: AWS's own example prices an ECC 256 signing key at USD 0.15 per 10,000 requests, and a root signs rarely.
- **The yearly ceremony and the checks** come from ADR 0002, ADR 0010 and ADR 0016. A drill is due once a year, with the yearly ceremony. ritueel teaches the rhythm and does not enforce it.
- **The advisory review** is a step of the ceremony, and the record says it was done. A missed advisory is the one event a holder can fail to notice ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)).
- **Renewing a cloud root without a person** is designed and built later (M7). A card root cannot be renewed that way.
- **Firmware.** A card with firmware older than 5.7.4 cannot hold a root ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#rules-for-a-shared-card)).

## The limit every choice accepts

Whoever holds one root card and its PIN, or the role that uses a cloud root, can sign things that outsiders trust, until that root is revoked and the update reaches them. Standard tools cannot require m-of-n. The second card is a second independent root, not a spare, and the custody is one holder's, not a two-person control. A replica is the same key, not a second root. A compromise is answered by revocation and a transition, never by a second copy ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit)).

## Where to go next

- The stores in plain words: [where a key lives](/learn/key-stores/).
- What each store can prove about itself: [what a key store can prove](/learn/what-a-store-can-prove/).
- Why two root cards and how they alternate: [two roots in practice](/learn/two-roots/).
- Which cards to buy: [which keys to buy](/learn/which-keys-to-buy/).
- The steps: [prepare a root card](/guides/prepare-a-root-card/) and [prepare the cloud root](/guides/prepare-the-cloud-root/).
- Replacing a root later: [moving from one root to another](/learn/transitions/).

## Sources

- The records named above, accepted on 2026-11-11.
- AWS, [AWS KMS pricing](https://aws.amazon.com/kms/pricing/): USD 1 a month for each key, prorated hourly, each primary and each replica counted; the ECC 256 example at USD 0.15 per 10,000 requests. Read 2026-11-11.
- age, [the age v1 specification](https://age-encryption.org/v1): a passphrase recipient must be the only recipient of a file. Read 2026-11-11, the sentence "An scrypt stanza, if present, MUST be the only stanza in the header".
