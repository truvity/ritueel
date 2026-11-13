---
title: Where a key lives
description: Key stores compared in the open, with software and its backends, YubiKey PIV and OpenPGP card, AWS KMS and planned key stores, and what each protects and costs.
sidebar:
  order: 12
---

*Design phase: this page teaches the trade-offs. None of the key stores is built yet; a key store is called supported only after it is proven on real hardware or a real account ([record 0002](../decisions/0002-where-a-key-lives.md)). The first version targets software, PIV, the OpenPGP card and AWS KMS. The measurements behind the card choices are in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/).*

A key has to live somewhere. The places differ in one question above all: **can the key be copied?** A key that cannot be copied can only be lost. A key that can be copied can also be stolen without anyone noticing.

One rule holds for every key store ([principle 1](/principles/)): **a key is born in its key store and never leaves it.** ritueel does not import a key, with two stated exceptions for a person's own OpenPGP key, an adopted primary and an encryption subkey made in software ([record 0002](../decisions/0002-where-a-key-lives.md), rule 2), and it never offers to export a key from a card or a cloud key service "for backup". For software stores the rule means the key is generated in memory and written directly into its key store, never to a file on disk.

## Which path is yours

Two paths lead to a root that others rely on. Pick the first unless you cannot.

- **The cloud root** is the recommended path for a team with a cloud account. It is an account you choose, with a key for each kind of root you use, each with a replica that the service keeps in a second Region, an audit trail of every use, and no cards to alternate. You pay in an account to secure, a provider to trust, and a key that cannot attest where it was made: you read its policy from the service instead ([what a key store can prove](/learn/what-a-store-can-prove/)). The first guide is [Prepare the cloud root](/guides/prepare-the-cloud-root/).
- **Two cards** is the path for a person or a lab with no cloud account, and it is the more demanding one: two independent keys on two cards, each made on its card, kept in two places, alternating by year ([Several keys, one root](/learn/two-roots/)).

To walk the questions in order, read [Choosing where a root lives](/learn/choosing-where-a-root-lives/).

**The trade-off the other tools make, said openly.** Other tools take a copy-once path: the root is made off the card and loaded onto two cards, so one card and a backup are enough ([the comparison](/learn/compared/) names them, with their sources). ritueel does not, because a copied key cannot attest where it was born, and the only verifier of a root's attestation is you. What you gain is a key that provably exists in one place. What you pay is two independent keys and the alternation. If you accept a wrapped copy in a safe, use one of those tools, and read ritueel to understand what you are doing.

## The key stores

| | Encrypted file | 1Password | OS keyring | YubiKey PIV | OpenPGP card | AWS KMS |
|---|---|---|---|---|---|---|
| **Kind** | Software | Software | Software | Hardware | Hardware | Cloud service |
| **Where the key is** | A passphrase-protected file on a disk you control. | An item in a 1Password vault, synced between your devices. | The system keyring: Secret Service on Linux, Keychain on macOS, Credential Manager on Windows. | A PIV slot of a hardware token. | The OpenPGP applet of a card. | The service. You ask it to sign. |
| **Can it be copied?** | Yes. A backup is a copy. | Yes, by anyone who can unlock the vault. Sync makes copies on each device. | Yes, by programs running as you, once the keyring is unlocked. | No. | No. | No, but the service can keep a replica. |
| **Protects against** | A casual thief who finds the file, if the passphrase is strong. | Loss of one device. Theft of one device that is locked. | Theft of a powered-off, encrypted disk. | Theft of the computer, and a copy of the key by malware. | The same. | Theft of a computer, loss of a card. Gives an audit trail. |
| **Does not protect against** | Malware that reads the file and the passphrase. A copy anywhere. | Malware on an unlocked device. A compromised account. | Malware, or any program of the same user. A lost laptop is a lost key: there is no copy. | Loss, fire, a thief who has the PIN and the token. | The same. | A locked or compromised account. A deleted key after the waiting period. |
| **Redundancy** | More copies, which raises the chance of theft. | The sync, which is the replication. Protects against loss only. | None. | A second, independent card. | A second, independent card. | A replica in another Region. |
| **What "present" means** | The passphrase. | Unlocking the vault. | The user session. | Possession, PIN and a touch. | Possession and PIN, and a touch if set. | Cloud permissions, plus what you add: a role, and the controls around it. |
| **Proof of where it lives** ([what that means](/learn/what-a-store-can-prove/)) | None. | None. | None. | An attestation certificate from the token. | An attestation from the card. | The key's description and policy, read from the service. |
| **Cost** | Free. | A subscription you probably have. | Free. | A token, bought twice. | A card, bought twice. | Per key and per use; an account to secure. |
| **Good for** | Drills, tests, development; a person's own primary, kept offline. | The keys of test roots, intermediates and subkeys; a drill that survives a lost laptop. Not a root, not a primary key. | Trying ritueel out. Not for a key others rely on. | The root keys; a service's intermediate. | A person's daily subkeys. | A company root; a service's intermediate. |

## The software stores in detail

**The encrypted file** is the simplest and the weakest. It is right for a drill, a test root and a development setup, and for a test harness that needs a root on day one. A backup of it is another copy, which is exactly the danger. A software root never anchors a signed release. It is also where a person keeps their own OpenPGP primary, offline, with copies on two media ([personal OpenPGP](/reference/personal-openpgp/)). Its key file is opened by a passkey on each root card (decided, not yet proven on a card: milestone M1), by a recovery key, or by a passphrase for a holder without cards ([the software store](/reference/software-store/#opening-a-key-file)).

**1Password, a planned backend, is a persistent home for the software keys of test roots, intermediates and subkeys.** The key goes straight from memory into a vault item through the `op` command line, so it is never a file on disk. The vault syncs between your devices, which gives you what a single file cannot: a lost laptop does not lose the key. That is redundancy against loss, and as ever it does not protect against compromise: whoever unlocks the vault has the key, and removing a member of a shared vault does not change its keys. So it is never the home of a production root or of your primary key. Use a vault only you can open, with a strong account password and Secret Key. ritueel never sees your account password ([the facts](/research/software-key-backends-2026-11-01/), read 2026-11-01).

**The operating system's keyring, a planned backend, can be insecure, and ritueel says so every time.** It is offered through [github.com/zalando/go-keyring](https://github.com/zalando/go-keyring) because it is already there and needs no account. But on many systems, once you are logged in and the keyring is unlocked, any program running as you can ask it for the key, and there is no copy: a dead disk is a dead key. Choose it to try ritueel out, or for a key whose loss you can survive. Do not choose it for a root other people trust. ritueel refuses to fall back to a file when no keyring is available, and puts the warning in the ceremony record.

## Hardware and cloud stores in plain words

**A PIV card makes the key physical.** The key is generated on the token, so it never exists in your computer's memory, and a thief needs the token, its PIN and a touch. The token can *attest* the key: it hands out a certificate, signed under the maker's published root, saying that a key in a given slot was made inside this token, with this firmware and this PIN and touch policy. A key that was imported cannot be attested. While a token is unlocked, other programs on the same computer can use it, so the computer is part of the trust boundary during a ceremony. A token has no backup, which is why there are two root cards.

**An OpenPGP card holds a person's daily key.** A signing or authentication subkey is born on the card's OpenPGP applet, so `gpg` uses it directly, and an offline primary key binds it. An encryption subkey is the exception: it is made in software and loaded onto each day-to-day card, with a wrapped backup, so a lost card does not lose the mail it decrypted ([record 0008](../decisions/0008-a-persons-own-key.md)). The PIV and OpenPGP applets of one card are independent, but a program that holds the card keeps the others out, so a root card holds only roots and the daily card is another card.

**AWS KMS makes the key a permission.** The key is as safe as the account's access control, and every use is in the audit trail. There is no card to lose, but an account to lose, and a deletion that can be undone only during a waiting period. A root that is "present" because a role was assumed is weaker than a touch unless the role is hard to assume. ritueel has the person confirm the plan and reads the key's policy, but it asks nothing of how the role is assumed, so the role's reach is the account's access control; making the role hard to assume is the holder's job. It reads the key's description, policy and public key from the service, never from a claim.

The two hardware and cloud stores are opened up in [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/) and [How a KMS key works](/learn/how-a-kms-key-works/).

The cloud root's account holds **one key for each kind of root the bundle uses, each with a multi-Region replica** ([record 0004](../decisions/0004-the-cloud-root.md)). A company that wants a root that does not depend on one provider gives it card keys.

## Planned key stores

These are not supported and not scheduled. Each arrives with its first real installation, a real account or a real device, because a key store that is only imagined cannot be tested ([principle 8](/principles/)). A key store is called supported only after it is proven on real hardware or a real account ([record 0002](../decisions/0002-where-a-key-lives.md), rule 1). The list of tests a key store passes first is in [a research note](/research/earlier-records-two-sources-2026-11-11/#the-tests-a-planned-key-store-passes).

| Key store | Why it is interesting | What has to be measured first |
|---|---|---|
| Google Cloud KMS | The same model as AWS KMS in another provider, for a company that does not use AWS. | What the key attestation and the policy can prove, signing with P-384, and how a key in another project is read. |
| Azure Key Vault | The same, for a company on Azure. | The same questions, and the difference between the vault and a managed HSM. |
| Nitrokey | Hardware with open firmware, as an alternative to YubiKey. | Which model supports PIV, the OpenPGP card or both, with which algorithms, and whether it can attest a key. A token that cannot attest holds no root ([what a key store can prove](/learn/what-a-store-can-prove/)). |
| Other tokens and HSMs | A company may already own them. | Whatever the first real installation needs. |

[Which keys to buy](/learn/which-keys-to-buy/) says which devices to buy for testing the hardware key stores, with the research behind it.

## Choosing

| If | Then |
|---|---|
| You are learning, or testing a pipeline | A software store, on a throw-away root, with a drill. |
| You want a drill to survive a lost laptop | 1Password, on a root that is still only a drill. |
| One person or a small team holds the roots, and no cloud is involved | Two independent root cards, in two places ([which path is yours](#which-path-is-yours)). |
| A person wants a daily OpenPGP key | A subkey born on an OpenPGP card, bound by a primary key kept offline. |
| An organisation already runs on AWS and wants audited, policy-gated roots | A cloud root: a key for each kind of root, each with a multi-Region replica, in an account kept for ceremony keys, with a ceremony role and the controls around it. |
| You want the strongest story | A root with keys in different key stores: for example cards and a KMS key. A failure of one kind does not take out the other. |

## Moving between key stores

Every move is a transition ([moving from one root to another](/learn/transitions/)): create the new key in the new key store, have an old key vouch for it, overlap, supersede. What differs is what you gain and what you check.

| From | To | What changes | What to check |
|---|---|---|---|
| Software | PIV card | The key stops being copyable. | The new key is attested, and the chain verifies against the maker's root. |
| Software | AWS KMS | The key moves under cloud access control and audit. | Only the ceremony role may sign. After the keys are created, only the break-glass principal may replicate a key ([record 0004](../decisions/0004-the-cloud-root.md), rule 5). |
| PIV card | AWS KMS | A physical key becomes a permission. | The confirmation still needs a person. |
| AWS KMS | PIV card | A permission becomes a physical key. | A second card exists in another place before the first is relied on. |
| Same kind | Same kind | A replaced token, or a KMS key in another account. The key is new. | The overlap is long enough for slow clients. |

There are no key copies in this table, on purpose. A transition never moves a key; it makes a new one and has the old one vouch for it, so a key store that cannot export a key is never a problem.
