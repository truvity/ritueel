---
title: Where a key lives
description: Key stores compared in the open, with software and its backends, YubiKey PIV and OpenPGP card, AWS KMS and planned stores, and what each protects and costs.
sidebar:
  order: 7
---

*Design phase: this page teaches the trade-offs. None of the stores is built yet; a store is called supported only after it is proven on real hardware or a real account ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/)). The first version targets software, PIV, the OpenPGP card and AWS KMS. The measurements behind the card choices are in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/).*

A key has to live somewhere. The places differ in one question above all: **can the key be copied?** A key that cannot be copied can only be lost. A key that can be copied can also be stolen without anyone noticing.

One rule holds for every store ([principle 1](/principles/)): **a key is born in its store and never leaves it.** ritueel does not import a key, and it never offers to export a key from a card or a cloud key service "for backup". For software stores the rule means the key is generated in memory and written directly into the store, never to a file on disk.

## The stores today

| | Encrypted file | 1Password | OS keyring | YubiKey PIV | OpenPGP card | AWS KMS |
|---|---|---|---|---|---|---|
| **Kind** | Software | Software | Software | Hardware | Hardware | Cloud service |
| **Where the key is** | A passphrase-protected file on a disk you control. | An item in a 1Password vault, synced between your devices. | The system keyring: Secret Service on Linux, Keychain on macOS, Credential Manager on Windows. | A PIV slot of a hardware token. | The OpenPGP applet of a card. | The service. You ask it to sign. |
| **Can it be copied?** | Yes. A backup is a copy. | Yes, by anyone who can unlock the vault. Sync makes copies on each device. | Yes, by programs running as you, once the keyring is unlocked. | No. | No. | No, but the service can keep a replica. |
| **Protects against** | A casual thief who finds the file, if the passphrase is strong. | Loss of one device. Theft of one device that is locked. | Theft of a powered-off, encrypted disk. | Theft of the computer, and a copy of the key by malware. | The same. | Theft of a computer, loss of a card. Gives an audit trail. |
| **Does not protect against** | Malware that reads the file and the passphrase. A copy anywhere. | Malware on an unlocked device. A compromised account. On Linux, any program of the same user can reach the app. | Malware, or any program of the same user, usually with no prompt. It is often synced or backed up. There is no copy of its own: a lost laptop is a lost key. | Loss, fire, a thief who has the PIN and the token. | The same. | A locked or compromised account. A deleted key after the waiting period. |
| **Redundancy** | More copies, which raises the chance of theft. | The sync, which is the replication. Protects against loss only. | None. | A second, independent card. | A second, independent card. | A replica in another Region. |
| **What "present" means** | The passphrase. | Unlocking the vault. | The user session. | Possession, PIN and a touch. | Possession and PIN, and a touch if set. | Cloud permissions, plus what you add: a role that needs multi-factor authentication. |
| **Proof of where it lives** | None. | None. | None. | An attestation certificate from the token. | An attestation from the card. | The key's description and policy, read from the service. |
| **Cost** | Free. | A subscription you probably have. | Free. | A token, bought twice. | A card, bought twice. | Per key and per use; an account to secure. |
| **Good for** | Drills, tests, development. | A drill that survives a lost laptop; an encrypted copy of an intermediate's key or a subkey. Not a home for a root. | A throw-away test key. Not for a key others rely on. | The root keys; a service's intermediate. | A person's daily subkeys. | A company root; a service's intermediate. |

## The software stores in detail

**The encrypted file** is the simplest and the weakest. It is right for a drill, a test root and a development setup, and for a test harness that needs a root on day one. A backup of it is another copy, which is exactly the danger. A software root never anchors a signed release.

**1Password is the proposed persistent store for software keys.** The key goes straight from memory into a vault item, so it is never a file on disk. The vault syncs between your devices, which gives you what a single file cannot: a lost laptop does not lose the key. That is redundancy against loss, and as ever it does not protect against compromise. What to know before you choose it (read from the vendor's documentation and white paper, 2026-11-01):

- **The key is exportable by design.** Whoever can unlock the item gets every byte. The vendor's own threat statement says malware that can read memory while the app is unlocked can extract secrets.
- **It is synced to the vendor's cloud and to every signed-in device,** so the key is not offline.
- **On Linux, any process started by your user can connect to the app's socket,** and a command-line session stays authorised for up to 10 minutes idle and 12 hours in all. On macOS and Windows the app checks the caller's code signature.
- **A shared vault is not rotated when a member leaves:** removing a member is not cryptographically enforced, and on team plans a recovery group can reach every vault.
- **Recovery needs the account password and the Secret Key.** The vendor cannot recover data if both are lost, and the Emergency Kit that holds the Secret Key is itself a secret.
- **The item type matters.** An SSH Key item accepts only Ed25519 and RSA, not ECDSA P-384, so ritueel stores its key in a Document item or a Secure Note.

So 1Password is a good place for a drill's key, for an encrypted copy of an intermediate's key or a subkey, and for a passphrase. It is not a home for a root that others rely on. Use a vault only you can open, and lock the app when you step away. ritueel never sees your account password.

**The operating system's keyring can be insecure, and ritueel says so every time.** It is offered through [github.com/zalando/go-keyring](https://github.com/zalando/go-keyring) (v0.2.8, read 2026-11-01) because it is already there and needs no account. The warning ritueel shows reads:

> The OS keyring is not a safe home for a root or master key. Any program running as your user can usually read it without a prompt, it is often synced or backed up, and it cannot be made non-exportable. Use it only for a throw-away test key or for the passphrase of an already encrypted key. Keep real root keys offline, on a hardware token or in a key service.

The details behind it:

| System | What backs it | What to know |
|---|---|---|
| Linux | The Secret Service over the D-Bus session bus (GNOME Keyring, or KWallet if it offers that interface). | The library opens a plain session, so the secret crosses the bus unencrypted. Any program on the session bus can ask an unlocked collection. A headless server without a session bus has no keyring, and ritueel refuses to fall back to a file. |
| macOS | The login Keychain, through the `security` tool. | The secret is base64, which is not encryption. About 3000 bytes fit. A program of the same user that can run `security` may read it while the keychain is unlocked (not confirmed on a Mac). |
| Windows | The Credential Manager. | A secret above 2560 bytes is refused. Programs of the same user can read generic credentials. |

An armoured OpenPGP secret key is about 1 KB, so it fits all three; size is not the reason to avoid it. ritueel puts the warning in the ceremony record too.

## Hardware and cloud stores in plain words

**A PIV card makes the key physical.** The key is generated on the token, so it never exists in your computer's memory, and a thief needs the token, its PIN and a touch. The token can *attest* the key: it hands out a certificate, signed under the maker's published root, saying that a key in a given slot was made inside this token, with this firmware and this PIN and touch policy. A key that was imported cannot be attested. While a token is unlocked, other programs on the same computer can use it, so the computer is part of the trust boundary during a ceremony. A token has no backup, which is why there are two root cards.

**An OpenPGP card holds a person's daily key.** A signing, encryption or authentication subkey is born on the card's OpenPGP applet, so `gpg` uses it directly, and an offline master key binds it. The PIV and OpenPGP applets of one card are independent, but a program that holds the card keeps the others out, so root cards are dedicated and the daily card is another card.

**AWS KMS makes the key a permission.** The key is as safe as the account's access control, and every use is in the audit trail. There is no card to lose, but an account to lose, and a deletion that can be undone only during a waiting period. A root that is "present" because a role was assumed is weaker than a touch unless the role is hard to assume, so ritueel gates the role with multi-factor authentication and has the person confirm the plan. It reads the key's description, policy and public key from the service, never from a claim.

A company root in KMS is **one root and a multi-Region replica, in one dedicated root account** ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). A company that wants a root that does not depend on one provider adds a card root.

## Planned stores

These are not supported and not scheduled. Each arrives with its first real installation, a real account or a real device, because a store that is only imagined cannot be tested ([principle 8](/principles/)).

| Store | Why it is interesting | What has to be measured first |
|---|---|---|
| Google Cloud KMS | The same model as AWS KMS in another provider. It signs a SHA-384 digest with P-384 at the HSM level and documents an attestation that a key was made in the HSM. About 2.50 USD per HSM key per month (computed from list prices, 2026-11-01). | Signing a real certificate and a real OpenPGP signature, importing a P-384 key, and how a key in another project is read. |
| Azure Key Vault | The same model for a company on Azure. P-384 signing with a supplied hash. A Premium HSM-protected key costs about 5 USD per month for the first 250 keys, and a Managed HSM about 2,300 USD per month (Azure price API, West Europe, 2026-11-01). No key attestation was found. | The signature encoding (probably raw r and s, which needs conversion), and the difference between the vault and a Managed HSM. |
| Nitrokey | Hardware with open firmware, at about 65 EUR for a Nitrokey 3 (shop, 2026-11-01). The Nitrokey 3 has an OpenPGP card with P-384 and touch confirmation, and a PIV applet with P-384 since firmware 1.8.2. **It cannot attest a key** in either (read from its source, 2026-11-01), so a ceremony with it has no hardware evidence. | Per-key touch policy for PIV, behaviour with the PIV and OpenPGP card libraries, and how it matures. |
| Other tokens and HSMs | A company may already own them. | Whatever the first real installation needs. |

A page on which keys to buy for testing the hardware stores follows with the research behind it.

## Choosing

| If | Then |
|---|---|
| You are learning, or testing a pipeline | A software store, on a throw-away root, with a drill. |
| You want a drill to survive a lost laptop | 1Password, on a root that is still only a drill. |
| One person or a small team holds the roots, and no cloud is involved | Two independent root cards, in two places. |
| A person wants a daily OpenPGP key | A subkey born on an OpenPGP card, bound by a master key kept offline. |
| An organisation already runs on AWS and wants audited, policy-gated roots | One KMS root with a multi-Region replica, in a dedicated root account, with a role that needs multi-factor authentication. |
| You want the strongest story | Roots on different kinds of store: for example a card root and a KMS root. A failure of one kind does not take out the other. |

## Moving between stores

Every move is a transition ([moving from one root to another](/learn/transitions/)): create the new root in the new store, have the old one vouch for it, overlap, supersede. What differs is what you gain and what you check.

| From | To | What changes | What to check |
|---|---|---|---|
| Software | PIV card | The key stops being copyable. | The new root is attested, and the chain verifies against the maker's root. |
| Software | AWS KMS | The key moves under cloud access control and audit. | The key's policy names one actor, and the role needs multi-factor authentication. |
| PIV card | AWS KMS | A physical key becomes a permission. | The confirmation step still needs a person. |
| AWS KMS | PIV card | A permission becomes a physical key. | A second card exists in another place before the first is relied on. |
| Same kind | Same kind | A replaced token, or a KMS key in another account. The key is new. | The overlap is long enough for slow clients. |

There are no key copies in this table, on purpose. A transition never moves a key; it makes a new one and has the old one vouch for it, so a store that cannot export a key is never a problem.
