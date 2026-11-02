# 0003 — Key stores and the card layer

**Status:** Accepted; amended by 0007
**Date:** 2026-11-02

## Context

A ritueel ceremony makes a key in a store, or binds a key that a store holds. The stores differ in how a key is reached and in what proves where it lives: a PIV slot attests with a certificate, a card's OpenPGP applet attests with a command of its own, a cloud key service has no attestation, and a file proves nothing. The roots on the cards need OpenPGP and X.509 keys side by side, and a person's daily OpenPGP key must be where `gpg` looks.

The card layer was the subject of a spike ([issue #26](https://github.com/truvity/ritueel/issues/26)) on two YubiKey 5 test cards (firmware 5.8.0) and AWS KMS keys, from 2026-10-31 to 2026-11-01. Its numbers are in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/) and [the verifier matrix](/research/openpgp-verifier-matrix-2026-11/). The verdicts used here: a P-384 key in a PIV slot or in KMS works as an OpenPGP version 4 primary and subkey for `gpg`, `gpgv`, `sqv`, apt and rpm; piv-go's built-in attestation roots fail on firmware 5.8; the PIV and OpenPGP applets are independent but share one PC/SC lock; the go-openpgp-card library needs fixes on firmware 5.8.

## Decision

### Four stores behind one interface

| Store | Driver | Holds | Evidence of where the key lives |
|---|---|---|---|
| `software` | An encrypted file, 1Password or the OS keyring ([below](/decisions/0003-key-stores-and-the-card-layer/#the-software-store)) | Test, drill and development roots; a person's own primary | None; every record says the key can be copied |
| `piv` | piv-go | Root keys on a root card; an intermediate in a card slot | The slot's attestation certificate and the card's certificate |
| `openpgp-card` | A vendored, patched fork of go-openpgp-card | A person's daily signing subkey | The card's attestation of the key, by its own command |
| `aws-kms` | The AWS SDK | A company root; an intermediate in a KMS key | The key's description, its policy and the audit trail, read from the service |

The six steps, the plan, the checks and the records are the same for every store ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). A store is called supported only after it is proven on real hardware or a real account.

### The `piv` store and the root cards

- **Both root keys live in PIV slots, through piv-go,** and ritueel builds the OpenPGP packets itself; the card signs digests. One applet, one library, one binary, no `gpg` at run time, and attestation works the same for both keys.
- **Dedicated root cards.** A root card is used for nothing else. piv-go and `scdaemon` each open a card exclusively, so a card shared with daily `gpg` would block one or the other during a ceremony.
- **Slot map, version 1.** A table built into ritueel, versioned and written into every record. It gives each purpose one place, refuses a collision, and refuses a purpose with no place. Every slot has PIN policy always and touch policy always.

  | Purpose | Place |
  |---|---|
  | X.509 root key; it also signs the root list and the SSH CA key list | PIV slot 9c |
  | OpenPGP primary | A retired PIV slot (82 to 95), fixed when the slot map is built, and recorded |
  | Break-glass SSH CA | A retired PIV slot, fixed and recorded the same way |

  The root list and the SSH CA key list are signed by the X.509 root key because their audience, lifetime, revocation and callers are those of the root: the key whose public key hosts pin is the one that tells them which roots to pin. A cloud setup applies the same rule: the break-glass SSH CA is a key of its own in the root account.
- **Attestation of a `piv` key** is verified against the maker's current root and its full intermediate bundle, which ritueel ships in the repository with a documented refresh step and a test that fails when a card's chain does not verify. piv-go's built-in list is not used. A card whose intermediate is missing is refused until the bundle is refreshed.

### The `openpgp-card` store and personal OpenPGP

- **A person's daily subkey is born on the card's OpenPGP applet,** so `gpg` and `scdaemon` use it directly. The card makes the subkey and its back-signature; an offline software primary makes the binding. It is the same hand-off as a service's subkey, with the person's card as the requester.
- **The driver is a vendored, patched fork of go-openpgp-card behind a small interface.** The fork carries the supported-algorithm fix, writes the correct ECDSA fingerprint to the card with PUT DATA, verifies the user PIN in each process, and adds the attestation command (`80 FB 01 00` on a YubiKey). The fallback is a small driver of our own on go-iso7816, and after that `scdaemon`.
- **Attestation of an `openpgp-card` key** chains to the maker's root through its OpenPGP intermediate. Until the encoding of its extensions is measured, ritueel records the key as attested and enforces no PIN or touch policy from it.

### The software store

The `software` store has three backends, chosen when the root is made ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)). The key is generated in memory and written directly into the backend, never to a file on disk. The formats and the limits of each backend are in [the software store](/reference/software-store/).

- **An encrypted file,** protected by a passphrase: the default for drills and tests, and the home of a person's own primary, which stays offline ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)).
- **1Password,** a persistent home for the software keys of test roots, intermediates and subkeys, reached through its `op` command line. Its sync is redundancy against loss, not against compromise: whoever unlocks the vault has the key. It is never the home of a production root or of a person's master key.
- **The OS keyring,** through `github.com/zalando/go-keyring`, with a warning in the creation output and in every record that it can be insecure and has no copy. ritueel refuses to fall back to a file when no keyring exists.

### What a store can prove decides what it may hold

The stores give three kinds of evidence, and the kind sets the work a store may do. The teaching page is [What a key store can prove](/learn/what-a-store-can-prove/).

| Evidence | Stores | What it shows | May hold |
|---|---|---|---|
| **Attested** | `piv`, `openpgp-card` | A chain to the maker's root says the key was made inside this device, with this firmware and these policies. | Roots, intermediates and subkeys. |
| **Read from the service** | `aws-kms` | The key's description, policy and audit trail, read from the service every time. Not that it was made in an HSM. | Roots, intermediates and subkeys. |
| **None** | `software` and its backends; a token that cannot attest | Nothing about where the key lives. | Test roots, drills, development; a person's own primary, in the encrypted file only. Intermediates and subkeys only where `policy.stores` lists the store. Never a root that others rely on. |

`init` and `root add` refuse a hardware or cloud root that cannot be attested or read, as [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-roots-at-init) says. A store with no evidence is the `software` store, marked as copyable in every record.

### Planned stores

Google Cloud KMS, Azure Key Vault and other hardware such as Nitrokey are planned ([issue #67](https://github.com/truvity/ritueel/issues/67), [issue #66](https://github.com/truvity/ritueel/issues/66)). A store is admitted, and called supported, when all of these hold, and not before:

1. **A real installation needs it** (principle 8): a real account or a real device, not an imagined one.
2. **A dated research page measures it:** a P-384 signature over a SHA-384 digest, the evidence it gives and how it is checked, how a second process or machine reaches it, what a replica or a backup is, and what a reset or a deletion does.
3. **Its evidence kind is stated,** which fixes what it may hold. A token that cannot attest holds no root.
4. **It passes the tagged tests of its kind** on a real device or account, selected by serial or by test account.
5. **The site compares it** on [Where a key lives](/learn/key-stores/) and a guide walks the transition into it.

Whether a new token joins `piv` or `openpgp-card` or stands alone is decided after step 2, with a line here or a record of its own.

### Rules for every store

- **SHA-384 on every backend.** A KMS P-384 key signs only 48-byte SHA-384 digests, and one hash makes a card, a KMS key and a file behave alike.
- **ritueel stores the OpenPGP creation time of every key it makes or binds.** The creation time fixes the fingerprint and is on no card; for a KMS key it is kept as a key tag and in every published certificate.
- **A KMS key is read by ritueel, never taken from a claim.** A key in another account is read through a read-only role in that account, which its owner creates, because `GetKeyPolicy` does not work across accounts ([the hand-off contract](/reference/hand-off-contract/#aws-kms)).
- **The OpenPGP packets are built with ProtonMail/go-crypto,** with a small bypass that plugs a card or KMS signer into its signing path. The version is pinned, and a test builds a certificate with a software signer and runs `gpgv`, `sqv` and a tampered control through it.

## Consequences

- A new store is a driver behind one interface; the cost is an interface to keep stable and a real-device test for each store.
- ritueel owns two things it would rather not: the attestation bundle, refreshed when the maker adds an intermediate, and a fork of a one-maintainer card library. Fixes are offered upstream and not awaited.
- The holder keeps at least three cards: two root cards and a daily card. The daily card's OpenPGP applet is never touched by a root ceremony.
- The directory is part of every key's identity, because it holds the creation times; it has to be backed up ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)).
- A go-crypto upgrade is a reviewed change with its signer test, not a routine bump.

## Roads not taken

- **Go builds the packets and `gpg-agent` signs on the card.** It worked in the spike, but needs `gpg` at run time, and `gpg` 2.2 sent two wrong PINs to a test card.
- **A Rust helper with `openpgp-card` and rPGP.** It did every step in the spike, but adds a second language and a helper to sign and ship, for a memory-safety gain that is gone when keys are born on the card.
- **Own PC/SC code for the OpenPGP applet of the root cards.** Keeps that applet in use, but means applet code to write and keep, on a binding last pushed in 2024.
- **The upstream go-openpgp-card as it is.** Nothing to maintain, but it needs three fixes on firmware 5.8 and has had no functional commit since December 2024.
- **A person's daily subkey in a PIV slot.** One applet for every key, but `gpg` reads the OpenPGP applet, so the key would not be usable day to day.
- **One card for the roots and daily `gpg`.** Fewer objects, but the shared PC/SC lock, a PIN prompt per operation in shared mode, and one reset that affects both.
- **A third key to sign the root list.** Separates list signing from certificate signing, but costs a slot and a touch on each card for a key with the same audience, lifetime and revocation.
- **Upstream a signer API to go-crypto, or write the packets ourselves.** Removes the bypass, but waits on review or adds security-critical code to keep; the pinned, tested bypass is enough.
- **Exporting a key from a card or KMS for backup.** An easy restore, but a key that was copied out can be stolen from the copy. Backup means two cards, or a KMS replica ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)).
- **A different ceremony for each store.** Each keeps its own shape, but plan, confirmation, records and refusals would be written and taught four times.
- **A slot map the holder edits.** Fits an odd card, but turns a collision into a user error that overwrites a key.

## Follow-ups

- The touch-policy test at a card: touch always across a ceremony with several signatures, through piv-go ([#11](https://github.com/truvity/ritueel/issues/11)).
- Measure the encoding of the `openpgp-card` attestation extensions, then read its PIN and touch policy ([#18](https://github.com/truvity/ritueel/issues/18)).
