# 0002 — A key is born in its store and never leaves it; a key file opens with a passkey on each root card

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. Key stores sit behind one ceremony, as drivers behind one interface: first software, piv, openpgp-card and aws-kms. A store is called supported only after it is proven on real hardware or a real account.
2. Every key is born in the store that holds it and never leaves it. Nothing is imported, except for a person's own key: an existing primary adopted as a software key, and an encryption subkey made in software and loaded onto day-to-day cards. An adopted cloud key is not an import, because it was born in the service.
3. ritueel never keeps a private key outside the store that made it (except as in rule 2), and keeps no PIN or passphrase a person types. It never retries a PIN, and reads one only from the terminal, without echo. The holder keeps PINs in a password manager, one entry per card.
4. A software key is generated in memory and written directly into its store, never to a plain file on disk.
5. Attested stores (piv, openpgp-card) and aws-kms may hold roots, intermediates and subkeys. Stores with no evidence (software; a token that cannot attest) may hold test roots, drills, development and a person's own primary (encrypted file only), and intermediates and subkeys only where policy.stores lists the store.
6. No root that others rely on exists in software or in any store with no evidence. The software store serves test roots, drills, development, the first consumer's harness and a person's own primary. Every record says it can be copied. A software root never anchors a signed release.
7. The software store has three backends, chosen at creation: encrypted file, 1Password (op) and OS keyring (go-keyring). The last two are planned.
8. The encrypted key file is the default backend, the home of drills, tests and a person's own primary (offline). It is a copy by nature; its backup is encrypted copies, which are more copies.
9. 1Password (op) is a home only for the software keys of test roots, intermediates and subkeys. Its sync is redundancy against loss only; it is never the home of a production root or a person's master key.
10. The OS keyring backend is offered with a warning (creation output, every record, the site) that it can be insecure and has no copy. ritueel refuses to fall back to a file when no keyring exists.
11. The default key algorithm is P-384, always with SHA-384 on every backend. RSA-4096 is allowed per key.
12. ritueel offers three custody modes for a root: a software key in an encrypted age file (opened by a passkey or a passphrase), a pair of root cards with card-born keys, and one cloud KMS key with a replica. A software root is generated in memory and written as an age file (rule 21); accepted costs: no attestation, the key in memory at each ceremony, a copy that may go unnoticed.
13. Redundancy protects against loss, not compromise, so the number of root keys follows the store. No hardware security module is used.
14. ritueel never exports a key from a card or KMS: backup means two independent cards or a KMS replica.
15. A key that can be copied (a test root, a person's primary, any software key) is replaced at the latest after three years (NIST SP 800-57 cryptoperiod).
16. Key material on a card or in a cloud KMS, a root included, is replaced only on an event, with no calendar: an advisory about the device, firmware or cloud service; deprecation of its algorithm; loss or end of life of a card; a suspected compromise; a change of store or custody.
17. Accepted limit: whoever holds one root card and its PIN, or the cloud root's role, can sign things outsiders trust until that root is revoked and the update reaches them; standard tools cannot require m-of-n. A stolen card without its PIN locks after three tries. Whoever will hold a cloud root's renewal role (later, M7) can only keep alive what the bundle holds, past its lapse, until a ceremony revokes it. Whoever tricks the holder into one extra touch on the workstation gets one signature that no card logs. ritueel shows this at init.
18. Succession is the holder's organisational duty; ritueel reminds and does not enforce.
19. The break-glass SSH CA is kept as one of a root's key kinds.
20. A software key file opens by default with a passkey on each root card: a CTAP2 hmac-secret credential that stores nothing on the card, with user verification required. It unwraps the private half of an age key, the unlock key. Any one root card is enough. No PIV slot is used.
21. A key file is an age file encrypted to two recipients, the unlock key's public half and a recovery recipient. Encrypting needs no card.
22. Every card-opened key file has a recovery key: an age identity in a passphrase-protected file, apart from the cards; file and passphrase never sit together. A password manager holds a backup of the encrypted key file and the recovery passphrase, never a usable key.
23. A passphrase alone also opens a key file, for a holder without cards. It holds only the passphrase recipient, because age v1 requires an scrypt stanza to be the only stanza in the header.
24. The fallback is a key-agreement key in PIV slot 9d of each root card, made only if passkey unlocking cannot be used. If the proof of the passkey way fails, 9d is the way and nothing else here changes. It spends slot 9d and the PIV PIN that also guards the root keys.
25. A synced passkey, unlocking inside the local page, and a day-to-day card for a root-level key file are not supported as unlockers.
26. The two root cards may also unlock software keys and sealed backups, in ceremonies only.
27. Opening a key file with a passkey must work in the static (no-cgo) build.
28. Each bundle has its own unlock key and recovery key.

## Why

A card or KMS key cannot be copied, so a calendar would force a new anchor on every relying party for no gain.

## What it costs

- The bundle is no longer public material only: sealed files rest on the unlock key and the recovery key, and the unlock key's private half is in memory at each unlock.
- A lost recovery key together with both root cards means the key files cannot be opened. The guides say where the recovery file and passphrase go.

## Roads not taken

- **More key stores in the first version.** Wider reach, but every store multiplies tests and guides, and four already cover every transition shape.
- **A separate classic passphrase mode and a separate wrapped-to-cards mode.** Two named modes, but the same idea (a password against a hardware key), so they are merged into one software mode.
- **One age file with a passphrase stanza and card recipients.** One file for both ways, but the age spec forbids mixing a passphrase (scrypt) stanza with other recipients.
- **Replace every root key at most every three years, whatever its store.** One rule, but a card or KMS key cannot be copied, so the calendar forces a new anchor on every relying party for no gain.
- **Only the encrypted file for software keys.** The simplest, but one copy on one disk, so a lost laptop loses the key.
- **1Password as the home of a production root or a person's master key.** It survives a lost laptop, but whoever unlocks the vault has the key, and removing a vault member does not change its keys.
- **Importing a key into 1Password or the keyring.** It lets people bring an old key, but the key then existed outside its store.
- **The OS keyring as the default.** No setup, but the weakest option, so it is offered with a warning and not chosen for the user.
- **Exporting a key from a card or KMS for backup.** An easy restore, but a key copied out can be stolen from the copy.
- **Dropping the break-glass SSH CA.** One key kind less; proposed in review and refused.
- **A passphrase for every key file.** Nothing to build, but one typed secret on the machine at every use and no second recipient; kept for a holder without cards.
- **The age key in PIV slot 9d as the default.** No second protocol, but it spends the slot and the PIV PIN that guard the root keys; kept as the fallback.
- **A card secret that wraps each file directly, with no age key between.** No key in memory, but encrypting would need a card present, and there is no standard format.
- **Keeping the PIV age key first and the passkey as a later step.** The research advice, overruled by the maintainer's preference for the passkey as default.
- **A synced passkey as the unlocker.** Easy to have, but it puts a root-level key file behind a cloud account.
- **Unlocking inside the local page.** Friendly, but the browser would hand the secret to the page's script; the page never receives a secret, and the offline system has no browser.
- **A day-to-day card as the unlocker.** Always at hand, but carried and used every day, and it must not open a root-level file.

## Not yet proven or only proposed

- **Not yet proven.** The 1Password and keyring backends of rule 7 stay planned until both issues are done ([#59](https://github.com/truvity/ritueel/issues/59), [#60](https://github.com/truvity/ritueel/issues/60)).
- **Not yet proven.** The passkey way of rule 20 is proven on a rehearsal card at milestone M1; until then it is decided, not proven ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Not yet proven.** Opening a key file with a passkey in the static (no-cgo) build, rule 27 ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** On a card shared by two bundles, the passkey way holds one credential for each bundle ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** How the slot 9d fallback works for two bundles is open: the card has one 9d key and each bundle has its own unlock key; the earlier proposal had the bundles share the one 9d key ([#8](https://github.com/truvity/ritueel/issues/8)).

## Replaces

0001, 0002, 0003, 0004, 0007, 0008, 0015 and 0017, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
