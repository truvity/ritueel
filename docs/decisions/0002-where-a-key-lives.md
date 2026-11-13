# 0002 — A key is born in its key store and never leaves it; a key file opens with a passkey on a card named for it

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. Key stores sit behind one ceremony, as drivers behind one interface: first software, piv, openpgp-card and aws-kms. A key store is called supported only after it is proven on real hardware or a real account.
2. Every key is born in the key store that holds it and never leaves it. Nothing is imported, except for a person's own key: an existing primary adopted as a software key, and an encryption subkey made in software and loaded onto day-to-day cards. An adopted cloud key is not an import, because it was born in the service.
3. ritueel never keeps a private key outside the key store that made it (except as in rule 2), and keeps no PIN or passphrase a person types. It never retries a PIN, and reads one only from the terminal, without echo. The holder keeps PINs in a password manager, one entry per card.
4. A software key is generated in memory and written directly into its key store, never to a plain file on disk.
5. ritueel never exports a key from a card or KMS: backup means two independent cards or a KMS replica.
6. Redundancy protects against loss, not compromise, so the number of root keys follows the key store. No hardware security module is used.

7. Attested key stores (piv, openpgp-card) and aws-kms may hold root keys, intermediates and subkeys. Key stores with no evidence (software; a token that cannot attest) may hold test roots, drills, development, the first consumer's harness and a person's own primary (encrypted file only), and intermediates and subkeys only where policy.stores lists the key store.
8. No root key that others rely on exists in software or in any key store with no evidence, except a person's own primary. A software root never anchors a signed release.
9. ritueel offers three kinds of key store for a root key: a software key in an encrypted age file, a card-born key on a root card, and one cloud KMS key with a replica. A software root key is written as an age file (rule 20); accepted costs: no attestation, the key in memory at each ceremony, a copy that may go unnoticed.

10. The software store has three backends, chosen at creation: encrypted file, 1Password (op) and OS keyring (go-keyring). The last two are planned.
11. The encrypted key file is the default backend, the home of drills, tests and a person's own primary (offline). It is a copy by nature; its backup is encrypted copies, which are more copies.
12. 1Password (op) is a home only for the software keys of test roots, intermediates and subkeys. Its sync is redundancy against loss only; it is never the home of a production root key or a person's master key.
13. The OS keyring backend is offered with a warning (creation output, every ceremony record, the site) that it can be insecure and has no copy. ritueel refuses to fall back to a file when no keyring exists.
14. The default key algorithm is P-384, always with SHA-384 on every backend. RSA-4096 is allowed per key.

15. A key that can be copied (a test root's key, a person's primary, any software key) is replaced at the latest after three years (NIST SP 800-57 cryptoperiod).
16. Key material on a card or in a cloud KMS, a root key included, is replaced only on an event, with no calendar: an advisory about the device, firmware or cloud service; deprecation of its algorithm; loss or end of life of a card; a suspected compromise; a change of key store or of place. The one other date is an outer limit for a root key: it is replaced at the latest 15 years after it was born. The yearly review of [record 0007](0007-changing-and-losing-a-root.md), rule 20, holds the fixed reviews of 2030 and 2035.
17. Accepted limit: whoever holds one root card and its PIN, or the cloud root's role, can sign things outsiders trust until that root key is revoked and the update reaches them; standard tools cannot require m-of-n. A stolen card without its PIN locks after three tries.
18. Succession is the holder's organisational duty; ritueel reminds and does not enforce.

19. A software key file opens by default with a passkey on each root card named to open it: a CTAP2 hmac-secret credential that stores nothing on the card, with user verification required. It unwraps the private half of an age key, the unlock key. Any one is enough; a file may name more than two. No PIV slot is used.
20. A key file is an age file encrypted to two recipients, the unlock key's public half and a recovery recipient. Encrypting needs no card.
21. Every card-opened key file has a recovery key: an age identity in a passphrase-protected file, apart from the cards. Its passphrase, the break-glass, may live in a password manager, never beside the file it protects. A password manager holds a backup of the encrypted key file and the recovery passphrase, never a usable key.
22. A passphrase alone also opens a key file, for a holder without cards. It holds only the passphrase recipient, because age v1 requires an scrypt stanza to be the only stanza in the header.
23. The fallback is a key-agreement key in PIV slot 9d of each card named to open the file, made only if passkey unlocking cannot be used. It spends slot 9d and the PIV PIN that also guards the root keys.
24. A synced passkey (a password-manager passkey is one), unlocking inside the local page and a day-to-day card for a root-level key file are not supported as unlockers. There is no password-manager unlock item; the break-glass is the recovery passphrase (rule 21).
25. The root cards named to open a key file (two or more) may also unlock software keys and sealed backups, in ceremonies only.
26. Opening a key file with a passkey must work in the static (no-cgo) build.
27. Each bundle has its own unlock key and recovery key.

## Why

- A card or KMS key cannot be copied, so a calendar would force a new anchor on every relying party for no gain.
- P-384 with SHA-384 (rule 14) is chosen for the larger security margin: about 192 bits against about 128 for P-256 (NIST SP 800-57 Part 1 Rev 5, table 2), on the largest curve that a PIV slot, the OpenPGP applet and the cloud key store all hold. It is not a defence against a quantum computer.
- The outer limit of 15 years (rule 16) is what the root programs allow: Mozilla removes the websites trust bit when a root's key material is more than 15 years old, and Chrome removes a root whose key was generated more than 15 years ago (Mozilla Root Store Policy 3.1, section 7.4; Chrome Root Program Policy 1.8, section 1.3.1.2). NIST SP 800-57 Part 1 Rev 5, section 5.3.6, recommends about one to three years of use for a private signature key; a key that cannot be copied has no such calendar, so the limit is an outer one.

## What it costs

- A root key made in 2026 reaches its outer limit in 2041, after 2035, the year from which NIST IR 8547 disallows ECDSA and EdDSA in its standards; the reviews of 2030 and 2035 ([record 0007](0007-changing-and-losing-a-root.md), rule 20) are how such a key is replaced sooner.
- The bundle is not public material only: sealed files rest on the unlock key and the recovery key, and the unlock key's private half is in memory at each unlock.
- A lost recovery key together with every card named as a way to open the file means the key files cannot be opened. The guides say where the recovery file and passphrase go.

## Roads not taken

- **More key stores in the first version.** Wider reach, but every key store multiplies tests and guides, and four already cover every transition shape.
- **A separate classic passphrase mode and a separate wrapped-to-cards mode.** Two named modes, but the same idea (a password against a hardware key); there is one software mode.
- **One age file with a passphrase stanza and card recipients.** One file for both ways, but the age spec forbids mixing a passphrase (scrypt) stanza with other recipients.
- **No outer limit.** The simplest rule, but nothing would ever call for the replacement of a root key that no event touched, and the root programs end a root at 15 years.
- **P-256 for every key.** Faster (a signature about 15 times, measured with OpenSSL 3.5.5) and read by the widest set of verifiers, but it gives up the 192-bit level, and a root signs only a few times a year, so the speed gains nothing.
- **Replace every root key at most every three years, whatever its key store.** One rule, but a card or KMS key cannot be copied, so the calendar forces a new anchor on every relying party for no gain.
- **Only the encrypted file for software keys.** The simplest, but one copy on one disk, so a lost laptop loses the key.
- **1Password as the home of a production root or a person's master key.** It survives a lost laptop, but whoever unlocks the vault has the key, and removing a vault member does not change its keys.
- **Importing a key into 1Password or the keyring.** It lets people bring an old key, but the key then existed outside its key store.
- **The OS keyring as the default.** No setup, but the weakest option, so it is offered with a warning and not chosen for the user.
- **Exporting a key from a card or KMS for backup.** An easy restore, but a key copied out can be stolen from the copy.
- **A passphrase for every key file.** Nothing to build, but one typed secret on the machine at every use and no second recipient; kept for a holder without cards.
- **The age key in PIV slot 9d as the default, or first with the passkey as a later step.** No second protocol, but it spends the slot and the PIV PIN that guard the root keys; kept as the fallback.
- **A card secret that wraps each file directly, with no age key between.** No key in memory, but encrypting would need a card present, and there is no standard format.
- **A synced or password-manager passkey as the unlocker, or as an extra way next to the cards.** Easy, but it puts a root-level key file behind a cloud account and adds nothing the recovery passphrase kept in the manager does not give; a key file is opened in the offline system, which has no network, manager or browser, so a passphrase can be typed there and a passkey cannot.
- **Unlocking inside the local page.** Friendly, but the browser would hand the secret to the page's script; the page never receives a secret, and the offline system has no browser.
- **A day-to-day card as the unlocker.** Always at hand, but carried and used every day, and it must not open a root-level file.
- **A and B as two roots of one kind.** Simple to say, but the word root would keep three meanings and could not name one root with a key on a card and a key in the cloud; a root is built from keys in any place ([record 0001](0001-what-ritueel-is.md), rule 29).

## Not yet proven or only proposed

- **Not yet proven.** The 1Password and keyring backends of rule 10 stay planned until both issues are done ([#59](https://github.com/truvity/ritueel/issues/59), [#60](https://github.com/truvity/ritueel/issues/60)).
- **Not yet proven.** The passkey way of rule 19 is proven on a rehearsal card at milestone M1; until then it is decided, not proven. If the proof fails, the slot 9d fallback (rule 23) is the way and nothing else here changes ([#200](https://github.com/truvity/ritueel/issues/200)).
- **Not yet proven.** Opening a key file with a passkey in the static (no-cgo) build, rule 26 ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** On a card shared by two bundles, the passkey way holds one credential for each bundle ([#8](https://github.com/truvity/ritueel/issues/8)).
- **Proposed.** How the slot 9d fallback works for two bundles is open: the card has one 9d key and each bundle has its own unlock key ([#8](https://github.com/truvity/ritueel/issues/8)).
