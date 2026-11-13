# 0008 — A person uses OpenPGP as their own key, an adopted primary first and card-born primaries later

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. Every employee uses OpenPGP as a person's own key. There is no staff key and no company-side flow for it. A person's key comes before a company's roots in the build order, because it is the smaller case.
2. OpenPGP is used for root management, the same for a company and a person; for a subkey bound on a YubiKey; and for a subkey bound in the requester system for CI signing that cosign cannot cover. "Same" means the same commands and lifecycle with a different key store.
3. A person's identity is their own name and address, not a release identity.
4. A personal bundle is an ordinary bundle with `kind: personal`. A person has a bundle of their own, which never shares a history or root list with a company bundle. It has one root, of the kind OpenPGP, and no X.509 root, CA bundle, CRL, root list or SSH CA key list. It uses the same engine, the same ceremony, ceremony records and hand-off files as a company bundle: `new` makes the folder, and the first `apply` makes the primary and its revocation signatures. The personal case is a company case with the X.509 half switched off.

5. Adoption comes first, then card-born primaries. In stage one, an existing personal primary may be adopted as it is, with its history, as a software key in a key file, opened in the default way for software key files. Its ceremony record marks it as adopted. It may arrive as RSA-4096 and without an expiry, which is outside the P-384 profile until it is replaced. It gets an expiry at adoption, and is replaced within three years of adoption or moved to stage two.
6. A person's primary is certify-only, OpenPGP version 4, ECDSA P-384. It lives in the software store, in the encrypted file backend, offline. Until stage two it is not on a card, not in 1Password and not in the system keyring. The ceremony records say it can be copied. The guide says to keep two encrypted copies in different places, and the restore drill checks one.
7. Each personal subkey is bound for about 13 months and renewed by re-signing at the yearly ceremony, like an intermediate; keyring upkeep is that renewal, with the expiry warnings of status. The personal primary is valid about three years and extended at each use. A software primary is replaced at most every three years, and the guide says so before the first one is made.
8. A primary on hardware (a card) or in a cloud KMS is replaced on events, not by calendar: an advisory about the device or firmware that affects the key, deprecation of the algorithm, or loss or end of life of the card. A primary in a KMS is not served for a person.

9. Each day-to-day card gets its own set of a signing subkey and an authentication subkey, born in one ceremony on the card's OpenPGP applet, with the card as requester and the primary binding each. The signing subkey carries its back-signature. The authentication subkey serves SSH through gpg-agent. gpg and scdaemon use both directly. Copying one set to several cards is Backlog, on demand only.
10. An encryption subkey is made in software, loaded onto each day-to-day card, and kept in a wrapped backup in the bundle, because a key born on a card cannot be copied and a lost card would lose the mail it decrypted. It can be copied; the ceremony records and the guide say so. The format and command are fixed with stage one.
11. On a day-to-day card, anything done daily or more often (signing, SSH to non-production) has touch off and a PIN once per insertion. Rarer operations and production access need a touch. Every decryption needs a touch. The touch setting of each key is the holder's choice, and the guide says what each choice costs.
12. A passkey for an employer's sign-in may live on a person's own day-to-day card.
13. The openpgp-card store is a vendored, patched fork of go-openpgp-card behind a small interface. It holds a person's day-to-day signing and authentication subkeys and the encryption subkey loaded from software. Its evidence is the card's own attestation command (80 FB 01 00 on a YubiKey). The fork carries the supported-algorithm fix, writes the correct ECDSA fingerprint with PUT DATA, verifies the user PIN in each process and adds the attestation command. ritueel owns the fork and the attestation bundle; fixes are offered upstream and not awaited.

14. A lost card is answered by the primary, which revokes the subkey and binds a new one. The primary's own revocation signatures are for the day the primary is lost.
15. A replaced subkey is retired by a revocation with the reason "superseded", dated on the day of the switch, or by expiry; "compromised" is for compromise only. Leftover software-only subkey sets are left to expire. What verifiers do with the signatures of a retired subkey is in [a dated research note](../research/openpgp-subkey-retirement-2026-11-10.md).
16. Changing an identity is a ceremony like any other. A person edits the wanted user IDs: one to add, or an old one to retire. `apply` then makes a new self-certification for the new user ID and gives the old user ID a revocation that says it is no longer valid. The fingerprint and all trust stay. For a person's own key it is in the milestone of a person's key (M3).

17. The output is the person's public certificate as binary and armoured files, to import into gpg. ritueel can send it to the listed keyservers and prints how to add it to a code host ([record 0011](0011-publishing-and-what-to-do-after-a-ceremony.md)). No package is built. A person with no card can run a personal bundle for a drill, with the subkey in software, as a test.

## Why

A person is the smallest case of the root ritual, so it shares the engine and comes first. A card cannot be copied and has no backup, so the primary stays in a file and the cards hold subkeys that the primary can replace. Adoption keeps the history that contacts have certified under the person's own name. The profiles are in the [personal OpenPGP reference](/reference/personal-openpgp/) and the wanted files in the [bundle page](/reference/bundle/); the card layouts are in the [cards reference](/reference/cards/).

## What it costs

- An adopted primary may be outside the P-384 profile for up to three years.
- The software primary can be copied: the guide must teach two copies, and the drill checks one.
- Replacing a software primary costs every contact; the guide must say so first.
- The encryption subkey exists outside the card.
- ritueel owns a fork and the attestation bundle, and keeps both.
- Every subkey is renewed yearly, with the advisory review at the same ceremony.

## Roads not taken

- **Make a new primary at once and drop the old one.** Nothing is imported, but every contact certifies again and the history is lost.
- **Adopt the key and keep it forever, with no expiry.** It is the least work, but a copyable key with no end is what the three-year rule exists to prevent.
- **The primary on a card.** It cannot be copied, but a card has no backup and a lost primary is a lost identity; stage two answers it with a standby primary.
- **The primary in 1Password or the system keyring.** It is convenient, but whoever unlocks the vault, or any program of the user once the keyring is unlocked, has the master key.
- **A separate tool for personal keys.** Each tool is smaller, but the ceremony, the ceremony records and the checks are written twice.
- **A release identity for a person.** It is a name that outlives the person, but a person's key is certified by contacts under their own name.
- **A day-to-day subkey in a PIV slot.** One applet serves every key, but gpg reads the OpenPGP applet, so the key would not be usable day-to-day.
- **The day-to-day subkey generated in software and moved to the card.** It is the usual practice and gives a backup, but the key would have existed outside its key store.
- **Signing subkey only.** It is the least code, but a person who wants SSH through gpg-agent would make that subkey by hand, outside the ceremony record.
- **An encryption subkey born on each card.** Nothing is imported, but a lost card loses the mail it decrypted.
- **An encryption key kept only in a file, not on the cards.** No copy is on a card, but every decryption needs the file opened.
- **The primary lives until an event, whatever its key store.** It is what most people do, but a copyable file ages unobserved and the replace path is exercised only by accident.
- **Replace every primary at most every three years, whatever its key store.** It is one rule, but it forces a new key on a card that cannot be copied, at every contact's cost.
- **Replace a primary every six years.** It halves the cost, but the number is invented and no standard gives it.
- **A new key and a new fingerprint for a new address.** The simplest, but the fingerprint and its trust would be lost.
- **Retire the old user ID as compromised.** The usual wording, but a user ID no longer valid is not a compromise; the reason says what happened.
- **The new address typed as the confirmation.** It names the change, but a second thing to type breaks the one confirmation; the person types the first eight characters of the plan's digest and nothing more ([record 0005](0005-a-ceremony-and-where-it-runs.md), rule 9).
- **Retire a replaced subkey as "compromised".** It is the simplest wording, but it states a compromise that did not happen, and verifiers treat it more harshly.
- **The upstream go-openpgp-card as it is.** There is nothing to maintain, but it needs three fixes on firmware 5.8 and has had no functional commit since December 2024 as of 2026-11.

## Not yet proven or only proposed

- **Not yet proven.** Stage two (decided, not built, M6, after the card proofs): one card-born primary on each root card, in the personal bundle's row; one published, the other a standby that it certifies, both keys of the person's one OpenPGP root ([record 0001](0001-what-ritueel-is.md), rule 29); the old key vouches for the published one with an overlap ([record 0007](0007-changing-and-losing-a-root.md)) ([#204](https://github.com/truvity/ritueel/issues/204)).
- **Proposed.** The plan certifies the new user ID, makes it primary and revokes the old one (rule 16); non-ASCII characters show as U+XXXX; the list of next steps ends with publishing ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Who owns the user IDs and when they are applied: whether a user ID is wanted once for the root and counts as applied when every active primary has certified it, or is wanted for each primary; and how an old user ID is marked to retire in the wanted file ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** Where an existing personal primary is imported and where its expiry is signed is not decided: [record 0005](0005-a-ceremony-and-where-it-runs.md), rule 22, uses a key that can be copied only in the offline system ([#18](https://github.com/truvity/ritueel/issues/18)).
