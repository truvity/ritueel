# 0015 — Key files open with a passkey on each root card, and card secrets are sealed in the bundle

**Status:** Accepted
**Date:** 2026-11-11

## Context

A software key lives in an encrypted key file ([0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store); [the software root's key files](/reference/bundle/#the-software-roots-key-files)). Until now the file is encrypted to one passphrase, typed at the terminal for every ceremony, and the holder keeps card PINs, PUKs and admin PINs in a password manager ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-yearly-ceremony), [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards)). Two things are weak.

- One passphrase is one secret to lose, and one secret to type on a machine at every use. An age file with a passphrase recipient cannot also have another recipient, so a second way in needs a different design.
- A management key that the card releases to the PIN lets anyone who holds the card and the PIN replace a key in a slot. [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards) accepted that.

The root cards are always present at a ceremony, so they can do the unlocking. The proposal is the design round of 2026-11-10 and 11, tracked in the issues under Follow-ups. Part of this record is decided but not yet proven on hardware: the last heading of the Decision says which part and what happens if the proof fails.

## Decision

### The key file

- **The default way to open a key file is a passkey on each root card.** The key file is an age file encrypted to two recipients: the public half of an age key (the unlock key) and a recovery recipient.
- **A passkey on each root card unwraps the private half of the unlock key.** The passkey is a CTAP2 hmac-secret credential, the kind that stores nothing on the card, with user verification required. The extension is defined in [CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html), section 12.5; how it behaves on a YubiKey over USB is what the proof below tries. Any one root card of the pair is enough.
- **Encrypting a key file needs no card,** because the unlock key's public half is a recipient. This way uses no PIV slot.
- **A recovery key always exists:** an age identity kept in a passphrase-protected file, apart from the cards. The recovery file and its passphrase never sit in the same place.

### Other ways to open it

- **Supported: a passphrase alone,** for a holder without cards. A passphrase file holds only that recipient, because the age v1 specification says "An scrypt stanza, if present, MUST be the only stanza in the header" (read 2026-11-11, [age v1](https://age-encryption.org/v1)).
- **Fallback: a key-agreement key in PIV slot 9d of each root card** (row 1 of the card, [0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-rows)), made only if passkey unlocking cannot be used.
- **Not supported:** a synced passkey; unlocking inside the local page; a day-to-day card unlocking a root-level key file.

### Card secrets

- **When ritueel adopts a card,** it replaces the management key by a random one that needs a touch to use, and seals it in the bundle, one file per card, to the same recipients as the key file. A card that two bundles use is sealed in each of them, to that bundle's own recipients; the unlock key and the recovery key are each bundle's own.
- **The PUK is random and sealed the same way.** So is the Admin PIN of the OpenPGP application on a day-to-day card.
- **The holder remembers only the PINs the holder types.** This replaces "the management key is PIN-protected" of [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards) for cards that ritueel adopts.

### Decided, not yet proven

- **To be proven on a rehearsal card before the store is built (milestone M1):** a passkey secret with PIN and touch over USB, from a static binary, and that the offline system of [0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#where-a-root-card-is-used) reaches the card's passkey side, and that one root card holds a passkey credential for each bundle that uses it (the credential is the non-resident kind, so the card stores nothing per bundle). Until then this part is decided, not yet proven.
- **If the proof passes,** the passkey is the default as above. **If it fails,** the PIV slot 9d key-agreement key is the way for a holder with root cards, and nothing else in this record changes. Both outcomes are decided here, so the proof is a follow-up and not an open part.
- **The format of the wrapped key** is fixed by the proof and then written on [the software store](/reference/software-store/) and [the bundle](/reference/bundle/). This record fixes no file layout.

## Consequences

- The bundle is no longer public material only. It holds sealed files, and their safety rests on the unlock key and the recovery key. The records and pages that say "public only" say so ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-bundle-and-the-records), [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#an-opinionated-bundle)).
- The unlock key's private half is in memory at each unlock.
- ritueel reaches the card's passkey side as well as its PIV side. How, and that it works in a static binary, is what the proof shows.
- A lost recovery key together with both root cards means the key files cannot be opened. The guides say where the recovery file and its passphrase go.
- The holder types fewer secrets: PINs only. The PUK and the management key stop living in a password manager.
- The fallback spends slot 9d and uses the PIV PIN that also guards the root keys. The slot 9d key is one for each card, so bundles that share a pair would then share one unlock key.
- Test roots and scripts are unchanged ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#software-roots-and-tests)).

## Roads not taken

- **A passphrase for every key file.** Nothing to build, but one typed secret on the machine at every use and no second recipient; kept as the option for a holder without cards.
- **The age key in PIV slot 9d as the default.** No second protocol, but it spends a slot and the PIV PIN that guard the root keys; kept as the fallback.
- **A card secret that wraps each file directly, with no age key in between.** No key in memory, but encrypting would need a card present and there is no standard format; not chosen.
- **A synced passkey as the unlocker.** Easy to have, but it puts a root-level key file behind a cloud account.
- **Unlocking inside the local page.** Friendly, but the browser would hand the secret to the page's script, and the page never receives a secret ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#the-wizards-security-rules)); the offline system has no browser.
- **A day-to-day card as the unlocker.** A card is always at hand, but a day-to-day card is carried and used every day and must not open a root-level file.
- **A typed or PIN-protected management key ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards)).** One secret fewer, but a thief with the card and the PIN could replace a root key; the random touch-protected key sealed in the bundle removes that.
- **PUK and Admin PIN kept in a password manager.** Nothing to seal, but a person has to type and keep a secret that the tool can generate.

## Follow-ups

- Prove the passkey secret on a rehearsal card, then fix the key-file format and the unlock in the software store ([#8](https://github.com/truvity/ritueel/issues/8)).
- Adopt a card: replace and seal the management key and the PUK, and fix the sealed-file format ([#11](https://github.com/truvity/ritueel/issues/11)).
