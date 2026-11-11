# 0016 — Several bundles share one pair of root cards, and the bundle keeps a card inventory

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) makes a root card "used for nothing else", and [the card reference](/reference/cards/) says one card holds one role. Slot map version 1 puts the X.509 root in slot 9c and the other keys in retired slots "fixed when the slot map is built". A holder with a company and a personal key keeps two bundles ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-bundle-and-the-records)) and wants one pair of cards for both; a personal root has only an OpenPGP primary, a company root also an X.509 key and a break-glass SSH CA key.

A PIV application has 24 key slots (9a, 9c, 9d, 9e and the retired slots 82 to 95). That is enough for several roots on one pair if every place is fixed. [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#keys) keeps its rule: the second card is redundancy, and the two cards are independent and never copies. The proposal is the design round of 2026-11-10 and 11, tracked in the issues under Follow-ups.

The four kinds of card, where a plan runs and the relaxed mode for tests are decided here. The third kind is called `server`, because `board` was not wanted and `hsm` names a product class that [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) rejects. The offline system also binds a real software root. The relaxed mode is wording only: a test root may run on the workstation and on a rehearsal card, with no flag.

## Decision

### The rows

- **One pair of root cards may hold roots of more than one bundle, all of one holder.** The 24 PIV key slots are taken four at a time, in the order 9a, 9c, 9d, 9e, then 82 to 95. That makes six rows.
- **Row 1 is the card's own jobs:** 9a empty; 9c empty; 9d a spare key-agreement key for unlocking, made only if passkey unlocking cannot be used ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#other-ways-to-open-it)); 9e never used.
- **Each of the five rows below it is one root of one bundle,** with the same kind of key in the same column: column 1 the X.509 root key, column 2 the OpenPGP primary, column 3 the break-glass SSH CA key, column 4 left empty. A root with fewer kinds of key leaves its other cells empty; a personal root has only an OpenPGP primary.
- **A root's row number is written in its record.** The map is built into ritueel and versioned (slot map version 1, rewritten in place); the holder does not edit it.
- **Five root rows per card are shared by all bundles on the pair.** One row stays free on each card, so that a replacement can be born beside the old root ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)); so at most four roots stand on a card at once.

### Rules for a shared card

- **The PIN, PUK and management key are changed from the factory values before any key is born.** The holder changes the PIN; ritueel's adoption of the card replaces the PUK and the management key ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)).
- **Every key is made with its PIN rule and its touch rule stated.** For root keys both are always.
- **A used root slot carries a placeholder certificate,** so that tools which look for empty slots skip it.
- **A read-only check compares the whole card with the built-in layout** and reports anything that is not the layout's own. How a row held by another bundle of the same holder is reported is proposed in [the card reference](/reference/cards/#a-pair-shared-by-bundles).
- **A card that holds real roots is never reset.** A half-born key is removed by deleting that one slot. The firmware floor for a root card is 5.7.4. That is ritueel's rule; that deleting one slot works there is tried on a rehearsal card in M1. Yubico documents a delete-key action for YubiKey 5.7 or higher (read 2026-11-11, [yubico-piv-tool, delete-key](https://developers.yubico.com/yubico-piv-tool/Actions/key_delete.html)).
- **A root card is never also a server card or a day-to-day card, and never a rehearsal card.**

### The inventory

- **The bundle holds an inventory of cards.** One file lists every card the holder registered: name, serial (the operator's own data), kind, model, firmware, and which applications are in use. It is `cards.yaml`, extended. One file per card maps every slot of its PIV, OpenPGP and FIDO2 applications to its use. For a used slot it gives the purpose, the root it belongs to, the algorithm, the PIN rule and the touch rule, the hash of the public key, the date of birth and the attestation file. The formats are in [the card reference](/reference/cards/).
- **ritueel writes both from the read-only check. Nobody edits them by hand.**
- **Bundles that share a pair each keep their own copy.** Each bundle keeps the card list for the cards it uses, and its own sealed copy of the card secrets ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)); the same serial is in both lists. A second bundle cannot adopt the card again, because adoption replaces the PUK and the management key and the first bundle's sealed copy would stop working; how it gets its own copy is proposed in [the card reference](/reference/cards/#a-pair-shared-by-bundles). The PIN, the PUK and the management key are the card's, so three wrong PINs lock the roots of every bundle on that card; and a lost card is one revocation or transition in each bundle that has a root on it.
- **A card has one of four kinds,** and never changes it:
  - `root`: holds roots by row; adopted; used in the offline system only.
  - `day-to-day`: a person's signing and authentication subkeys and passkeys; adopted.
  - `server`: a card that stays plugged into a server of a requester system and signs for its services. It is an ordinary card, not a hardware security module product ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). ritueel lists it in the inventory and only ever reads it. Its slots follow the requester's own layout, so the built-in layout check does not apply; ritueel adopts nothing on it, changes no secret and seals none.
  - `rehearsal`: practice and tests. It never holds a real key and may be reset; the M1 proofs and the drills use it. It serves only a test root.

### Where a root card is used

- **A root card goes only into a machine booted from a read-only system made for the purpose (the offline system),** never into the everyday system. The plan holds public information only, so it can be made anywhere and carried over as a saved plan file ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)).
- **The one-time-code (OTP) application is switched off** on the root and day-to-day cards that ritueel adopts. On a server card ritueel changes nothing; on a rehearsal card it may.
- **A card check and a proof of life run every six months.** The card check is the read-only comparison above. The proof of life is a short test that the card still works for its holder; its exact steps are written in the card reference when the check is built.

### Where a plan runs

| Root | Where its ceremonies run |
|---|---|
| Card root, and real software root (a key file, for example a person's own primary) | The offline system. The plan can be made anywhere and carried over as a saved plan file, so the USB-stick step is shown only here. |
| Cloud root | Your workstation, with no stick. |
| Test root | See the next bullet. |

- **A test root (`--test-root`) may run its ceremonies on the workstation and on a rehearsal card, so that tests stay fast.** Its key is a file with no passphrase, or lives on a rehearsal card, and its certificate name, records and products say `TEST ONLY` and refuse to mix with real roots. A rehearsal card serves only a test root, and a real root never becomes a test root: `test` is written when the root is born and never changes. ritueel checks nothing about the machine it runs on, for any root; the offline system is the holder's rule, taught and not enforced. The relaxed mode is these words and nothing else: there is no flag.

## Consequences

- "One card holds one role" and `role: root:A` in the card reference become a card that holds roots by row. Slot map version 1 and the retired-slot sentence of 0003 are replaced by the rows. Each root record gains its row.
- A shared pair costs a duplicated card list and duplicated sealed secrets in each bundle, and no bundle sees the whole card.
- One set of PIN, PUK and touches serves all bundles on a card; the six-monthly check is run for each bundle and covers its own rows.
- A holder with more than four roots on a card buys another pair.
- A card with a placeholder certificate in every used slot no longer looks empty to other tools. That is the intent.
- The offline system costs a boot for every card or real software-root ceremony. It replaces the "ordinary workstation" of [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-yearly-ceremony). A cloud root is unaffected, and so is a test root.
- Firmware older than 5.7.4 cannot hold a root.
- The six-monthly check adds work and gives early notice of a dead card between yearly ceremonies. The restore drill stays yearly ([0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/#drills)).

## Roads not taken

- **One pair of cards per bundle.** The simplest, but a holder with a company bundle and a personal bundle buys and keeps four cards, and every extra card is a place to lose one.
- **A map the holder edits.** It fits an odd card, but it turns a collision into a user error that overwrites a key ([0003](/decisions/0003-key-stores-and-the-card-layer/) already refused it).
- **Rows by purpose instead of by root (all X.509 roots first, then all primaries).** Fewer rows for one root, but a root's keys would be scattered and a replacement could not be born beside the old one as a unit.
- **A card reset to clean up a half-born key.** Simple, but it destroys every other root on the card; deleting one slot does not.
- **No placeholder certificate.** No extra step, but tools that look for empty slots would offer to overwrite a root key.
- **Using the root card in the everyday system.** No boot, but the card is exposed to everything that system runs; [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) weighed an air gap and saw no gain for the friction, and the read-only system is the middle course.
- **Leaving the OTP application on.** Nothing to switch off, but the card then answers to a second kind of secret that nobody tracks.
- **Two kinds only (root, day-to-day).** Fewer words, but a server's card and a practice card would have no honest place and would be forced into "day-to-day".
- **ritueel manages the server card like a root card.** One rule for all, but its slots belong to the requester, and a ritueel layout check or adoption would break the service.
- **A flag that turns the offline rule off.** Faster tests, but the program checks nothing about the machine, so a flag would only relax a rule that nothing enforces, and `--test-root` already marks everything `TEST ONLY`; the maintainer chose wording only, with no flag.
- **Call the third kind `board` or `hsm`.** `board` was the first name and was not wanted; `hsm` names a product class that [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) rejects for the roots, and a server card is an ordinary card; `server` was chosen.
- **Let a test root live only in a file.** Simplest, but the card proofs and the drills need a real card under a test root, and the rehearsal kind exists for that; a rehearsal card serves only a test root, so a real root cannot be born on it.
- **A card check only at the yearly ceremony.** One rhythm, but a dead card would show only at the next ceremony, up to a year later.
- **Several roots of different trust domains in one bundle.** Cards live once, but it needs a second layer between the bundle and the root and mixes a person's files with a company's ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-bundle-and-the-records)).
- **A home bundle that holds the card's one sealed file.** One copy, but a second bundle could not be used or handed over without the first.
- **A holder-level card file shared by bundles.** One inventory, but a new structure above the bundle.
- **A pair of cards belongs to one bundle until a later milestone.** Nothing to build now, but the maintainer chose that bundles may share a pair.

## Follow-ups

- Build the slot-map rows, the placeholder certificates, the read-only check and the inventory files, and test them on a rehearsal card, including the deletion of one slot on firmware 5.7.4 and the way other tools treat a placeholder certificate, then the adoption of a pair by a second bundle and the card check run for each bundle ([#11](https://github.com/truvity/ritueel/issues/11)).
- Add the six-monthly card check and proof of life to `status` ([#30](https://github.com/truvity/ritueel/issues/30)).
