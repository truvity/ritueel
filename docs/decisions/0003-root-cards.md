# 0003 — Roots live on two independent root cards laid out as six rows of four slots

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. The root is two independent root cards, A and B. Each generates its own keys; they are never copies. One holder operates both and keeps them in two places. They are redundancy, not two-person control.
2. Every key has its PIN rule and touch rule stated; root keys have both always. A touch rule is fixed at birth.
3. The 24 PIV slots are taken four at a time as six rows. Row 1 is the card's own jobs: 9a and 9c empty, 9d a spare unlocking key made only if passkey unlocking cannot be used, 9e never used. Rows 2 to 6 are each one root of one bundle; a root has an X.509 root key, an OpenPGP primary and a break-glass SSH CA key (fewer if it has fewer kinds; a personal root has only the primary). The X.509 root key also signs the root list and the SSH CA key list. A root's row number is in its record. Details: [cards reference](/reference/cards/).
4. The slot map is built into ritueel, versioned (version 1), written into every record, and not edited by the holder. It gives each purpose one place and refuses a collision or a purpose with no place. A checked copy is in the requester system.
5. Each card holds its own root of every bundle on the pair, in rows 2 to 6 shared by all bundles. One row stays free on each card for a replacement born beside the old root, so a card holds at most four roots: four bundles on a pair. More roots need another pair.
6. One pair may serve more than one bundle of the holder. Each bundle keeps its own card list and its own copy of the card secrets, sealed to its own recipients. The card has one PIN, one PUK and one management key for all its bundles; a sealed copy out of step shows as check 7, `management-key-unsealed`.
7. A second bundle cannot adopt the cards again. It gets its sealed copy by a request to the first bundle, which wraps the secrets for it; they never travel in the clear. Request and answer are detachable; with both bundles and the cards at hand, ritueel chains the steps. The record names the serial, never the other bundle.
8. A row of another bundle of the holder is declared in the card's file. An undeclared occupied row is a finding.
9. PIN, PUK and management key are changed from factory values before any key is born. The holder sets each root card's PIN with the maker's tool. ritueel reads whether they are still factory values and refuses if so, never guesses a PIN to find out, and refuses a card that cannot report them.
10. Adoption replaces the management key by a random one that needs a touch, and seals it in the bundle (one file per card, to the key file's recipients); nothing else is accepted for a root card. The PUK, and a day-to-day card's OpenPGP Admin PIN, are random and sealed the same way. The holder remembers only the PINs typed.
11. A card that holds real roots is never reset; a half-born key is removed by deleting that one slot. A used root slot carries a placeholder certificate that tools looking for empty slots skip.
12. A read-only check compares the whole card with the built-in layout and reports anything not the layout's own.
13. The firmware floor for a root card is 5.7.4: ritueel's rule; older firmware cannot hold a root.
14. A card has one of four kinds and never changes it. Root: holds roots by row; adopted; used on the workstation or in the offline system by the rules of the ceremony record. Day-to-day: a person's signing and authentication subkeys and passkeys; adopted. Server: stays plugged into a requester's server and signs for its services; an ordinary card, not an HSM product, named "server"; ritueel lists it and only reads it: no adoption, no secret changed or sealed, no layout check. Rehearsal: for practice and tests; never holds a real key, may be reset, serves only a test root; the M1 proofs and drills use it.
15. A root card is never also a server, day-to-day or rehearsal card; a day-to-day card is never also a requester card. The holder keeps at least three cards: two root cards and a daily card. A root ceremony never touches the daily card's OpenPGP applet.
16. The one-time-code (OTP) application is switched off on adopted root and day-to-day cards, and may be on a rehearsal card.
17. Attestation of a piv key is verified against the maker's current root and an attestation bundle of intermediates, shipped in the repository with a refresh step and a test that fails when a chain does not verify. piv-go's built-in root list is not used. A card with a missing intermediate is refused until the bundle is refreshed; `--extra-intermediates` may supply it as a helper only, and it must chain to the pinned root. An openpgp-card key's attestation chains to the maker's root through its OpenPGP intermediate.
18. The bundle holds a card inventory: one file lists the cards this bundle uses, for its own rows, and one file per card maps every slot of its applications to its use. ritueel writes both from the read-only check; nobody edits them. A serial is never reused for another holder's role.
19. The piv store uses piv-go and holds root keys on a root card and an intermediate in a card slot; its proof is the slot's attestation certificate and the card's certificate. ritueel builds the OpenPGP packets and the card signs digests; no gpg at run time.
20. If the PIN was accepted in the same session and the card refused after 10 seconds or more, ritueel reports that no touch was given in time or PIN state was lost; a sooner refusal is reported as a refusal. It claims no more than it knows and does not retry.

## Why

Each card makes its own keys, so no copy exists and each key can be attested at birth.

## What it costs

- The PIN, PUK and management key are the card's, so three wrong PINs lock the roots of every bundle on it.
- A lost card is one revocation or transition in each bundle.
- No bundle sees the whole card.

## Roads not taken

- **One root, one card, a spare.** The spare is a copy or nothing a verifier trusts.
- **Off-card key imported into both.** No card can attest its birth.
- **Software key wrapped, or split 2-of-2.** In memory at each signing; a split stops signing if one card is lost.
- **HSM pair with a wrapped export.** About EUR 786 a device (checked 2026-10-29), and the key is copied.
- **Two holders, or a remote one.** Either card alone signs, so separation is procedural, and each ceremony waits on a person.
- **One pair per bundle.** A holder with two bundles keeps four cards.
- **Pair per bundle until a later milestone.** A shared pair was chosen.
- **Home bundle holding the sealed file.** A second bundle could not be used without it.
- **Holder-level card file.** A new structure above the bundle.
- **Rows by purpose.** A root's keys scatter, and a replacement cannot be born beside the old one.
- **Third key signing the root list.** A slot and a touch per card, for the same audience, lifetime and revocation.
- **Holder-edited slot map.** A collision becomes a user error that overwrites a key.
- **Typed or PIN-protected management key.** A thief with card and PIN could replace a root key, or a second secret is kept.
- **Default management key.** Anyone with the card could replace a root key.
- **PUK and Admin PIN in a password manager.** A person keeps a secret the tool can generate.
- **Second bundle opens the first one's sealed file.** Both bundles are needed and the secret is in the clear.
- **Master key in plain text.** Refused outright.
- **No placeholder certificate.** Tools looking for empty slots would offer to overwrite a root key.
- **Card reset for a half-born key.** It destroys every other root on the card.
- **Two kinds of card only.** A server's card and a practice card would have no honest place.
- **Server card managed like a root card.** Its slots belong to the requester; adoption would break the service.
- **Names "hsm" and "board".** "hsm" names a product class this design rejects; "board" was the first name, and another was asked for.
- **Test root only in a file.** Proofs and drills need a real card.
- **One card for the roots and daily gpg.** A shared PC/SC lock, a PIN prompt per operation, one reset for both.
- **Role-block allocation of cards.** It was rejected.
- **Signing on the card with gpg-agent.** It needs gpg at run time; gpg 2.2 sent two wrong PINs to a test card.
- **Rust helper with openpgp-card and rPGP.** A second language and a helper to ship.
- **Own PC/SC code for the OpenPGP applet.** Applet code to keep, on a binding last pushed in 2024.
- **OTP application left on.** The card answers to a secret nobody tracks.

## Not yet proven or only proposed

- **Not yet proven.** On Linux the card is reached by direct USB (CCID) in ritueel, tried first; a pure-Go pcscd client is the fallback; macOS is for planning only, with no card access. To be tried on a spare real card ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Not yet proven.** At a card: touch always holds across a ceremony with several signatures through piv-go, and reading the factory-value report spends no PIN try. On a rehearsal card in M1: deleting one slot works on firmware 5.7.4, and how other tools treat a placeholder certificate ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Not yet proven.** Until the encoding of the openpgp-card attestation extensions is measured, ritueel records the key as attested and enforces no PIN or touch policy from it ([#18](https://github.com/truvity/ritueel/issues/18)).
- **Proposed.** A declared row of another bundle is not a failure; a key outside the layout still fails with `card-layout`; the plan takes the lowest empty row; another bundle's slot is listed as "use: other-bundle" with its row, no key hash. The severity of an undeclared occupied row, and whether it blocks a ceremony or sets an exit code, are open ([#11](https://github.com/truvity/ritueel/issues/11)).

## Replaces

Parts of 0002, 0003, 0004, 0008, 0012, 0015 and 0016, read at commit 1634be413c5e7d8d173e421928665ba30971a46e.
