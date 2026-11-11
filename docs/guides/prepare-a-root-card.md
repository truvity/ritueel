---
title: Prepare a root card
description: Set the PIN of a new hardware token with the maker's tool, then let ritueel adopt it so that it is accepted as a root card, and check the result.
sidebar:
  order: 0.5
---

*These steps use `ykman`, the YubiKey Manager command line, which exists today (commands checked against ykman 5.8.0 on 2026-11-02). ritueel does not set the PIN you type: it checks the result and refuses a card that is not ready. It then adopts the card, which replaces the PUK and the management key with random ones sealed in the directory ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards), [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)). The read-only check and the inventory come with M2; card adoption and the `piv` store with M6 ([issue #11](https://github.com/truvity/ritueel/issues/11)). Do this on a rehearsal card first.*

A new token ships with a PIN, a PUK and a management key that everyone knows. With the management key, anyone who holds the token can put their own key in a slot; with the default PIN, anyone can use a key. A root card must not leave the box like that. This guide sets the PIN, and nothing else; ritueel's adoption of the card changes the other two, as the steps say. Why the cards are dedicated and why there are two is in [Two roots in practice](/learn/two-roots/).

## What you start with

- A new token with firmware 5.7.4 or later, which is ritueel's floor for a root card ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#rules-for-a-shared-card)), bought to hold roots and nothing else ([Which keys to buy](/learn/which-keys-to-buy/)). It is never also a day-to-day card or an HSM card.
- `ykman` on your workstation, and no other program holding the card: stop `scdaemon` first (`gpgconf --kill scdaemon`).
- Your password manager open, with an entry for this card.

## Steps

1. **Look at the card.** `ykman list`, then `ykman piv info`. Result: the serial number and the firmware version. Put the serial in the password-manager entry's title, so you can tell two cards apart. A new card also prints `WARNING: Using default PIN!` and the same for the PUK and the management key.
2. **Change the PIN.** `ykman piv access change-pin`. It asks for the current PIN and the new one. Choose a PIN you will not forget and others will not guess, and put it in the entry. Result: the warning for the PIN is gone.
3. **Leave the PUK and the management key.** Do not change them with `ykman`. `ritueel card adopt` (planned) replaces both with random keys, makes the management key need a touch to use, and seals them in the directory, so you keep neither. Result: `ykman piv info` still warns about the PUK and the management key until the card is adopted.
4. **Check, and close.** `ykman piv info` shows that the PIN warning is gone. Put the card in its place. Result: a card that `ritueel card adopt` will accept, and then `ritueel init`.

## How you know it worked

- `ykman piv info` shows no "default" warning for the PIN. After `ritueel card adopt` it shows none for the PUK and the management key either.
- Three PIN tries remain.
- The card holds no key and no certificate in any slot you did not put there: a root card starts empty.

## When something goes wrong

- **A wrong PIN is typed.** Stop. Do not guess: three wrong tries block the PIN, and then the PUK is needed. The PUK is sealed in the directory, and ritueel opens it.
- **The card is blocked.** The sealed PUK unblocks the PIN (`ykman piv access unblock-pin`), not a PUK you typed. If the PUK is also blocked, the PIV applet can only be reset, which destroys every key in it. On a card with no key yet that costs nothing.
- **ritueel says the card is held.** Another program has it. Close it, or stop `scdaemon`.
- **ritueel says the management key is not the sealed one** (`management-key-unsealed`). The card was not adopted by ritueel, or a management key was set by hand. A card that holds no root yet can be adopted again; a card that holds roots is never reset.

## Drill

Run it on a spare token that will never hold a real root. End the drill by resetting the PIV applet (`ykman piv reset`) so the card is back in factory state, and check that `ykman piv info` warns again. The next guide is [Adopting the roots](/guides/root-adoption/).
