---
title: Prepare a root card
description: Set the PIN of a new hardware token with the maker's tool, then let ritueel adopt it so that it is accepted as a root card, and check the result.
sidebar:
  order: 0.5
---

*These steps use `ykman`, the YubiKey Manager command line, which exists today (commands checked against ykman 5.8.0 on 2026-11-02). ritueel does not set the PIN you type: it checks the result and refuses a card that is not ready. It then adopts the card, which replaces the PUK and the management key with random ones sealed in the bundle ([record 0003](../decisions/0003-root-cards.md)). The read-only check and the inventory come with M2; card adoption and the `piv` store with M6 ([issue #11](https://github.com/truvity/ritueel/issues/11)). Do this on a rehearsal card first. The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

A new token ships with a PIN, a PUK and a management key that everyone knows. With the management key, anyone who holds the token can put their own key in a slot; with the default PIN, anyone can use a key. A root card must not leave the box like that. This guide sets the PIN, and nothing else; ritueel's adoption of the card changes the other two, as the steps say. Why the cards are dedicated and why there are two is in [Two roots in practice](/learn/two-roots/). A pair may serve up to four bundles of the same holder ([record 0003](../decisions/0003-root-cards.md)); how the rows are handled is on the [card page](/reference/cards/#a-pair-shared-by-bundles), with some details still proposed.

## What you start with

- A new token with firmware 5.7.4 or later, which is ritueel's floor for a root card ([record 0003](../decisions/0003-root-cards.md)), bought to hold roots and nothing else ([Which keys to buy](/learn/which-keys-to-buy/)). It is never also a day-to-day card or a server card.
- `ykman` on your workstation, and no other program holding the card: stop `scdaemon` first (`gpgconf --kill scdaemon`).
- Your password manager open, with an entry for this card.

## Steps

1. **Look at the card.** `ykman list`, then `ykman piv info`. Result: the serial number and the firmware version. Put the serial in the password-manager entry's title, so you can tell two cards apart. A new card also prints `WARNING: Using default PIN!` and the same for the PUK and the management key.
2. **Change the PIN.** `ykman piv access change-pin`. It asks for the current PIN and the new one. Choose a PIN you will not forget and others will not guess, and put it in the entry. Result: the warning for the PIN is gone.
3. **Leave the PUK and the management key.** Do not change them with `ykman`. Adoption by ritueel (planned; the command name `ritueel card adopt` is proposed) replaces both with random keys, makes the management key need a touch to use, and seals them in the bundle, so you keep neither. Result: `ykman piv info` still warns about the PUK and the management key until the card is adopted.
4. **Check, and close.** `ykman piv info` shows that the PIN warning is gone. Put the card in its place. Result: a card that ritueel will adopt, and then `ritueel init`.

## How you know it worked

- `ykman piv info` shows no "default" warning for the PIN. After ritueel adopts the card it shows none for the PUK and the management key either.
- Three PIN tries remain.
- The card holds no key and no certificate in any slot you did not put there: a root card starts empty.

## When something goes wrong

- **A wrong PIN is typed.** Stop. Do not guess: three wrong tries block the PIN, and then the PUK is needed. The PUK is sealed in the bundle, and ritueel opens it.
- **The card is blocked.** The sealed PUK unblocks the PIN (`ykman piv access unblock-pin`), not a PUK you typed. If the PUK is also blocked, the PIV applet can only be reset, which destroys every key in it. On a card with no key yet that costs nothing.
- **ritueel says the card is held.** Another program has it. Close it, or stop `scdaemon`.
- **ritueel says the management key is not the sealed one** (`management-key-unsealed`). The card was not adopted by ritueel, or a management key was set by hand. A card that holds no root yet can be adopted again; a card that holds roots is never reset.

## Drill

Run it on a spare token that will never hold a real root. End the drill by resetting the PIV applet (`ykman piv reset`) so the card is back in factory state, and check that `ykman piv info` warns again. The next guide is [Adopting the roots](/guides/root-adoption/).
