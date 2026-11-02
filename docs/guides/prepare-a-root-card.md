---
title: Prepare a root card
description: Change the PIN, the PUK and the management key of a new hardware token with the maker's tool so that ritueel accepts it as a root card, and check the result.
sidebar:
  order: 0.5
---

*These steps use `ykman`, the YubiKey Manager command line, which exists today (commands checked against ykman 5.8.0 on 2026-11-02). ritueel does not prepare a card: it checks the result and refuses a card that is not ready ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards)). The check is planned for M2 ([issue #11](https://github.com/truvity/ritueel/issues/11)). Do this on a test card first.*

A new token ships with a PIN, a PUK and a management key that everyone knows. With the management key, anyone who holds the token can put their own key in a slot; with the default PIN, anyone can use a key. A root card must not leave the box like that. This guide changes all three, once, and nothing else. Why the cards are dedicated and why there are two is in [Two roots in practice](/learn/two-roots/).

## What you start with

- A new token with firmware 5.7 or later, bought for this root and used for nothing else ([Which keys to buy](/learn/which-keys-to-buy/)).
- `ykman` on your workstation, and no other program holding the card: stop `scdaemon` first (`gpgconf --kill scdaemon`).
- Your password manager open, with an entry for this card.

## Steps

1. **Look at the card.** `ykman list`, then `ykman piv info`. Result: the serial number and the firmware version. Put the serial in the password-manager entry's title, so you can tell two cards apart. A new card also prints `WARNING: Using default PIN!` and the same for the PUK and the management key.
2. **Change the PIN.** `ykman piv access change-pin`. It asks for the current PIN and the new one. Choose a PIN you will not forget and others will not guess, and put it in the entry. Result: the warning for the PIN is gone.
3. **Change the PUK.** `ykman piv access change-puk`. The PUK unblocks a PIN that three wrong tries blocked. Put it in the entry. Result: the PUK warning is gone.
4. **Change the management key, and let the card keep it.** `ykman piv access change-management-key --protect`. With `--protect`, ykman makes a random management key and stores it on the card, released by the PIN. You never see it and do not keep it. Result: `ykman piv info` says the management key is stored on the card, protected by PIN, and no management-key warning remains.
5. **Check, and close.** `ykman piv info` once more shows no warning. Put the card in its place. Result: a card that `ritueel init` will accept.

## How you know it worked

- `ykman piv info` shows no "default" warning and says the management key is protected by the PIN.
- Three PIN tries remain.
- The card holds no key and no certificate in any slot you did not put there: a root card starts empty.

## When something goes wrong

- **A wrong PIN is typed.** Stop. Do not guess: three wrong tries block the PIN, and then the PUK is needed. Look in the password manager.
- **The card is blocked.** The PUK unblocks the PIN (`ykman piv access unblock-pin`). If the PUK is also blocked, the PIV applet can only be reset, which destroys every key in it. On a card with no key yet that costs nothing.
- **ritueel says the card is held.** Another program has it. Close it, or stop `scdaemon`.
- **ritueel says the management key is not protected.** Step 4 was skipped, or a typed management key was set. Run step 4 again.

## Drill

Run it on a spare token that will never hold a real root. End the drill by resetting the PIV applet (`ykman piv reset`) so the card is back in factory state, and check that `ykman piv info` warns again. The next guide is [Adopting the roots](/guides/root-adoption/).
