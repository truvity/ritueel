---
title: "I sign my commits and my own releases."
description: "Keep your OpenPGP primary key offline and sign with subkeys on your card. ritueel is a command-line program in its design phase."
template: splash
tableOfContents: false
prev: false
next: false
flow: landing
---

## The pain

- My OpenPGP primary key is a file on my laptop.
- A copy of that file would leave no trace.
- If my primary key were lost tomorrow, I would have no tested way back.

## What to do

- Keep your [OpenPGP primary key](/learn/chain-openpgp/) offline, in an [encrypted file](/learn/a-key-in-a-file/), away from your daily machine (ritueel support planned, [M3](/roadmap/)).
- Put a signing subkey and an authentication subkey on your [day-to-day card](/how-it-works/cards/#day-to-day-card) (ritueel support planned, [M3](/roadmap/)).
- Sign your own releases with cosign, and add OpenPGP where users need it.
- Keep two encrypted copies in different places.

M3 is a milestone on the [roadmap](/roadmap/).

## What not to do

- A primary key on one card alone: no second key.
- A primary key or subkeys as files on your daily machine.

## What ritueel does for you

ritueel will adopt your primary key and bind to it the subkeys born on your day-to-day card. It does not sign your commits: your card does that each day.

---

**ritueel: a command-line program for root keys. Design phase, no release yet.**

Built today: [the list of commands](/reference/cli/#built-so-far).

**[See how your card binds subkeys](/how-it-works/#bind-the-subkeys-of-your-card)**

## Read next

- [A key in a file](/learn/a-key-in-a-file/)
- [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/)
- [OpenPGP or Sigstore](/guides/openpgp-and-sigstore/#both-together)

[Status of this case](/status/#case-3) · [All cases](/)
