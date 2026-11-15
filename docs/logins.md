---
title: "I protect my own logins."
description: "Two YubiKeys guard the few top accounts and 1Password holds the rest. ritueel, a program for root keys, is not needed here."
template: splash
tableOfContents: false
prev: false
next: false
flow: landing
---

## The pain

- A stolen password could open my accounts.
- If I lose one device, I could be locked out.

## What to do

- Two YubiKeys guard your 1Password, main mail and Apple or Google accounts. Put a [passkey](/learn/how-passkeys-work/#passkeys-in-brief) on both.
- 1Password, a password manager that syncs passkeys, holds one for every other site. This is the default.
- Backup: a one-time code (TOTP) in 1Password, where a site has no passkey or asks for a second way in. An account is as strong as its weakest way in.

## What not to do

- One YubiKey alone: one loss locks you out.
- SMS or mail codes: weak. A password alone: unsafe.
- Do not keep a root key or an OpenPGP primary key in 1Password.

## What ritueel does for you

No ritueel tool is needed for your own logins. This page gives you advice instead.

---

**ritueel: a command-line program for root keys. Design phase, no release yet.**

Built today: [the list of commands](/reference/cli/#built-so-far).

**[Read how passkeys work](/learn/how-passkeys-work/#passkeys-in-brief)**

## Read next

- [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/)
- [Keys from zero](/learn/what-is-a-root/#keys-from-zero)
- [Learn](/learn/)

[Status of this case](/status/#case-5) · [All cases](/)
