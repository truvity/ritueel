---
title: "We log in to our servers with SSH."
description: "Keep the keys behind your SSH logins safe: your own login key, and a break-glass SSH CA key. ritueel is in its design phase."
template: splash
tableOfContents: false
prev: false
next: false
flow: landing
---

## The pain

- A copied key file would open our servers, and we would not know.
- When someone leaves, we must remove their key from every host.
- Replacing our SSH CA key means a visit to every host.

## What to do

- Use an [SSH CA](/learn/chain-ssh/#an-ssh-ca): a person joins or leaves without a change on every host.
- Keep the daily SSH CA key in the system that issues certificates.
- Keep the break-glass (emergency) SSH CA key in a [cloud key](/learn/how-a-kms-key-works/) (ritueel support planned, [M4](/roadmap/)). Or keep it on two [root cards](/how-it-works/cards/#root-card) (ritueel support planned, [M6](/roadmap/)).
- For your own login key, use 1Password with its SSH agent. Or use a day-to-day card (ritueel support planned, [M3](/roadmap/)).

M3, M4 and M6 are milestones on the [roadmap](/roadmap/).

## What not to do

- A break-glass [key in a file](/learn/a-key-in-a-file/), Vault or OpenBao: it can be copied.
- One card alone: no second key.
- A plain key file for your own login: a copy takes your key.

## What ritueel does for you

ritueel will keep a signed list of the CA keys your hosts trust. It also plans each use of the break-glass key. It does not issue SSH certificates.

---

**ritueel: a command-line program for root keys. Design phase, no release yet.**

Built today: [the list of commands](/reference/cli/#built-so-far).

**[Read the SSH chain](/learn/chain-ssh/)**

## Read next

- [Revoke](/learn/revoke/)
- [How a KMS key works](/learn/how-a-kms-key-works/)
- [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/)

[Status of this case](/status/#case-4) · [All cases](/)
