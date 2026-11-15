---
title: "We run our company's private CA."
description: "Keep the root of your private CA safe, in a cloud key or on two root cards. ritueel is a command-line program in its design phase."
template: splash
tableOfContents: false
prev: false
next: false
flow: landing
---

## The pain

- We renew certificates once a year and must find out again how.
- We cannot say today what our root has signed.

## What to do

- Keep the root in a cloud key with a copy in a second region (ritueel support planned, [M4](/roadmap/)).
- Or keep it on two root cards (ritueel support planned, [M6](/roadmap/)).

M4 and M6 are milestones on the [roadmap](/roadmap/).

## What not to do

- A real root in a key file, Vault or OpenBao: it can be copied.
- One card alone: no second key.

## What ritueel does for you

ritueel will plan each ceremony; a person confirms it. HSMs and AWS Private CA roots are not covered.

---

### Next to what you already run

| Tool | Answers |
|---|---|
| YubiKey, cloud key | Where the key is kept. |
| <span class="nb">Vault, OpenBao, step-ca</span><br><span class="nb">AWS Private CA</span> | Who issues certificates every day. |
| Script, wiki page | How it was done. |
| ritueel (planned) | The rare root ceremony, checked and recorded. |

Aim: in three years, another person repeats the ceremony, and the history will show what was signed.

---

**ritueel: a command-line program for root keys. Design phase, no release yet.**

Built today: [the list of commands](/reference/cli/#built-so-far).

**[See a ceremony in pictures](/how-it-works/#sign-an-intermediate)**

## Read next

- [Private PKI](/learn/chain-private-pki/)
- [How a KMS key works](/learn/how-a-kms-key-works/)
- [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/)

[Status of this case](/status/#case-1) · [All cases](/)
