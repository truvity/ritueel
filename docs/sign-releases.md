---
title: "We sign our project's releases."
description: "Keep the OpenPGP root of your releases safe, and sign with cosign and OpenPGP together. ritueel is in its design phase."
template: splash
tableOfContents: false
prev: false
next: false
flow: landing
---

## The pain

- A key expired, and we learned it when something stopped working.
- If our root were lost tomorrow, we would have no tested way back.

## What to do

- Keep the [OpenPGP root](/learn/chain-openpgp/) in a [cloud key](/learn/how-a-kms-key-works/) (ritueel support planned, [M4](/roadmap/) and [M5](/roadmap/)).
- Or keep it on two [root cards](/how-it-works/cards/#root-card) (ritueel support planned, [M6](/roadmap/)).
- Sign with cosign together with OpenPGP, never instead: RPM and DEB need OpenPGP.

M4, M5 and M6 are milestones on the [roadmap](/roadmap/).

## What not to do

- A root [key in a file](/learn/a-key-in-a-file/): a copy leaves no trace.
- One card alone: no second key.

## What ritueel does for you

ritueel will plan each [ceremony](/glossary/); a person confirms it. It does not package or publish releases.

---

### Next to what you already run

| Tool | Answers |
|---|---|
| YubiKey, cloud key | Where the key is kept. |
| Pipeline, cosign | Who signs releases. |
| Script, wiki page | How it was done. |
| ritueel (planned) | The rare root ceremony, checked and recorded. |

Aim: in three years, another person repeats the ceremony, and a yearly drill tries recovery.

---

**ritueel: a command-line program for root keys. Design phase, no release yet.**

Built today: [the list of commands](/reference/cli/#built-so-far).

**[See the OpenPGP chain](/learn/chain-openpgp/#where-ritueel-fits)**

## Read next

- [How a KMS key works](/learn/how-a-kms-key-works/)
- [A key in a file](/learn/a-key-in-a-file/)
- [OpenPGP or Sigstore](/guides/openpgp-and-sigstore/#both-together)

[Status of this case](/status/#case-2) · [All cases](/)
