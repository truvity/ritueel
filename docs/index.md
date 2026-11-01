---
title: "ritueel: manage the root of your PKI and the master key of OpenPGP"
description: ritueel teaches how to keep a PKI root and an OpenPGP master key safe, and gives tools that simplify the ceremonies, while you stay in charge. Open source.
template: splash
hero:
  tagline: Keep the root of your PKI and the master key of OpenPGP smoothly and safely. Learn the logic first; the tools simplify the rituals.
  actions:
    - text: Start learning
      link: /learn/
      icon: right-arrow
    - text: The custody chain
      link: /learn/custody-chain/
      variant: secondary
    - text: View on GitHub
      link: https://github.com/truvity/ritueel
      icon: external
      variant: minimal
---

## Our mission

> ritueel teaches people to manage the root of a PKI and the master key of OpenPGP smoothly and safely, and gives them tools that simplify each ritual, from creating a root to signing intermediates and subkeys onto cards, while the person stays in charge.

Almost everything built on keys hangs from a few keys that are used rarely: the root of a certificate hierarchy, the master key of an OpenPGP identity. Using them is a manual ritual, a *ceremony*, done by a person, and most people do it once or twice in their life. ritueel exists to make that experience smooth and safe.

Three promises follow from the mission:

1. **This site teaches first.** It explains the logic of handling root keys and intermediates, in plain words, for a reader who is technically capable and new to PKI. Start with [Learn](/learn/).
2. **The tools simplify the rituals; they do not replace the person.** A command line, and a wizard that runs on your own computer only. Nothing irreversible happens without your confirmation, and the touch and the PIN stay on the card.
3. **Help for the whole life of a root,** not only its birth: where the record of what you did lives, how to back it up and restore it, when to re-sign and when to rotate, how to revoke, and what to do when a card is lost. See [the life of a root](/learn/life-of-a-root/).

## Where to start

| If you want to | Read |
|---|---|
| Understand what a root is and why it is kept offline | [What is a root?](/learn/what-is-a-root/) and [Why the root stays offline](/learn/why-the-root-stays-offline/) |
| See who holds which key, from the root down to the leaf | [The custody chain](/learn/custody-chain/) |
| Choose where a key will live | [Where a key lives](/learn/key-stores/) |
| Follow a root from birth to retirement | [The life of a root](/learn/life-of-a-root/) |
| Do something now | [Guides](/guides/) |
| Know what the tools do today | [Tools](/tools/) |

## Keys in a store

A key has to live somewhere. ritueel compares the places openly: software (an encrypted file, 1Password, or the operating system's keyring), a YubiKey (PIV or OpenPGP card) and AWS KMS today; Google Cloud KMS, Azure Key Vault and other hardware such as Nitrokey are planned. [Where a key lives](/learn/key-stores/) says what each one protects against and what it costs.

## Status

ritueel is in the **design phase**. There is no release yet. The [decision records](/decisions/) are accepted, the learning pages and the [hand-off contract](/reference/hand-off-contract/) are written, and the [roadmap](/roadmap/) lists the milestones of the first version. The command line and the wizard are [planned](/tools/); every page says what is built.

ritueel is a separate product from [sluis](https://sluis.id), which holds intermediates and signs online. The two do not depend on each other and exchange standard formats only.

How to take part is in [Contributing](/contributing/).
