---
title: What a key store can prove
description: How to tell that a root key really lives where you are told, by an attestation chain, a policy read from a cloud service, or nothing, and what each allows.
sidebar:
  order: 12.2
---

*Design phase: this page teaches the model. The checks it describes are planned for M2 ([issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12)); the rule they follow is in [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold).*

Someone tells you a root key is "safe on a hardware token", or "in the cloud, locked down". How would you know? A claim is not evidence, and a root is the one key where being wrong is expensive. This page is about what each kind of store can show, so you can tell a claim from a proof.

It sits in the middle of [the custody chain](/learn/custody-chain/): the question "where does this key live?" is answered here, and the ceremony that asks it is in [What a ceremony is](/learn/ceremonies/).

## Three kinds of evidence

| Kind | Example | What it shows | What it does not show |
|---|---|---|---|
| **Attested** | A YubiKey's PIV or OpenPGP applet | A certificate chain, ending at the maker's published root, says: this key was made inside this device, this firmware, with this PIN and touch policy. | That the maker is honest, or that the computer in front of you is. |
| **Read from the service** | AWS KMS | You ask the service for the key's description and its policy, and read who is allowed to sign. The audit trail records every use. | That the key was made in a hardware module: the service gives no such statement. |
| **None** | A key file, a password manager, the system keyring, a token that cannot attest | Nothing. The key could have been made anywhere, and copied anywhere. | Everything. |

## Why a key made elsewhere can be told apart

A key that was *imported* into a token can be copied before it went in. A key *generated* on the token cannot, because it never existed outside. The token signs a statement about the second kind only: an imported key has no attestation, which is how you tell them apart. That is why ritueel never imports a key ([principle 1](/principles/)) and why a root whose key cannot be attested is refused.

The chain is checked against the maker's root, which ritueel carries and refreshes ([the bundle](/reference/cards/#the-attestation-bundle)), and never against a certificate the token or the requester hands over by itself: a root inside the evidence is not trusted ([principle 4](/principles/)). If the chain cannot be checked, ritueel reports that the check did not run. It never reports it as passed.

## What the cloud gives instead

A cloud key service cannot attest where its key was made, but it can tell you, truthfully and every time you ask, who may use the key. For a root, ritueel reads three things from the service and compares them with what it expects: the key's description (its type, its Region, that it is enabled), its policy (that exactly one role may sign, and only with multi-factor authentication), and its replica. If the policy changed since the last ceremony, you are shown the change before you confirm anything ([The cloud root](/reference/kms-root/)).

## What the kind allows a store to hold

| Kind | May hold |
|---|---|
| Attested | Roots, intermediates and subkeys. |
| Read from the service | Roots, intermediates and subkeys. |
| None | Test roots, drills and development; a person's own key; never a root that other people rely on. |

A new device or service is judged the same way before it joins: what does it prove? A token that cannot attest has no evidence, and so holds no root, whatever else it does well ([Which keys to buy](/learn/which-keys-to-buy/#the-evidence-gap-in-plain-words) gives the example, read 2026-11-01).

## What evidence cannot fix

- **A lying workstation.** Evidence says where a key lives, not what you are about to sign. That is the job of the plan and its digest, which you read before you confirm.
- **A stolen card and its PIN.** The key is where it should be, and in the wrong hands. Revocation answers that ([Revoke](/learn/revoke/)).
- **The maker.** You trust the maker's root, as you trust any root. Compare it, pin it, and refresh it by reviewed change.

## Drill

On two test cards, make a key on one and import a key into a slot of the other with the maker's tool. Ask each for its attestation certificate. Result: the first answers, the second refuses. Then run the same ceremony with ritueel on each (when `init` exists) and read the refusal.
