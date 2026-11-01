---
title: Where a key lives
description: Software, a PIV card, an OpenPGP card or AWS KMS as the home of a key. What each protects against, what each costs, and how a root moves between them.
sidebar:
  order: 3
---

*Design phase: this page teaches the trade-offs. The first version of ritueel supports exactly these four key stores ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/)). The measurements behind it are in [Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/).*

A key has to live somewhere. The places ritueel supports differ in one question above all: **can the key be copied?**

## The four stores

| | Software (`software`) | PIV card (`piv`) | OpenPGP card (`openpgp-card`) | AWS KMS (`aws-kms`) |
|---|---|---|---|---|
| Where the key is | A file, encrypted with a passphrase, on a disk you control. | A PIV slot of a hardware token, such as a YubiKey. The key is made on the token and cannot be read out. | The OpenPGP applet of a card. The key is made on the card and cannot be read out. | A cloud service. The key is made in the service and cannot be exported; you ask the service to sign. |
| Can it be copied? | Yes. Anyone who has the file and the passphrase has the key, and a backup is a copy. | No. Loss of the token is loss of the key. | No. Loss of the card is loss of the key. | No, but the service can keep a replica in another Region. Loss of the account is loss of the key. |
| What "present" means | The passphrase. | Physical possession, the PIN, and a touch on the token. | Physical possession and the PIN (a touch, if the card asks). | Cloud permissions, plus what you add: a role that needs multi-factor authentication, a key policy that names one actor. |
| Proof of where it lives | None. You are asked to believe it. | An attestation certificate from the token, chaining to the maker's published root. | An attestation certificate from the card's own command, chaining to the maker's published root. | The key's description and policy, read from the service, and the audit trail of each use. |
| Failure you plan for | The file is stolen or copied. | The token breaks or is lost. | The card breaks or is lost. | The account is locked, the key is scheduled for deletion, a Region is unavailable. |
| In ritueel it holds | Test, drill and development roots; a person's own primary. | The root keys on the root cards; a service's intermediate in a card slot. | A person's daily signing subkey, used by `gpg`. | A company root; a service's intermediate. |

One ceremony serves all four: it makes a key in a store, or binds a key a store holds, and only the store and the consumer of the key differ.

## The trade-offs in plain words

**Software is the easiest to start and the easiest to lose.** It is the right store for a drill, a test root and a development setup, and for the first consumer's test harness, which needs a root on day one. It is the wrong store for a root others rely on, because a copy leaves no trace. Real roots are born in their store, on a card or in KMS; no real root starts in software and moves later. A software root never anchors a signed release.

**A PIV card makes the key physical.** The key is generated on the token, so it never exists in your computer's memory, and a thief needs the token, its PIN and a touch. The token can attest the key: it hands out a certificate, signed under the maker's published root, saying that a key in a given slot was made inside this token, with this firmware and this PIN and touch policy. Imported keys cannot be attested. While a token is unlocked, other programs on the same computer can use it, so the computer is part of the trust boundary during a ceremony. A token has no backup, which is why there are two root cards.

**An OpenPGP card holds a person's daily key.** A person's signing subkey is born on the card's OpenPGP applet, so `gpg` uses it directly, and an offline software primary binds it. The PIV and OpenPGP applets of one card are independent, but a program that holds the card keeps the others out, so the root cards are dedicated and the daily card is another card.

**AWS KMS makes the key a permission.** The key is as safe as the account's access control, and every use is in the audit trail. There is no card to lose, but an account to lose, and a deletion that is reversible only for a waiting period. A root that is "present" because a role was assumed is weaker than a touch unless the role is hard to assume, so ritueel gates the role with multi-factor authentication and has the person confirm the plan. ritueel reads the key's description, policy and public key from the service itself, never from a claim; for a key in another account, through a read-only role that the owner creates in that account. Two details matter for OpenPGP: a P-384 KMS key signs only SHA-384 digests, and the OpenPGP creation time that fixes the fingerprint is not KMS's own, so ritueel stores it.

A company root in KMS is **one root and a multi-Region replica, in one dedicated root account** ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). A company that wants a root that does not depend on one provider adds a card root.

## Choosing

| If | Then |
|---|---|
| You are learning, or testing a pipeline | Software, on a throw-away root, with a drill. |
| One person or a small team holds the roots, and no cloud is involved | Two independent root cards, in two places. |
| A person wants a daily OpenPGP key | A subkey born on an OpenPGP card, bound by a software primary kept offline. |
| An organisation already runs on AWS and wants audited, policy-gated roots | One KMS root with a multi-Region replica, in a dedicated root account, with a role that needs multi-factor authentication. |
| You want the strongest story | Roots on different kinds of store: for example a card root and a KMS root. A failure of one kind does not take out the other. |

## Moving between stores

Every move is a transition ([Roots, intermediates and transitions](/concepts/roots-and-transitions/)): create the new root in the new store, vouch for it from the old one, overlap, supersede. What differs is what you gain and what you check.

| From | To | What changes | What to check |
|---|---|---|---|
| Software (a drill or a test setup) | PIV card | The key stops being copyable. | The new root is attested, and the chain verifies against the maker's root. |
| Software (a drill or a test setup) | AWS KMS | The key moves under cloud access control and audit. | The key's policy names one actor, and the role needs multi-factor authentication. |
| PIV card | AWS KMS | A physical key becomes a permission. | The confirmation step still needs a person. |
| AWS KMS | PIV card | A permission becomes a physical key. | A second card exists in another place before the first is relied on. |
| Same kind to same kind | Replacement of a token, or a KMS key in another account | Nothing in principle; the key is new. | The overlap is long enough for slow clients. |

There are no key copies in this table, on purpose. A transition never moves a key; it makes a new one and has the old one vouch for it, so a store that cannot export a key is never a problem.

Each transition will have its own guide, with a drill on test keys. They arrive with the tools; the [roadmap](/roadmap/) has the order.
