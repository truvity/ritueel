---
title: Where a key lives
description: Software, a YubiKey or AWS KMS as the home of a root key. What each protects against, what each costs, and how a root moves from one to another.
sidebar:
  order: 2
---

*Design phase: this page teaches the trade-offs. The first version of ritueel supports exactly these three key stores. Claims about firmware and service behaviour were checked on 2026-10-31 and 2026-11-01; check again before you rely on one.*

A root key has to live somewhere. The three places ritueel supports differ in one question above all: **can the key be copied?**

## The three stores

| | Software | YubiKey | AWS KMS |
|---|---|---|---|
| Where the key is | A file, encrypted with a passphrase, on a disk you control. | A hardware token. The key is made on the token and cannot be read out. | A cloud service. The key is made in the service and cannot be exported; you ask the service to sign. |
| Can it be copied? | Yes. Anyone who has the file and the passphrase has the key, and a backup is a copy. | No. Loss of the token is loss of the key. | No. Loss of access to the account or the key is loss of the key. |
| What "present" means | The passphrase. | Physical possession, the PIN, and a touch on the token. | Cloud permissions, plus whatever you add: a role that needs multi-factor authentication, a key policy that names one actor. |
| Proof of where it lives | None. You are asked to believe it. | An attestation certificate, signed by the maker, chaining to the maker's published root. | The key's description and policy, read from the service; the service's audit trail shows each use. |
| Speed | Fast. | A few signatures a second (about 7 a second with P-384, measured 2026-10-31 on one model); roots need a handful a year. | A network call per signature. |
| Failure you plan for | The file is stolen or copied. | The token breaks or is lost. | The account is locked, the key is scheduled for deletion, the region is unavailable. |
| Good for | Learning, drills, test roots, and the first bootstrap before anything else exists. | Roots held by a person or a small team, without a cloud dependency. | Roots in an organisation that already runs on that cloud and wants its access control and audit. |

## The trade-offs in plain words

**Software is the easiest to start and the easiest to lose.** It is the right store for a drill, for a test root and for the first version of anything. It is the wrong store for a root you expect others to rely on for years, because a copy leaves no trace. ritueel still supports it, and treats it as the first store, because every other store is reached by a transition *from* software, and because a system that needs a certified intermediate on day one needs a root that exists on day one. A software root never anchors a signed release: no release is signed until the card roots exist.

**A YubiKey makes the key physical.** The key is generated on the token, so it never exists in your computer's memory, and a thief needs the token, its PIN and a touch. The token can attest the key: it hands out a certificate, signed by a key the maker's published root vouches for, saying that a key in a certain slot was made inside this token, with this firmware, with this touch and PIN policy. Imported keys cannot be attested. Two measured facts that matter in practice (2026-10-31, firmware 5.8):

- Attestation certificates chain to the maker's *new* root, not the older one that earlier firmware used. A verifier that has only the old root rejects them.
- A verifier also needs the maker's *intermediates*. piv-go v2.6.0's built-in list lacks the one that firmware 5.8 uses, so its `Verify` fails (measured 2026-11-01). ritueel passes the maker's current root and the full intermediate bundle to the verifier and refreshes the bundle by a documented step.
- While a token is unlocked, other programs on the same computer can use it. Treat the computer as part of the trust boundary during a ceremony.
- The PIV and OpenPGP applets of a token are independent, but the connection to the card is one lock: a program that holds it (`gpg`'s `scdaemon`, or ritueel) keeps the other out. A separate card for roots avoids the problem; see [the ceremony](/concepts/ceremonies/#one-card-one-lock).

A token has no backup. That is why the model asks for more than one independent root.

**AWS KMS makes the key a permission.** The key is as safe as the account's access control, and every use is in the audit trail. There is no card to lose, but there is an account to lose, and a deletion that is only reversible for a waiting period. A root that is "present" because a role was assumed is weaker than a touch unless you make the role hard to assume. ritueel's answer is to gate the role with multi-factor authentication and to let the person confirm the use, so that the cloud key behaves like a card with a touch. KMS keys do not attest in the YubiKey sense; ritueel reads the key's description and policy instead, and records both, and the audit trail shows each use. That is the whole evidence for a KMS key: description, policy and audit trail. For a key in another account, the owner grants ritueel read access to the key's description, and ritueel reads the public key from the service itself; it does not accept a copy of either.

Two facts about OpenPGP keys in KMS (measured 2026-11-01). A P-384 KMS key signs only 48-byte SHA-384 digests, so every P-384 OpenPGP signature uses SHA-384, on every store, and a SHA-256 or SHA-512 digest is refused. The OpenPGP creation time is part of the fingerprint, and KMS's own creation date is not it; ritueel stores the time it chose, as a tag on the key and in the published certificate, because without it the same KMS key yields a different fingerprint.

A KMS root has the same rule as a card root: **two roots, independent.** A company setup has a second KMS root in a separate account, as the model has two cards. A multi-Region replica of a KMS key is the same key, so it adds availability and not independence; a lost account, a deleted key or a stolen role takes every copy. Whether each root gets an account of its own is not decided yet.

## Choosing

| If | Then |
|---|---|
| You are learning, or testing a pipeline | Software, on a throw-away root, with a drill. |
| One person or a small team holds the roots, and no cloud is involved | Two independent YubiKey roots, in two places. |
| An organisation already runs on AWS and wants audited, policy-gated roots | Two AWS KMS roots with an MFA-gated role, the second in a separate account, or at least one root on a different store, so that a lost account does not strand your clients. |
| You want the strongest story | Roots on different kinds of store: for example one YubiKey and one KMS key. A failure of one kind does not take out the other. |

## Moving between stores

Every move is a transition ([Roots, intermediates and transitions](/concepts/roots-and-transitions/)): create the new root in the new store, vouch for it from the old one, overlap, supersede. What differs is what you gain and what you check.

| From | To | What changes | What to check |
|---|---|---|---|
| Software | YubiKey | The key stops being copyable. | The new root is attested, and the attestation chain verifies against the maker's published root. Destroy the old file only after the supersede. |
| Software | AWS KMS | The key moves under cloud access control and audit. | The key's policy names one actor and the role needs MFA. The old file is destroyed after the supersede. |
| YubiKey | AWS KMS | A physical key becomes a permission. | The confirmation step still involves a person. Keep one non-cloud root. |
| AWS KMS | YubiKey | A permission becomes a physical key. | A second YubiKey exists in another place before the first is relied on. |
| Same kind to same kind | Replacement of a token, or a KMS key in another account | Nothing in principle; the key is new. | The overlap is long enough for slow clients. |

There are no direct key copies in this table, on purpose. A transition never moves a key; it makes a new one and has the old one vouch for it. That is why a key store that cannot export a key is not a problem for ritueel: it never asks for one.

Each transition will have its own guide, written step by step, with a drill on test keys. They arrive with the tools; the [roadmap](/roadmap/) has the order.
