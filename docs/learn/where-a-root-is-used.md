---
title: Where a root is used
description: "Who can use a root, and on which machine a ceremony runs: a copyable key only offline, a key that cannot be copied also on a workstation under conditions."
sidebar:
  order: 3
---

*Design phase: ritueel is in design and has no release; nothing here is built ([roadmap](/roadmap/)). What the page says about ritueel is what the accepted decision records say. The offline system on a stick is decided, not yet proven, and how the program enforces the four conditions is proposed ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).*

This page answers two questions. Who can use a root at all? Nobody, in any key store, without a person present. On which machine does a ceremony run? A key that can be copied is used only in the offline system; a key that cannot be copied is used on your workstation, under four conditions; a root on cards may also be used in the offline system, and a cloud root cannot, because that system has no network. Behind the second answer is the oldest rule of PKI, "keep the root offline". It is worth knowing what that rule is for, because it has a literal form (a machine in a safe) and a practical form, and they are not the same.

## What an online key is exposed to

A key that lives on a machine connected to a network can be reached by anything that runs on that machine or can talk to it:

- malware, and a stolen or hijacked user session;
- a bug in the software that uses the key;
- someone with remote access, an insider, or a stolen backup;
- an operator who is tricked into signing something that looks routine.

A root that is online is exposed to all of them every day. A root that is used only at a planned ceremony is exposed to them for the hour a [ceremony](/glossary/) (the planned, recorded occasion on which the root is used) lasts.

## Three places for a root

| Way | What it gives | What it costs |
|---|---|---|
| **A machine in a safe, no network** | The key never touches a network. | A machine to keep alive, a live system to build for every use, a place to store it. Most people do not do this more than twice. |
| **A key that cannot leave a card** | A computer at a ceremony cannot copy the key, even if it is hostile. Possession of the card, its PIN and a touch for every signature are needed. | A card can be lost or break, so you need two. |
| **A key in a cloud service behind a role** | Nobody downloads the key. Every use is an audited call to the service, and a role gates it. A person types the plan's digest; there is no touch. | Trust in the provider and in the account. Losing the account loses the key. |

ritueel's rule has two parts. First, a root is never used without a person present: every ceremony is interactive, you type the start of the plan's digest, and a card also needs its PIN and a touch for every signature.

Second, the machine depends on whether the key can be copied ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)):

- **A key that can be copied**, a software key in a file, is used only in the offline system: a machine started from a read-only system made for the purpose (the offline system), never the everyday one. A test root is the exception.
- **A key that cannot be copied**, a root on cards or a key in a cloud service, may be used on your own workstation, under four conditions. A touch for every signature, for a root on cards only. The number of signatures stated in the plan. No retry of a failed touch. The result checked against the plan on a second device, before you hand it over or publish it. The last three apply to both kinds. A cloud key has no touch: for a cloud root the typed digest and the role session stand, and its audit trail records every signature.
- **The offline system is an option for a root on cards,** if you want a clean machine. A cloud root always runs on the workstation, because the offline system has no network.

For a card or a cloud key, ritueel does not trust the machine: the private key never leaves its card or cloud key, so a compromised machine cannot copy a key it never holds. A software key is in memory while it signs, which is why it stays in the offline system.

## What offline does not give you

A hostile machine cannot steal the key from a card, but it can lie about what is being signed. You think you are certifying one request, and the computer sends another. This is why a ceremony shows you what will be signed in a form you can compare, and asks for a deliberate act, a typed digest and a touch, before each irreversible step.

On the workstation a hostile machine can show you the right digest and still ask the card for one more signature. A touch for every signature, the stated count and no retry bound the rest. If you are tricked into one extra touch, one unknown signature exists, and a card keeps no log of it ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 25). A cloud key has no touch: anyone who can assume the ceremony role can sign any digest without ritueel, and its audit trail records it ([record 0004](../decisions/0004-the-cloud-root.md), rule 10; [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 25).

Offline also does not protect against loss. A key on one card in one drawer is safe from thieves and fragile against fire. The answer to loss is redundancy, and the answer to theft is revocation. They are different problems.

## Offline for software keys

A software key, a file or an entry in a password manager, can be copied by whatever can read it. It is "offline" only to the extent that the machine it sits on is. That is why ritueel treats a software root as fit for drills, tests and a person's own key, and not for a root others rely on. For every key that can be copied, ritueel teaches the offline system as the rule, and the program does not check where it runs ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)). A test root may run on the workstation or on a rehearsal card.

Next: [how a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/).
