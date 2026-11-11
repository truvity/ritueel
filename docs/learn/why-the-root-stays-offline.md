---
title: Why the root stays offline
description: What offline protects a root against, what it cannot protect against, and how a card or a cloud key gets most of the benefit without a vault.
sidebar:
  order: 3
---

"Keep the root offline" is the oldest rule of PKI. It is worth knowing what it is for, because the rule has a literal form (a machine in a safe) and a practical form, and they are not the same.

## What an online key is exposed to

A key that lives on a machine connected to a network can be reached by anything that runs on that machine or can talk to it:

- malware, and a stolen or hijacked user session;
- a bug in the software that uses the key;
- someone with remote access, an insider, or a stolen backup;
- an operator who is tricked into signing something that looks routine.

A root that is online is exposed to all of them every day. A root that comes out once a year is exposed to them for the hour a [ceremony](/glossary/) (the planned, recorded occasion on which the root is used) lasts.

## Three ways to be offline

| Way | What it gives | What it costs |
|---|---|---|
| **A machine in a safe, no network** | The key never touches a network. | A machine to keep alive, a live system to build for every use, a place to store it. Most people do not do this more than twice. |
| **A key that cannot leave a card** | A computer at a ceremony cannot copy the key, even if it is hostile. Possession of the card, its PIN and a touch are needed. | A card can be lost or break, so you need two. |
| **A key in a cloud service behind a role** | Nobody downloads the key. Every use is an audited call to the service, and a role gates it. | Trust in the provider and in the account. Losing the account loses the key. |

ritueel's approach is the second and third. A card root or a real software root is used only in a machine booted from a read-only system made for the purpose (the offline system), never in the everyday system; a cloud root is signed from the holder's workstation through the ceremony role; a test root may run on the workstation or on a rehearsal card ([decision record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)). In all these cases the machine is not trusted: the private key never leaves its card or cloud key, so a compromised machine cannot copy a key it never holds.

## What offline does not give you

A hostile machine cannot steal the key from a card, but it can lie about what is being signed. You think you are certifying one request, and the computer sends another. This is why a ceremony shows you what will be signed in a form you can compare, and asks for a deliberate act, a typed digest and a touch, before each irreversible step.

Offline also does not protect against loss. A key on one card in one drawer is safe from thieves and fragile against fire. The answer to loss is redundancy, and the answer to theft is revocation. They are different problems.

## Offline for software keys

A software key, a file or an entry in a password manager, can be copied by whatever can read it. It is "offline" only to the extent that the machine it sits on is. That is why ritueel treats a software root as fit for drills, tests and a person's own key, and not for a root others rely on. ritueel teaches running a real software root in the offline system too; the program does not check where it runs ([decision record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).

Next: [how a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/).
