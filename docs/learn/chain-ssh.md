---
title: SSH
description: The custody chain of SSH, raw keys compared with an SSH certificate authority, user and host certificates, and how a CA key list tells hosts which CAs to trust.
sidebar:
  order: 11
---

SSH has two ways to answer "may this key log in?". The first is a list of keys. The second is a certificate authority. They are different custody chains.

## Raw keys

With raw keys, each host keeps a file of the public keys allowed to log in (`authorized_keys`), and each user keeps a file of host keys they have seen (`known_hosts`).

- **No chain.** Every key is trusted on its own.
- **No expiry and no revocation,** except removing the key from every file that has it.
- **First use is a guess.** The first time you connect to a host you accept its key on faith, so you are trusting a network at the moment it is least trustworthy.
- **It scales badly.** Ten people and a hundred hosts is a thousand lines to keep right.

It is fine for one person and a few machines. It is the wrong shape for a team.

## An SSH CA

With an SSH certificate authority, a CA key signs a short statement: this public key belongs to this user (or host), with these names, valid between these times. A host trusts the CA's public key once (`TrustedUserCAKeys`), and then accepts any user certificate it signed. A user trusts the CA for host keys once (`@cert-authority` in `known_hosts`) and stops guessing.

| | Raw keys | SSH CA |
|---|---|---|
| What a host trusts | Each key, one by one. | One CA public key. |
| Joining | Add a line on every host. | The CA signs a certificate; hosts change nothing. |
| Leaving | Remove a line on every host. | Let the certificate expire, which can be minutes. |
| Expiry | None. | In the certificate. |
| Names | None. | Principals: which account names the certificate allows. |
| Revocation | Delete the key. | A revoked-keys list on each host, or short lifetimes. |
| First connection | A guess. | None, if the host has a host certificate. |

## The custody chain

An SSH CA key is an *anchor*, not a chain: it signs certificates directly, and there is normally no intermediate. That makes the custody question sharper.

| Link | Key | Held by | Lives in | Authority came from |
|---|---|---|---|---|
| CA key (user) | Signs user certificates. | The system that issues them, behind sign-in and policy. | A cloud key service or a card. | Listed by the hosts that trust it. |
| CA key (host) | Signs host certificates. | The system that provisions hosts. | The same. | Listed by the users who trust it. |
| Break-glass CA | A second CA, for emergencies when the first is unavailable. | The holder, offline like a root. | A root card or cloud root. | Listed by the hosts, and used only by a ceremony. |
| Certificate | A user's or host's key plus names and validity. | The user or host. | A hardware key, an agent, a disk. | Signed by the CA key. |

Because hosts hold the CA's public key directly, rotating a CA key means updating every host. That is the one job an SSH CA key list does: a signed, versioned list of the CA keys a host should trust, so that adding or removing a CA is a change to the list, not a visit to every host.

## Where ritueel fits

ritueel holds the break-glass SSH CA offline, like a root, and publishes the signed **SSH CA key list** ([reference](/reference/ssh-ca-key-list/)). The CA keys that issue day-to-day certificates stay with the system that holds them. An OpenPGP authentication subkey can also serve as an SSH key; see [chain OpenPGP](/learn/chain-openpgp/) and the guide on using it.
