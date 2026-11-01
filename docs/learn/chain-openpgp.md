---
title: OpenPGP
description: The custody chain of OpenPGP. A master key that only certifies, subkeys on a card for signing, encryption and login, and how verifiers learn your fingerprint.
sidebar:
  order: 10
---

OpenPGP has no certificate authorities. It has one identity, one master key and several subkeys, and the question of how anyone learns that this identity is yours.

## The chain

| Link | Key | Held by | Lives in | Authority came from |
|---|---|---|---|---|
| Master key | The primary key, set to *certify only*. | You. | Offline, in a store only a ceremony reaches. | Self-certified when created. Its fingerprint is what people record. |
| Signing subkey | Signs commits, tags, releases, documents. | You. | A card used every day. | A binding signature from the master key; renewed by re-signing the binding. |
| Encryption subkey | Decrypts what people send you. | You. | The same card. | The same. |
| Authentication subkey | Logs you in, for example to SSH servers. | You. | The same card. | The same. |

The master key carries no daily duties: it certifies identities, binds subkeys, extends expiry, and revokes. Setting it to *certify only* means that even a program that wanted to use it for signing a document could not. Each subkey does one job, so a break in one is limited to that job. The subkeys live on a card, so the daily key cannot be copied; the master key lives where only a ceremony reaches it.

See [root and intermediate](/learn/root-and-intermediate/) for the split, and [OpenPGP release keys](/learn/openpgp-release-keys/) for the case of a project that signs releases.

## How a verifier learns your fingerprint

A signature proves that the key made it. It does not tell the verifier whose key it is. Four ways exist, and they can be combined.

| Way | How it works | Good for | Weak because |
|---|---|---|---|
| **Web of trust** | People sign each other's keys after checking identity; a verifier follows signatures from keys it already trusts. | A community that meets and signs keys. | Few people maintain it; trust paths are hard to explain; many tools no longer rely on it. |
| **A channel you already trust** | You publish the fingerprint where verifiers already go: your project's website over HTTPS, the release notes, a signed message. | One project, one fingerprint. | Only as safe as the channel. An attacker who changes the page changes the fingerprint. |
| **A keyring package** | Your distribution ships the public keys as a package that a package manager installs and updates. | Software releases. | Needs a package and a pipeline; a verifier must install it from a trusted place first. |
| **A key directory (WKD)** | A mail domain publishes the keys of its users at a standard address, found from the email address. | Email and mail-based identities. | Trusts the domain's web server and DNS. |

For software releases, ritueel recommends the keyring package and a fingerprint published on the project's own site, and not the web of trust. Both are in the [keyring package reference](/reference/keyring-package/).

## Revocation

The master key's revocation certificate is made when the key is born and kept apart from the card, because after a loss it cannot be made. A subkey is revoked by the master key. A revocation does not reach every verifier; see [revoke](/learn/revoke/) and the [table of what each verifier does](/learn/openpgp-release-keys/#revocation).

## Where ritueel fits

ritueel creates the master key in its store, makes the revocation certificate, binds the subkeys, including onto a card, extends the expiry each year and builds the keyring package. How to use the subkeys day to day is in the guides: [SSH login](/guides/openpgp-ssh-authentication/), [signing git commits and tags](/guides/openpgp-sign-git/), [signing releases](/guides/openpgp-sign-releases/), and [OpenPGP or Sigstore](/guides/openpgp-and-sigstore/).
