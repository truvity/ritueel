---
title: Learn
description: How the pages are grouped, where to start from zero, and a table that leads from a goal to its chain, its keys and the pages to read.
sidebar:
  label: Overview
  order: 0
---

ritueel teaches first. These pages explain how to keep a root key safe, whatever tool you use; of ritueel, only `version` is built. Only the first group, Basics, starts from zero. Every other page says in its first lines what it assumes, and links to the basics. If you come with a goal, the [table of goals](#goals) says which pages to read.

## Basics

- [What is a root?](/learn/what-is-a-root/): the key everything else hangs from, what goes wrong when it is lost or stolen, and five ideas about keys that the other pages use.

## Down the chain

- [The custody chain](/learn/custody-chain/): who or what holds each key from the root to the leaf, and four chains side by side.
- [Private PKI](/learn/chain-private-pki/): your own root, an intermediate for each environment, and how the root reaches every client.
- [OpenPGP](/learn/chain-openpgp/): the primary key, its subkeys, and how a verifier learns your fingerprint.
- [SSH](/learn/chain-ssh/): raw keys, an SSH certificate authority, and the list of CA keys that hosts trust.

## Where a key lives

- [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/): what is inside a YubiKey 5, how PIV, OpenPGP and FIDO2 differ, and what locks or wipes a card. Under it, [how passkeys work](/learn/how-passkeys-work/): what a passkey is, how a sign-in goes, and what the PIN and the touch protect.
- [How a KMS key works](/learn/how-a-kms-key-works/): what an AWS KMS signing key is made of, what limits it, and how it compares with a card slot.
- [A key in a file](/learn/a-key-in-a-file/): what a key file is for, and how a passkey on a root card opens it.
- [Choosing where a root lives](/learn/choosing-where-a-root-lives/): two questions that pick a key file, a pair of root cards or a cloud key, and what each costs a year.

## Side by side

- [Several keys, one root](/learn/two-roots/): why one root has more than one key, how the cards alternate, and how a key is added, moved, retired and revoked.
- [The life of a root](/learn/life-of-a-root/): create, sign, record, back up, re-sign, rotate, revoke, recover, in order.
- [Revoke](/learn/revoke/): lost or exposed a key? Make the certificate before you need it, and know what it reaches.

## Goals

Each row starts from what you want to do, and names the chain, the keys, what ritueel does and the pages to read in order. The guides are in the repository; a tool a guide uses is planned unless the guide says it is built.

| Goal | Chain | Keys | What ritueel does | Read |
|---|---|---|---|---|
| Keep the root of a private PKI for your services | [Private PKI](/learn/chain-private-pki/) | An X.509 root key on two root cards or in a cloud key with a replica. An intermediate for each environment, held by the system that issues certificates. | Holds the root, signs each intermediate at a ceremony, builds the CA bundle, the root list and the CRL. It issues no leaf certificates ([record 0001](../decisions/0001-what-ritueel-is.md), rule 9; [record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 13, 16, 23 and 24). | [Private PKI](/learn/chain-private-pki/), then [KMS](/learn/how-a-kms-key-works/) or [YubiKey](/learn/how-a-yubikey-holds-keys/), then [Choosing](/learn/choosing-where-a-root-lives/). Guide: [Prepare the cloud root](/guides/prepare-the-cloud-root/). |
| Sign a release with OpenPGP | [OpenPGP](/learn/chain-openpgp/) | The primaries of the root, one for each root key, certify only, on a root card or in the cloud. A release subkey that the root binds. | Makes the keyring file. The project's pipeline packages and publishes it ([record 0009](../decisions/0009-release-keys-and-the-keyring.md), rules 1, 21 and 22). | [OpenPGP](/learn/chain-openpgp/), [Revoke](/learn/revoke/), then [OpenPGP release keys and the keyring](/learn/openpgp-release-keys/). Guide: [Sign software and releases](/guides/openpgp-sign-releases/). |
| Your own OpenPGP key, to sign commits and documents and to decrypt what people send you | [OpenPGP](/learn/chain-openpgp/) | A primary that only certifies, kept offline in an encrypted file. A signing subkey and an authentication subkey made on each day-to-day card. An encryption subkey made in software and loaded onto the card. | Adopts the primary or makes it, makes its revocation signature, binds the subkeys and renews them each year. Using the keys belongs to other tools ([record 0008](../decisions/0008-a-persons-own-key.md), rules 5, 7, 9 and 10; [record 0007](../decisions/0007-changing-and-losing-a-root.md), rule 21; [record 0001](../decisions/0001-what-ritueel-is.md), rule 13). | [OpenPGP](/learn/chain-openpgp/), [A key in a file](/learn/a-key-in-a-file/), [Revoke](/learn/revoke/). Guide: [Your own OpenPGP key](/guides/personal-openpgp/). |
| SSH login with certificates | [SSH](/learn/chain-ssh/) | A break-glass SSH CA key, held like a root key. The CA keys of a system stay with that system. | Holds the break-glass SSH CA key offline and builds the signed SSH CA key list for hosts ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rules 25 to 29). | [SSH](/learn/chain-ssh/), then [Choosing](/learn/choosing-where-a-root-lives/). Guide: [After a ceremony](/guides/after-a-ceremony/#sshd). |

A decision record is a file in `docs/decisions/` in the repository; [The design](/design/) says what the records decide, and pages cite them for the reason behind a rule. Words with one fixed sense are in the [glossary](/glossary/).

:::note[Design phase]
ritueel has no release yet. Where a page says what a tool does, the tool is planned unless the page says it is built; the [roadmap](/roadmap/) has the order.
:::
