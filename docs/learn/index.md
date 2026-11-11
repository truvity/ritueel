---
title: Learn
description: Six pages in order, from what a root is to choosing where it lives, then four pages to go further.
sidebar:
  label: Overview
  order: 0
---

ritueel teaches first. These pages explain how to keep a root key safe, whatever tool you use; ritueel's own tools are not built yet. Read the first six in order. Each one assumes the one before.

1. [What is a root?](/learn/what-is-a-root/): the key everything else hangs from, and what goes wrong when it is lost or stolen.
2. [Where a root is used](/learn/where-a-root-is-used/): who can use a root at all, which machine a ceremony runs on, and what offline protects against.
3. [How a YubiKey holds keys](/learn/how-a-yubikey-holds-keys/): what is inside a YubiKey 5, how PIV, OpenPGP and FIDO2 differ, and what locks or wipes a card.
4. [How passkeys work](/learn/how-passkeys-work/): what a passkey is, how a sign-in goes, what the PIN and the touch protect, and how a passkey can open a key file.
5. [How a KMS key works](/learn/how-a-kms-key-works/): what an AWS KMS signing key is made of, what limits it, and how it compares with a card slot.
6. [Choosing where a root lives](/learn/choosing-where-a-root-lives/): two questions that pick a key file, a pair of root cards or a cloud key, and what each costs a year.

Pages 1 and 2 are short; pages 3 to 6 are longer reference reading. A decision record is a file in `docs/decisions/` in the repository; [The design](/design/) says what the records decide, and pages cite them for the reason behind a rule. Words with one fixed sense are in the [glossary](/glossary/).

## Going further

- [The life of a root](/learn/life-of-a-root/): create, sign, record, back up, re-sign, rotate, revoke, recover, in order.
- [Revoke](/learn/revoke/): lost or exposed a key? Make the certificate before you need it, and know what it reaches.
- [The custody chain](/learn/custody-chain/): who or what holds each key from the root to the leaf.
- [OpenPGP: one identity, many keys](/learn/chain-openpgp/): the primary key, its subkeys, and how a verifier learns your fingerprint.

The words these pages use are fixed in the [glossary](/glossary/).

:::note[Design phase]
ritueel has no release yet. Where a page says what a tool does, the tool is planned unless the page says it is built; the [roadmap](/roadmap/) has the order.
:::
