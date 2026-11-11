---
title: Glossary
description: The eleven words ritueel's pages and records use in one fixed sense each, with the word a page uses when it differs and the record that decides it.
sidebar:
  order: 17
---

Eleven words carry the design. The pages and the records use each in the sense below and in no other. Where a page keeps an older or narrower word, the third column says so: the glossary does not rename a page's word. It defines words from the records; it decides nothing new.

| Word | Meaning | The page word | Decided in |
|---|---|---|---|
| **root** | The key that others trust without further proof: an X.509 root CA key, or an OpenPGP primary key. It is born in its store and used rarely. | `root`, `primary` for OpenPGP | [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [What is a root?](/learn/what-is-a-root/) |
| **delegated key** | A key that a root certifies or binds: the key of an intermediate certificate, an OpenPGP subkey, an SSH CA key. The root signs for it; the system that holds it keeps its private half. | `intermediate` for the X.509 case; the hand-off contract keeps this word | [0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/), [hand-off contract](/reference/hand-off-contract/) |
| **holder** | The person, or the small team, who keeps a root and runs its ceremonies. | `holder`, `operator` for the one who prepares a card or an account | [0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/), [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/) |
| **requester** | The system that holds delegated keys and asks a root for a certificate or a binding through the hand-off contract. [sluis](https://sluis.id) is one. | `requester`, with ritueel the `certifier` | [hand-off contract](/reference/hand-off-contract/) |
| **store** | Where a key is born and kept: a software key file, a PIV card, an OpenPGP card, or a cloud key service. | `store`, `key store` | [0003](/decisions/0003-key-stores-and-the-card-layer/), [Where a key lives](/learn/key-stores/) |
| **ceremony** | One act that uses a root, in six steps: plan, confirm, reserve, sign, verify, record. A person confirms it. | `ceremony`; the practice of meeting the root once a year is called the yearly ceremony (there is no yearly command) | [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony), [What a ceremony is](/learn/ceremonies/) |
| **ledger** | The write-once part of the directory: one sub-folder for each ceremony, holding its plan, attempt, record, transcript and birth journal, each naming the one before it. | `ledger` for this part, a folder inside the directory; `directory` for the whole | [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-directory-and-the-records), [The ledger](/learn/the-ledger/) |
| **record** | The JSON file a ceremony writes into its sub-folder of the ledger. It names the record before it by digest, so the records form a hash chain. | `record`, `ceremony record` | [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#the-directory-and-the-records), [Ceremony files](/reference/ceremony-record/) |
| **renew** | Extend the validity of the same key: a new certificate or binding over the same key material. No key is made. | `renew`, `re-sign` | [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement), [Re-signing](/learn/re-sign/) |
| **replace** | Make a new key on an event, and let the old one end: an advisory, an algorithm that is deprecated, a lost card, a suspected compromise, a change of store, or the three-year limit on a key that can be copied. | `replace`, `rotate` | [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement), [Rotate](/learn/rotate/) |
| **trust files** | The files that outsiders read to decide whom to trust: the root list, the CA bundle, the CRLs and the SSH CA key list. The keyring package carries the OpenPGP side. | `trust products` | [0005](/decisions/0005-trust-products-the-root-list-the-ca-bundle-the-ssh-ca-key-list-and-the-trust-sequence/) |

The words `directory`, `card`, `row` and `inventory` are defined on their own pages: [the directory](/reference/directory/) and [cards](/reference/cards/).
