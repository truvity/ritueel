---
title: Glossary
description: The words ritueel's pages and records use in one fixed sense each, with the word a page uses when it differs and the record that decides it.
sidebar:
  order: 17
---

These words carry the design. The pages and the records use each in the sense below and in no other. Where a page keeps an older or narrower word, the third column says so: the glossary does not rename a page's word. It defines words from the records; it decides nothing new.

| Word | Meaning | The page word | Decided in |
|---|---|---|---|
| **root** | The key that others trust without further proof: an X.509 root CA key, or an OpenPGP primary key. It is born in its store. | `root`, `primary` for OpenPGP | [0002](decisions/0002-where-a-key-lives.md), [What is a root?](/learn/what-is-a-root/) |
| **delegated key** | A key that a root certifies or binds: the key of an intermediate certificate, an OpenPGP subkey, an SSH CA key. | `intermediate` for the X.509 case; the hand-off contract keeps this word | [0001](decisions/0001-what-ritueel-is.md), [hand-off contract](/reference/hand-off-contract/) |
| **holder** | The person, or the small team, who keeps a root and runs its ceremonies. | `holder`, `operator` for the one who prepares a card or an account | [0001](decisions/0001-what-ritueel-is.md) |
| **requester** | The system that holds delegated keys and asks a root for a certificate or a binding through the hand-off contract. [sluis](https://sluis.id) is one. | `requester`, with ritueel the `certifier` | [hand-off contract](/reference/hand-off-contract/) |
| **store** | Where a key is born and kept: a software key file, a PIV card, an OpenPGP card, or a cloud key service. | `store`, `key store` | [0002](decisions/0002-where-a-key-lives.md), [Where a key lives](/learn/key-stores/) |
| **ceremony** | One act that uses a root, in six steps: plan, confirm, reserve, sign, verify, record. A person confirms it. | `ceremony`; the practice of meeting the root once a year is called the yearly ceremony (there is no yearly command) | [0005](decisions/0005-a-ceremony-and-where-it-runs.md), [What a ceremony is](/learn/ceremonies/) |
| **bundle** | The directory with a fixed structure that holds everything ritueel knows about one trust domain: its history, trust sequence, root list, roots and card inventory. A holder with a personal key and a company keeps two. A root is written with the bundle's name across bundles, for example `acme/A`. | `bundle`, always; `directory` only for any other directory (key directory, working directory); the trust file is `the CA bundle` in full | [0006](decisions/0006-bundle-history-and-trust-files.md), [The bundle](/reference/bundle/) |
| **history** | The write-once part of the bundle: the folder `history/`, one sub-folder for each ceremony, holding its plan, attempt, record, transcript and birth journal, each naming the one before it. | `ledger` is the older word; `history` for this part, `bundle` for the whole | [0006](decisions/0006-bundle-history-and-trust-files.md), [The history](/learn/the-history/) |
| **record** | The JSON file a ceremony writes into its sub-folder of `history/`. It names the record before it by digest, so the records form a hash chain. | `record`, `ceremony record` | [0006](decisions/0006-bundle-history-and-trust-files.md), [Ceremony files](/reference/ceremony-record/) |
| **renew** | Extend the validity of the same key: a new certificate or binding over the same key material. No key is made. | `renew`, `re-sign` | [0007](decisions/0007-changing-and-losing-a-root.md), [Re-signing](/learn/re-sign/) |
| **replace** | Make a new key on an event, and let the old one end: an advisory, an algorithm that is deprecated, a lost card, a suspected compromise, a change of store, or the three-year limit on a key that can be copied. | `replace`, `rotate` | [0002](decisions/0002-where-a-key-lives.md), [0007](decisions/0007-changing-and-losing-a-root.md), [Rotate](/learn/rotate/) |
| **trust files** | The files that outsiders read to decide whom to trust: the root list, the CA bundle, the CRLs, the SSH CA key list and the public OpenPGP keyring, one numbered set in `trust/<number>/` of the bundle. A personal bundle has only the person's public certificate. | the older page word `trust products` goes | [0006](decisions/0006-bundle-history-and-trust-files.md) |

The words `card`, `row` and `inventory` are defined on their own pages: [the bundle](/reference/bundle/) and [cards](/reference/cards/).
