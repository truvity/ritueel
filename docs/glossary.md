---
title: Glossary
description: The words ritueel's pages and records use in one fixed sense each, with the word a page uses when it differs and the record that decides it.
sidebar:
  order: 17
---

These words carry the design. The pages and the records use each only as below. Where a page keeps an older or narrower word, the third column says so: the glossary does not rename a page's word. It defines words from the records; it decides nothing new.

| Word | Meaning | The page word | Decided in |
|---|---|---|---|
| **root** | What outsiders trust without further proof, of one kind: X.509 anchor, OpenPGP identity or SSH CA. Built from one or more keys, labelled A, B, then the next letter. | `root`, `root key` (one key), `primary` (OpenPGP) | [0001](decisions/0001-what-ritueel-is.md) (rules 28 to 31), [0002](decisions/0002-where-a-key-lives.md) |
| **delegated key** | A key a root certifies or binds: an intermediate, OpenPGP subkey or SSH CA key. A **delegation** is a name declared under a root for a daily-work key. | `intermediate` (X.509), kept in the hand-off contract | [0001](decisions/0001-what-ritueel-is.md), [hand-off contract](/reference/hand-off-contract/) |
| **holder** | The person or small team who keeps a root, runs its ceremonies and prepares its card, account, roles and PIN. | `holder` | [0001](decisions/0001-what-ritueel-is.md) |
| **requester** | The system that holds delegated keys and asks a root for a certificate or a binding. [sluis](https://sluis.id) is one. | `requester`; ritueel is the `certifier` | [hand-off contract](/reference/hand-off-contract/) |
| **key store** | The kind of place where a key is born and kept: key file, PIV card, OpenPGP card or cloud key service. A key's **place** is its one slot, cloud key or file. | `store` | [0002](decisions/0002-where-a-key-lives.md) |
| **ceremony** | One act that uses a root key: `apply`. A person confirms it. | `ceremony`; the yearly one is a practice, not a command | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) |
| **bundle** | The directory with a fixed structure holding everything ritueel knows about one organisation or one person. A root key is written `acme/A` across bundles. | `bundle`, never `directory`; the trust file is `the CA bundle` | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **history** | The folder `history/` is write-once, with one ceremony folder per ceremony. The end of the history is the ceremony record no other names; two ends are a fork. | `history` | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **record** | The JSON file that ends a ceremony, written last in its ceremony folder. It names the ceremony record before it by digest, so they form a hash chain. | `ceremony record`, in full | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **renew** | Extend the same key with a new certification; no new key. A **certification** is a certificate or binding one key makes for a subject, for a period. | `renew`, `re-sign` | [0007](decisions/0007-changing-and-losing-a-root.md) |
| **replace** | Make a new key and end the old one on an event: advisory, deprecated algorithm, lost card, suspected compromise, change of key store; a key that can be copied: at the latest after three years. | `replace`, `rotate` | [0002](decisions/0002-where-a-key-lives.md), [0007](decisions/0007-changing-and-losing-a-root.md) |
| **trust files** | Files outsiders read to decide whom to trust: root list, CA bundle, CRLs, SSH CA key list, OpenPGP keyring, in a numbered set. The holder's pipeline publishes them. | `trust products` goes | [0006](decisions/0006-bundle-history-and-trust-files.md), [0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md) |
| **wanted** | What a person writes about how the bundle should be: `ritueel.yaml` and a strict YAML file for each card, root, delegation and the user IDs, on the workstation only. A ceremony never writes one. | `wanted file` | [0006](decisions/0006-bundle-history-and-trust-files.md) (rules 5 and 31) |
| **not applied yet** | What is wanted and not done, found each time from wanted files, history, date and requests; never stored. An item is a **change**, never a row. | `not applied yet`, `a change` | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) (rule 4) |
| **apply** | Do the changes not applied yet in one ceremony: `apply` finds them, writes the plan and, once a person confirms it, does them. `apply PLAN` runs a saved one. | `apply` | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) (rules 7 and 13) |

The words `card`, `row` and `card file` are defined on their own pages: [the bundle](/reference/bundle/) and [cards](/reference/cards/).
