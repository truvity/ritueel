---
title: Glossary
description: The words ritueel's pages and records use in one fixed sense each, with the word a page uses when it differs and the record that decides it.
sidebar:
  order: 17
---

These words carry the design. The pages and the records use each in the sense below and in no other. Where a page keeps an older or narrower word, the third column says so: the glossary does not rename a page's word. It defines words from the records; it decides nothing new.

| Word | Meaning | The page word | Decided in |
|---|---|---|---|
| **root** | What outsiders trust without further proof, of one kind: X.509 trust anchor, OpenPGP identity or SSH CA. Built from one or more keys, labelled A, B, then the next letter. | `root key` for one key; `primary` for OpenPGP | [0001](decisions/0001-what-ritueel-is.md) (rule 28), [0002](decisions/0002-where-a-key-lives.md) |
| **delegated key** | A key that a root certifies or binds: an intermediate certificate key, an OpenPGP subkey or an SSH CA key. A **delegation** is a declared name under a root for a key that does daily work. | `intermediate` (X.509), kept in the hand-off contract | [0001](decisions/0001-what-ritueel-is.md), [hand-off contract](/reference/hand-off-contract/) |
| **holder** | The person, or the small team, who keeps a root and runs its ceremonies. | `operator` prepares a card or an account | [0001](decisions/0001-what-ritueel-is.md) |
| **requester** | The system that holds delegated keys and asks a root for a certificate or a binding. [sluis](https://sluis.id) is one. | ritueel is the `certifier` | [hand-off contract](/reference/hand-off-contract/) |
| **store** | The kind of place where a key is born and kept: key file, PIV card, OpenPGP card or cloud key service. A key's **place** is its one slot, cloud key or file. | `key store` | [0002](decisions/0002-where-a-key-lives.md) |
| **ceremony** | One act that uses a root key, in six steps: plan, confirm, reserve, sign, verify, record. A person confirms it. | the yearly ceremony is a practice, not a command | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) |
| **bundle** | The directory with a fixed structure that holds everything ritueel knows about one trust domain. A root key is written `acme/A` across bundles. | never `directory`; the trust file is `the CA bundle` | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **history** | The folder `history/` is write-once, with one ceremony folder per ceremony. The end of the history is the ceremony record no other names; two ends are a fork. | `history` | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **record** | The JSON file that ends a ceremony, written last in its ceremony folder. It names the ceremony record before it by digest, so they form a hash chain. | `ceremony record`, in full | [0006](decisions/0006-bundle-history-and-trust-files.md) |
| **renew** | Extend the same key with a new certification; no key is made. A **certification** is a certificate or binding one key makes for a subject, from a day to a day. | `renew`, `re-sign` | [0007](decisions/0007-changing-and-losing-a-root.md) |
| **replace** | Make a new key on an event and let the old one end: advisory, deprecated algorithm, lost card, suspected compromise, change of store or, for a copyable key, at most three years. | `replace`, `rotate` | [0002](decisions/0002-where-a-key-lives.md), [0007](decisions/0007-changing-and-losing-a-root.md) |
| **trust files** | Files outsiders read to decide whom to trust: root list, CA bundle, CRLs, SSH CA key list and OpenPGP keyring, in a numbered trust set. The holder's pipeline publishes them. | `trust products` goes | [0006](decisions/0006-bundle-history-and-trust-files.md), [0011](decisions/0011-publishing-and-what-to-do-after-a-ceremony.md) |
| **wanted** | What a person writes about how the bundle should be: `ritueel.yaml` and one strict YAML file for each card, root, delegation and the user IDs, only on the workstation. A ceremony never writes a wanted file. | `wanted file` | [0006](decisions/0006-bundle-history-and-trust-files.md) (rules 11, 29) |
| **not applied yet** | What is wanted and not done, found each time from the wanted files, history, date and requests; never stored. Each item is a **change**, never a row. | `not applied yet`, `a change` | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) (rule 29) |
| **apply** | Do the changes not applied yet in one ceremony: `apply` finds them, writes the plan and, once the person confirms, signs and records. `apply PLAN` runs a saved plan. | `apply` | [0005](decisions/0005-a-ceremony-and-where-it-runs.md) (rules 4, 10) |

The words `card`, `row` and `card file` are defined on their own pages: [the bundle](/reference/bundle/) and [cards](/reference/cards/). The cards page still says `inventory` and is rewritten to follow the records.
