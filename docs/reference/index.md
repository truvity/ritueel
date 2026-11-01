---
title: Reference
description: The specifications of ritueel, the hand-off contract, the root list, the ceremony files, the directory, the commands and the keyring package.
sidebar:
  label: Overview
  order: 0
---

Reference pages say exactly what a file, a message or a command is. The reasons are in the [decision records](/decisions/).

| Page | What it fixes |
|---|---|
| [Hand-off contract](/reference/hand-off-contract/) | What a system that holds intermediates sends and gets back, with test vectors. |
| [Commands](/reference/cli/) | The commands, their arguments and files, the shared flags, the exit codes and the JSON output. |
| [Keyring package](/reference/keyring-package/) | The name, version and files of the keyring package. |
| [Signed root list and CA bundle](/reference/root-list/) | The root list's members and signature, how a host reads it, the CA bundle, with test vectors. |
| [Ceremony files](/reference/ceremony-record/) | The plan and its digest, the attempt, the hash-chained record and the transcript. |
| [The directory](/reference/directory/) | The directory's layout, `ritueel.yaml`, the root certificate and primary profiles, and the software root's key files. |

The SSH CA key list gets a page of its own when it is specified ([issue #55](https://github.com/truvity/ritueel/issues/55)).
