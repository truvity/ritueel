---
title: Reference
description: The specifications of ritueel, with the hand-off contract, root list, SSH CA key list, CRLs, cards, the cloud root, ceremony files, directory and commands.
sidebar:
  label: Overview
  order: 0
---

Reference pages say exactly what a file, a message or a command is. The reasons are in the [decision records](/decisions/).

| Page | What it fixes |
|---|---|
| [Hand-off contract](/reference/hand-off-contract/) | What a system that holds intermediates sends and gets back, with test vectors. |
| [Commands](/reference/cli/) | The commands, their arguments and files, the shared flags, the exit codes and the JSON output. |
| [Keyring package](/reference/keyring-package/) | The name, version, files, contents, build and verify steps of the keyring package, and what older rpm support means. |
| [Signed root list and CA bundle](/reference/root-list/) | The root list's members and signature, how a host reads it, the CA bundle, with test vectors. |
| [Ceremony files](/reference/ceremony-record/) | The plan and its digest, the attempt, the hash-chained record and the transcript. |
| [Root transitions](/reference/transitions/) | The state of a root, `root add`, `retire` and `revoke` with their checks, the cross-certificate and the OpenPGP vouch. |
| [Revocation material](/reference/revocation-material/) | The revocation signatures made at birth, where they are written and refused, and how to make and check one. |
| [Drills and the restore check](/reference/drill/) | The restore check and its report, the walk-through scripts, and when a drill is due. |
| [The wizard](/reference/wizard/) | What the wizards drive, how they stay one engine with the commands, and the security profile of the web page. |
| [The software store](/reference/software-store/) | The encrypted file, 1Password and the OS keyring: how each is chosen, what it holds, refuses and warns. |
| [Personal OpenPGP](/reference/personal-openpgp/) | The personal directory, the person's primary and daily subkey, and the two commands. |
| [The directory](/reference/directory/) | The directory's layout, `ritueel.yaml`, the root certificate and primary profiles, and the software root's key files. |
| [SSH CA key list](/reference/ssh-ca-key-list/) | How an SSH CA key enters the list, its members and signature, how a host reads it, and the file for sshd, with test vectors. |
| [Root-signed CRLs](/reference/crl/) | The CRL each root signs to revoke an intermediate: profile, cadence, how a relying party reads it, with test vectors. |
| [Root cards](/reference/cards/) | The card registry, the checks made on a card, the attestation files and the maker's bundle with its refresh step. |
| [The cloud root in AWS KMS](/reference/kms-root/) | The operator's roles, the `ritueel.yaml` block, the keys and key policy ritueel creates, and the checks it makes. |
