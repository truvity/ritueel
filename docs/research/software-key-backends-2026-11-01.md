---
title: Software key backends, 1Password and the OS keyring (2026-11-01)
description: What 1Password and the system keyring can and cannot do as homes for software keys, their size limits and who can read them, from their documents and source.
sidebar:
  order: 5
---

## Question

Where may a software key live between ceremonies, if not in a file on one disk: in 1Password, or in the operating system's keyring? What does each protect against, what does each cost, and what must ritueel do about it? It feeds [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store) and [the software store](/reference/software-store/).

## When

Read on 2026-11-01. The rows marked *rechecked* were read again on 2026-11-02, against the document or the source and not a summary.

## Verdict

**1Password through its `op` command line, for the keys of test roots, intermediates and subkeys; the keyring only with a warning, for a throwaway key.** `op` takes a JSON item template on standard input, so a key never reaches disk or a command line, and it needs no CGO and no pre-1.0 library. The Go SDK's desktop sign-in needs CGO on Linux and macOS, and its service accounts cannot reach personal vaults. Neither store is a place for a root that others rely on: whoever unlocks the vault, or any program of the user once the keyring is unlocked, can read the key.

## Method

Read the vendor documents and the library source named below. Nothing was written to a vault or a keyring. The facts about what a program of the same user can do are the vendors' own statements, not tests.

## What the setup over- and under-counts

- No vault or keyring was exercised, so size limits are the documented ones, not measured; they are measured by the tests of [issue #59](https://github.com/truvity/ritueel/issues/59) and [issue #60](https://github.com/truvity/ritueel/issues/60) before either backend is called supported.
- macOS and Windows keyring behaviour was read from source only.

## Numbers

### 1Password

| Fact | Source | Label |
|---|---|---|
| The Go SDK is `github.com/1password/onepassword-sdk-go`, latest release v0.4.1 on 2026-07-30, a version 0. | GitHub releases (*rechecked*). | READ |
| `WithDesktopAppIntegration` returns an error when the program is built without CGO on Linux and macOS ("requires CGO to cross-compile"). | `client_builder_no_cgo.go` (*rechecked*). | READ |
| Service accounts cannot reach Personal, Private or Employee vaults; they have hourly and daily rate limits. | 1Password service account documents, 2026-11-01. | READ |
| `op item create` can read an item JSON template from standard input: `op item template get Login \| op item create --vault personal -`, and not together with `--template`. The documents say command arguments "can be visible to other processes on your machine" and "If you're assigning sensitive values, use a JSON template instead." | `op item` reference (*rechecked*). | READ |
| An SSH Key item accepts Ed25519 and RSA (2048, 3072, 4096) keys; "other key types, such as DSA or ECDSA keys, aren't supported". A P-384 key does not go in one. | The 1Password SSH key documents (*rechecked*). | READ |
| An authorization of the command line expires "after 10 minutes of inactivity" with "a hard limit of 12 hours". | The CLI app-integration security page (*rechecked*). | READ |
| On Linux the command line connects to a Unix socket of the app that is "owned by the current user/group, allowing any process started by this user to connect to it". | The same page (*rechecked*). | READ |
| Removing a member of a shared vault does not change its keys; recovery needs the account password and the Secret Key, which 1Password cannot recover. | The 1Password security white paper, dated 2024-12-10, sections 1 and 10. | READ |
| Per-item and per-field size limits. | No official figure found. | UNVERIFIED |

### The operating system keyring (`github.com/zalando/go-keyring`)

| Fact | Source | Label |
|---|---|---|
| The latest tag is v0.2.8 (2026-03-23). | GitHub, 2026-11-01. | READ |
| On Linux it uses the Secret Service over the D-Bus session bus, and opens the session with `"plain"`, so the secret crosses the bus unencrypted. | `secret_service/secret_service.go`, master (*rechecked* 2026-11-02). | READ |
| Size: on macOS the combination of service, user and secret "should not exceed ~3000 bytes"; on Windows the password is limited to 2560 bytes; on Linux there is no limit but "performance suffers with big values (>100KiB)". | The `ErrSetDataTooBig` comment in `keyring.go` and `keyring_windows.go` (*rechecked*). | READ |
| Without a D-Bus session bus there is no keyring on Linux: the library fails to find one. | `godbus` source, 2026-11-01. | READ |
| Whether another program of the same user can read an entry without a prompt. | Linux: any program on the session bus can use the Secret Service API of an unlocked collection (secondary sources). macOS and Windows: not confirmed from an authoritative source. | READ for Linux; UNVERIFIED for macOS and Windows |

An armoured OpenPGP secret key is about 1 KB and a P-384 PKCS#8 key under 200 bytes, so all three limits are above them.

## Roads not taken

- **The 1Password Go SDK.** In-process, but a version 0 with breaking changes allowed between minors, and a sign-in that needs CGO or a service account that cannot reach personal vaults.
- **An SSH Key item for the key.** The native type, but it refuses P-384.
- **A Document item with the key as a file.** Fits any key, but `op` attaches a file by path, so the key would be written to disk first.
- **The Connect server.** Self-hosted, but it cannot create the item types needed and its file endpoints only read.
- **The keyring as the default.** No account, but it is the weakest store, so it is offered with a warning and not chosen for the person ([ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/)).

## Open questions

None.

## Changes made

None.

## Raw logs

Not kept; the sources are public and named in the table.
