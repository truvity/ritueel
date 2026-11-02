---
title: The software store and its backends
description: The three backends of the software store, an encrypted file, 1Password and the OS keyring, how each is chosen, what it holds and refuses, and its warning.
sidebar:
  order: 16
---

*Not built yet. The encrypted file is built with M1 ([issue #8](https://github.com/truvity/ritueel/issues/8)); 1Password ([issue #59](https://github.com/truvity/ritueel/issues/59)) and the OS keyring ([issue #60](https://github.com/truvity/ritueel/issues/60)) are M4. The reasons are in [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store) and [ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#software-keys-three-backends-all-born-in-the-store); the facts behind the choices are in [the research](/research/software-key-backends-2026-11-01/).*

A software key has no evidence of where it lives and can be copied ([what a store can prove](/learn/what-a-store-can-prove/)). The backend decides where the bytes sit between ceremonies. In every backend the key is generated in memory and written straight into its backend, never to a file on disk.

## The backends

| Backend | May hold | Never holds | Platforms |
|---|---|---|---|
| `file`: an age-encrypted file | Test roots, drills, development; a person's own primary ([ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)). | A root that others rely on. | Linux, macOS |
| `onepassword`: 1Password, through `op` | The keys of test roots, intermediates and subkeys. | A production root, or a person's master key. | Linux, macOS |
| `keyring`: the OS keyring | A throwaway test key. | Anything else, and any passphrase. | Linux, macOS |

It is chosen when a root is made: `ritueel init --store software --backend file|onepassword|keyring`. A root is never moved between backends; a move is a transition ([root transitions](/reference/transitions/)). The backend and the reference to the key are in the root's `root.json`:

| Member | Meaning |
|---|---|
| `backend` | `file`, `onepassword` or `keyring`. |
| `key_ref` | For `onepassword`: `{ "vault", "item" }`, a vault name and an item id. For `keyring`: `{ "service", "user" }`. Absent for `file`, whose files are in `--key-dir` ([the directory](/reference/directory/#the-software-roots-key-files)). |

Windows has no consumer, so no backend is built for it; the release builds are for Linux and macOS ([tools](/contributing/tools/#how-a-consumer-gets-ritueel)).

## Revocation signatures

With the `file` backend they are in the key directory, as [the directory](/reference/directory/#the-software-roots-key-files) says. With `onepassword` and `keyring` they are written to `--revocation-dir`, outside the ledger and apart from the key ([revocation material](/reference/revocation-material/)): a revocation signature next to its key in the same vault or keyring would be one theft, not two.

## 1Password

Through the `op` command line, not the Go SDK ([the research](/research/software-key-backends-2026-11-01/#roads-not-taken)). ritueel never sees the account password or the Secret Key; `op` asks the 1Password app to unlock, by its own integration.

- **The item.** One item of the category Secure Note in the vault given by `--op-vault`, titled `ritueel <name> root <label> (TEST)`. The X.509 key (PKCS#8, PEM) and the OpenPGP secret key (armoured) are concealed fields; a note says the key is a test key and can be copied. An SSH Key item is not used: it takes Ed25519 and RSA only. A Document item is not used: attaching a file goes by path, so the key would reach a disk.
- **Writing.** ritueel builds the item as JSON and gives it to `op item create` on standard input. Nothing is put on a command line, where other processes can read it, and nothing in a file.
- **Reading.** `op item get` with JSON output, parsed in memory.
- **The plan records** the item's id and its version. A ceremony refuses with `item-changed` if the version differs when it signs.
- **Refusals.** `backend-locked` (the vault is locked or `op` is not signed in; exit code 4), `backend-missing` (`op` is not on the path, or older than the version the tests were run with), `item-missing`, `item-changed`.
- **Said plainly** in the creation output and in every record: whoever can unlock the vault has the key, and the vault's sync gives redundancy against loss, not against compromise (`warnings` carries `onepassword-copyable`).

A test with a stub `op` covers a locked vault, a missing item and an item changed since the plan; another scans the working directory and the temporary directory after a ceremony and finds no key material.

## The OS keyring

Through `github.com/zalando/go-keyring`. The entries are under the service `ritueel`, one for each key, named by the root's name, label and kind.

- **Refusal, not fallback.** When the library reports no usable backend (no D-Bus session bus, no Secret Service provider), ritueel refuses with `backend-missing`. It never writes the key to a file instead.
- **Size.** The limits of the platforms are in the research (about 3000 bytes on macOS in all, 2560 on Windows); an armoured OpenPGP secret key of about 1 KB and a P-384 PKCS#8 key fit. A write the platform refuses is reported as it is; the limits on each supported platform are measured and dated in a research page before the backend is called supported ([issue #60](https://github.com/truvity/ritueel/issues/60)).
- **The warning.** Printed when the root is created and carried in every record (`warnings` has `keyring-insecure`). The words are fixed, and a test compares them:

> WARNING: the OS keyring is not a safe home for a root or master key. Programs running as your user can usually read it once it is unlocked, it may be synced or backed up, and it cannot be made non-exportable. Use it only for a throwaway test key. Keep real root keys offline, on a hardware token or in a cloud key service.

ritueel stores no passphrase in the keyring, because it keeps no passphrase anywhere ([ADR 0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).

## The record

A ceremony with a software root writes in its record: `copyable` true (as the plan's `root` already says), `backend`, and `warnings`, a list of codes: `software-copyable` for every backend, and `onepassword-copyable` or `keyring-insecure` as above. No secret and no reference to a path.

## Follow-ups

- The `file` backend ([issue #8](https://github.com/truvity/ritueel/issues/8)).
- The 1Password backend, with the `op` stub tests and the restore drill against it ([issue #59](https://github.com/truvity/ritueel/issues/59)).
- The keyring backend, with the warning and the refusal tests on Linux and macOS, and the dated size research ([issue #60](https://github.com/truvity/ritueel/issues/60)).

## Standards

| Standard | Used for |
|---|---|
| [age v1](https://age-encryption.org/v1) | The `file` backend. |
| [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958), [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580) | The key formats stored. |
