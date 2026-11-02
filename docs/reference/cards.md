---
title: Root cards, the registry and the attestation bundle
description: The card registry cards.yaml, the checks made on a card before anything is written, the attestation files kept for each root key, and the maker's bundle.
sidebar:
  order: 9
---

*Not built yet. This is the page that [ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/) leaves for the formats of the `piv` store; the code is [issue #11](https://github.com/truvity/ritueel/issues/11), in M2. The slot map is in [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) and is not repeated here.*

A root card is a hardware token that holds a root and is used for nothing else. Before it holds anything, the holder prepares it with the maker's tool ([Prepare a root card](/guides/prepare-a-root-card/)). ritueel then registers it, checks it before every ceremony, and keeps the evidence that a key was born on it.

## Files

| Path | Written by | Holds |
|---|---|---|
| `cards.yaml` | ritueel | The registry: one row for each card that ever held a root. |
| `roots/<label>/attestation/slot-<slot>.pem` | ritueel | The attestation certificate of one key, as the card made it: one file for each key of the root (`9c`, and the retired slots of the OpenPGP primary and of the break-glass SSH CA key). |
| `roots/<label>/attestation/card.pem` | ritueel | The token's own certificate (slot `f9`), which signed the slot certificates. |
| `roots/<label>/attestation/result.json` | ritueel | What ritueel read and checked, as below. |

All four are public material. The attestation files are written at `init` and `root add`, once, and never changed: a key is born once and never replaced in place ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)).

## The registry, `cards.yaml`

ritueel writes it; the operator does not edit it. A card is added at the ceremony that first uses it, and the plan names the row so that the person confirms it.

```yaml
version: 1
cards:
  - serial: "00000000"
    role: root:A
    maker: yubico
    firmware: 5.8.0
    form_factor: usb-c-keychain
    management_key: pin-protected
    slot_map: 1
    registered_at: 2026-11-15T12:00:00Z
```

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `serial` | The serial number the card reports about itself, as a string of digits. It identifies the card in every later check. |
| `role` | `root:<label>`: the root this card holds. One card holds one role, and one role is held by one card ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards): dedicated cards). |
| `maker` | The maker whose attestation roots verify it. `yubico` today. |
| `firmware` | The firmware version read when the card was registered. |
| `form_factor` | As read from the slot certificate. |
| `management_key` | `pin-protected`. Nothing else is accepted in the first version ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards)). |
| `slot_map` | The version of the slot map in force when the card was registered. |
| `registered_at` | The time of that ceremony, UTC. |
| `retired_at` | Present once the root it holds is retired or revoked. The row stays: a serial is never reused for another role. |

A serial number is the operator's own data and sits in the operator's directory, not in this repository ([public content](/contributing/public-content/#hardware-tokens)).

## What is checked on a card

Before anything is written, in this order. A check that cannot run is `not-run` and the ceremony stops: it is never reported as passed ([principle 4](/principles/)). The code is the reason code of the command's JSON `reasons`.

| # | Check | Code | Exit |
|---|---|---|---|
| 1 | Exactly one card is the one chosen: `--card SERIAL`, or the only card connected. | `card-ambiguous` | 2 |
| 2 | No other program holds the card (`scdaemon`, a PKCS#11 module). The message names the way to free it. | `card-held` | 4 |
| 3 | The serial is in the registry with this role, or the ceremony registers it (`init`, `root add`) and the plan says so. | `card-unknown`, `card-wrong-role` | 3 |
| 4 | The firmware is at least `policy.min_firmware`. | `firmware-old` | 3 |
| 5 | The PIN has at least three tries left. | `pin-tries-low` | 4 |
| 6 | The PIN, the PUK and the management key are not the factory values. | `pin-default`, `puk-default`, `management-key-default` | 4 |
| 7 | The management key is protected by the PIN. | `management-key-unprotected` | 3 |
| 8 | Every slot the ceremony will write is empty, and every slot it will use holds the key the directory says. | `slot-occupied`, `slot-mismatch` | 3 |
| 9 | After a key is made: its attestation chains to the maker's pinned root through the bundle, its public key is the one the card reports, and its policies are what `policy` asks (PIN `always`, touch `always`). | `attestation-failed`, `policy` | 3 |

Check 6 reads whether each secret is still at its factory value from the card's own report (firmware 5.3 and later), as `ykman piv info` does when it prints "Using default PIN" (ykman 5.8.0, source read 2026-11-02). ritueel never guesses a PIN to find out. Where a card cannot report it, the check is `not-run` and the card is refused. That the report spends no PIN try is measured on a test card before the store is called supported ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## `result.json`

One canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)).

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `store` | `piv`. |
| `serial`, `firmware`, `form_factor` | As read from the chain, not from the card's own claim. |
| `keys` | A list, one for each key: `{ "purpose", "slot", "public_key_sha256", "pin_policy", "touch_policy" }`. `purpose` is `x509-root`, `openpgp-primary` or `ssh-break-glass`; `public_key_sha256` is the SHA-256 of the DER `SubjectPublicKeyInfo`; the policies are `never`, `once`, `always` and `cached` as the slot certificate states them. |
| `bundle` | `{ "version", "sha256" }`: the bundle that verified the chain. |
| `extra_intermediates` | True when a file given by `--extra-intermediates` supplied an intermediate that the bundle lacked. |
| `checked_at` | The ceremony time. |

## The attestation bundle

The chain of a slot certificate is checked with ritueel's own copy of the maker's roots and intermediates, not with piv-go's built-in list, which lacks the intermediate that firmware 5.8 uses ([Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/), measured 2026-11-01).

- **What it is.** One PEM file in the source tree, embedded in the binary: the maker's current attestation root and every intermediate it publishes, for each maker. Beside it, in the source, the SHA-256 of the root's public key as a pin. A release carries the bundle as it was on the day of the release, and `result.json` records its version.
- **What it trusts.** Only the pinned root. An intermediate is a helper that must chain to the root; nothing in a card's own answer is trusted ([the contract](/reference/hand-off-contract/#piv): "A root in the file is never trusted").
- **A card whose intermediate is missing** is refused with `attestation-failed` until the bundle is refreshed. The holder may supply the missing intermediate with `--extra-intermediates FILE`; it is used only as a helper, so it still has to chain to the pinned root, and `result.json` says it was used.

### Refreshing it

A refresh is a reviewed change to the repository, made when a maker adds an intermediate or a root, and at least once before each release.

1. Fetch the maker's published files over HTTPS: for Yubico, the root and the intermediate bundle on `developers.yubico.com/PKI/` (read and fetched 2026-11-02: `Yubico Attestation Root 1`, and 15 intermediates).
2. Check that the root's public key still has the pinned SHA-256. A different root is not a refresh: it is a decision, and goes to the maintainer.
3. Replace the bundle, and bump its version (the date).
4. Run the test below, and commit the bundle with the output of the diff of the certificate subjects and validity in the message.

### The test

A test with no hardware verifies a recorded chain for every firmware family the project supports (5.7 and later; older firmware chains to the earlier PIV root and is not in the first version). It fails when a chain does not verify against the bundle, and it has three negative cases: a wrong root, a missing intermediate and a modified extension. A card is not needed to run it; one run on a real test card checks the same chain end to end ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Other makers

A maker joins the bundle when a store for it is admitted ([ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold)). A token that offers no attestation has no bundle and cannot hold a root.

## Follow-ups

- The `piv` store, the registry, the checks, the bundle and its test ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- Measure that reading the factory-value report spends no PIN try, on firmware 5.8 ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | Certificate path validation of the attestation chain. |
| [NIST SP 800-73-4](https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final) | The PIV interface: slots, PIN and management key. |
| [Yubico PIV attestation](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html) | The slot certificate, the token certificate and the extensions under `1.3.6.1.4.1.41482.3`. |
