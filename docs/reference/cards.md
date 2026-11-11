---
title: Cards, the inventory and the attestation bundle
description: The four kinds of card, the card inventory cards.yaml and cards/NAME.yaml, the checks made on a card, the attestation files kept for each root key, and the maker's bundle.
sidebar:
  order: 9
---

*Not built yet. This is the page that [ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/) leaves for the formats of the `piv` store; the code is [issue #11](https://github.com/truvity/ritueel/issues/11): the inventory files come with M2, and the `piv` store and the card adoption with M6. The rows of slots are in [ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-rows) and [ADR 0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) and are not repeated here.*

A root card is a hardware token that holds roots and nothing else: the roots of one holder, each in its own row ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-rows)). It is never also a day-to-day card, an HSM card or a rehearsal card. Before it holds anything, the holder sets its PIN with the maker's tool ([Prepare a root card](/guides/prepare-a-root-card/)). ritueel then adopts it, which replaces the PUK and the management key with random ones sealed in the directory ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)); it registers the card, checks it before every ceremony, and keeps the evidence that a key was born on it. A root card goes only into a machine booted from the read-only offline system ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-root-card-is-used)).

## The four kinds

The inventory knows four kinds of card. A card has one kind and never changes it.

:::note[Proposed]
The name `hsm` for the third kind is proposed, awaiting the maintainer's word. An HSM card is an ordinary card that stays in a server, not a hardware security module product ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)).
:::

| Kind | What it is | What ritueel does with it |
|---|---|---|
| `root` | Holds roots by row. | Adopts it, seals its secrets, checks its layout; used in the offline system only. |
| `day-to-day` | A person's signing and authentication subkeys, and passkeys. | Adopts it; the Admin PIN is sealed. |
| `hsm` | Stays plugged into a server of a requester system and signs for its services. | Lists it in the inventory and only ever reads it. Its slots follow the requester's layout. No adoption, no sealed file, no layout check. |
| `rehearsal` | Practice and tests. It never holds a real key and may be reset. | Lists it. The M1 proofs and the drills use it. |

## Files

| Path | Written by | Holds |
|---|---|---|
| `cards.yaml` | ritueel | The inventory list: one entry for each card the holder registered, of any of the four kinds. |
| `cards/NAME.yaml` | ritueel | The map of one card: every slot of its PIV, OpenPGP and FIDO2 applications and what it is used for. |
| `cards/NAME.sealed.age` | ritueel | The card's secrets (management key, PUK and, on a day-to-day card, the Admin PIN of the OpenPGP application), sealed to the same recipients as the key files ([ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)). One file for each card that ritueel adopted, root and day-to-day. |
| `roots/<label>/attestation/slot-<slot>.pem` | ritueel | The attestation certificate of one key, as the card made it: one file for each key of the root, in the slots of the root's row. |
| `roots/<label>/attestation/card.pem` | ritueel | The token's own certificate (slot `f9`), which signed the slot certificates. |
| `roots/<label>/attestation/result.json` | ritueel | What ritueel read and checked, as below. |

The sealed file is not public material: it is safe only because the recipients' keys are. The other files are public material, and ritueel writes the inventory from the read-only check below; nobody edits it by hand. The attestation files are written at `init` and `root add`, once, and never changed: a key is born once and never replaced in place ([ADR 0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)).

## The inventory, `cards.yaml` and `cards/NAME.yaml`

:::note[Proposed]
The maintainer decided what the inventory holds (one file that lists the cards, one file per card that maps its slots). The file names, the members and the values below are the proposed shape, awaiting his word, and are fixed with the card proofs (M1).
:::

ritueel writes both files from the read-only check; the operator does not edit them ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-inventory)). A card is added at the ceremony that first uses it, and the plan names the entry so that the person confirms it.

### The list, `cards.yaml`

```yaml
version: 1
cards:
  - name: root-a
    serial: "00000000"
    kind: root
    maker: yubico
    model: example-model
    firmware: 5.8.0
    form_factor: usb-c-keychain
    applications: [piv]
    roots:
      - { root: A, row: 2 }
    management_key: sealed
    slot_map: 1
    registered_at: 2026-11-15T12:00:00Z
```

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `name` | The holder's name for the card. It names the card's map file and its sealed file. |
| `serial` | The serial number the card reports about itself, as a string of digits. It identifies the card in every later check. |
| `kind` | `root`, `day-to-day`, `hsm` or `rehearsal` ([the four kinds](/reference/cards/#the-four-kinds)). A card has one kind and never changes it. |
| `roots` | For a root card only: the roots it holds, each as `{ root, row }`, where `root` is the root's label and `row` its row in the slot map ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-rows)). |
| `maker` | The maker whose attestation roots verify it. `yubico` today. |
| `model` | The model, as read from the card. |
| `firmware` | The firmware version read when the card was registered. For a root card it is at least 5.7.4, which is ritueel's floor for a root card ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#rules-for-a-shared-card)). |
| `form_factor` | As read from the slot certificate. |
| `applications` | The applications of the card that are in use: a list of `piv`, `openpgp` and `fido2`. The one-time-code application is switched off on the root and day-to-day cards that ritueel adopts. |
| `management_key` | For root and day-to-day cards only, and absent for `hsm` and `rehearsal`. `sealed`: a random key that needs a touch to use, sealed in `cards/NAME.sealed.age`. Nothing else is accepted for a root card ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#root-cards), [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/#card-secrets)). |
| `slot_map` | The version of the slot map in force when the card was registered. |
| `registered_at` | The time of that ceremony, UTC. |
| `retired_at` | Present once the card holds no active root. The entry stays: a serial is never reused for another holder's card. |

A serial number is the operator's own data and sits in the operator's directory, not in this repository ([public content](/contributing/public-content/#hardware-tokens)).

### The map of one card, `cards/NAME.yaml`

One file for each card. It lists every slot of the card's PIV, OpenPGP and FIDO2 applications and says what the slot is used for. An unused slot is listed as unused, so that the read-only check can compare the whole card with the file.

```yaml
version: 1
name: root-a
slots:
  - { application: piv, slot: 9a, use: unused }
  - application: piv
    slot: 9c
    row: 2
    use: x509-root
    root: A
    algorithm: ecdsa-p384
    pin_rule: always
    touch_rule: always
    public_key_sha256: "<sha-256 of the public key>"
    born_at: 2026-11-15T12:00:00Z
    attestation: roots/A/attestation/slot-9c.pem
```

| Member | Meaning |
|---|---|
| `application`, `slot` | The application (`piv`, `openpgp` or `fido2`) and the slot or the key position in it. |
| `use` | What the slot is for: `unused`, or a purpose such as `x509-root`, `openpgp-primary`, `ssh-break-glass` or `unlock-key`. |
| `row` | For a PIV slot of a root card: its row in the slot map. |
| `root` | For a used slot of a root: the root's label. |
| `algorithm` | The key's algorithm. |
| `pin_rule`, `touch_rule` | `never`, `once`, `always` or `cached`, as the slot certificate states them. For a root key both are `always`. |
| `public_key_sha256` | The SHA-256 of the DER `SubjectPublicKeyInfo` of the public key. |
| `born_at` | The time the key was born, UTC. |
| `attestation` | The path of the attestation file of the key, in the directory. |

The format is version 1 and is fixed with the card proofs (M1), when the read-only check meets a real card.

## What is checked on a card

Checks 5 to 10 apply to adopted cards (root, day-to-day), and checks 8 to 10 to root cards. For an `hsm` card the read-only check lists what it finds (serial, model, firmware, applications, slots as found) and fails nothing about its layout; this sentence waits for the maintainer's word on the name above. For a `rehearsal` card, check 3 refuses it for any ceremony that needs another kind (`card-wrong-role`), so a real root can never be born on it.

Before anything is written, in this order. A check that cannot run is `not-run` and the ceremony stops: it is never reported as passed ([principle 4](/principles/)). The code is the reason code of the command's JSON `reasons`.

| # | Check | Code | Exit |
|---|---|---|---|
| 1 | Exactly one card is the one chosen: `--card SERIAL`, or the only card connected. | `card-ambiguous` | 2 |
| 2 | No other program holds the card (`scdaemon`, a PKCS#11 module). The message names the way to free it. | `card-held` | 4 |
| 3 | The serial is in the inventory with the kind the ceremony needs, and the root's row is free or holds the key the directory says; or the ceremony registers the card (`init`, `root add`) and the plan says so. | `card-unknown`, `card-wrong-role` | 3 |
| 4 | The firmware is at least `policy.min_firmware`, and for a root card at least 5.7.4. | `firmware-old` | 3 |
| 5 | The PIN has at least three tries left. | `pin-tries-low` | 4 |
| 6 | The PIN, the PUK and the management key are not the factory values. | `pin-default`, `puk-default`, `management-key-default` | 4 |
| 7 | The management key is the sealed one: it opens with the secret sealed in the directory, and the card needs a touch to use it. | `management-key-unsealed` | 3 |
| 8 | Every slot the ceremony will write is empty, and every slot it will use holds the key the directory says. | `slot-occupied`, `slot-mismatch` | 3 |
| 9 | Every used root slot carries a placeholder certificate, and the whole card equals the built-in layout of its rows. Anything else on the card is reported. | `card-layout` | 3 |
| 10 | After a key is made: its attestation chains to the maker's pinned root through the bundle, its public key is the one the card reports, and its policies are what `policy` asks (PIN `always`, touch `always`). | `attestation-failed`, `policy` | 3 |

The firmware floor of check 4 is ritueel's own rule ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#rules-for-a-shared-card)); that deleting one slot works on that firmware is tried on a rehearsal card in M1. Check 6 reads whether each secret is still at its factory value from the card's own report (firmware 5.3 and later), as `ykman piv info` does when it prints "Using default PIN" (ykman 5.8.0, source read 2026-11-02). ritueel never guesses a PIN to find out. Where a card cannot report it, the check is `not-run` and the card is refused. That the report spends no PIN try is measured on a test card before the store is called supported ([issue #11](https://github.com/truvity/ritueel/issues/11)).

### Every six months

The card check above runs every six months, with a proof of life, between the yearly ceremonies. [ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#where-a-root-card-is-used) decides the rhythm; the proof of life is a short test that the card still works for its holder; its exact steps are written here when the check is built. Showing when a card was last checked in `ritueel status` is tracked in [issue #30](https://github.com/truvity/ritueel/issues/30).

## `result.json`

One canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)).

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `store` | `piv`. |
| `serial`, `firmware`, `form_factor` | As read from the chain, not from the card's own claim. |
| `keys` | A list, one for each key: `{ "purpose", "row", "slot", "public_key_sha256", "pin_policy", "touch_policy" }`. `purpose` is `x509-root`, `openpgp-primary` or `ssh-break-glass`; `public_key_sha256` is the SHA-256 of the DER `SubjectPublicKeyInfo`; the policies are `never`, `once`, `always` and `cached` as the slot certificate states them. |
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

- The `piv` store, the inventory, the checks, the bundle and its test ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- Measure that reading the factory-value report spends no PIN try, on firmware 5.8 ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | Certificate path validation of the attestation chain. |
| [NIST SP 800-73-4](https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final) | The PIV interface: slots, PIN and management key. |
| [Yubico PIV attestation](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html) | The slot certificate, the token certificate and the extensions under `1.3.6.1.4.1.41482.3`. |
