---
title: Cards, the card files and the attestation bundle
description: The four kinds of card, the card file and the card map, the checks made on a card, and the attestation files kept for each root key
sidebar:
  order: 9
---

*Not built yet. This is the page that [record 0003](../decisions/0003-root-cards.md) leaves for the formats of the `piv` store; the code is [issue #11](https://github.com/truvity/ritueel/issues/11): the card files and the card maps come with M2, and the `piv` store and the card adoption with M6. The rows of slots are in that record and are not repeated here. The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

A root card is a hardware token that is used for root keys only: the root keys of the holder's bundles, each bundle in its own row, and the card's own jobs in row 1 ([record 0003](../decisions/0003-root-cards.md), rules 3 and 15). It is never also a day-to-day card, a server card or a rehearsal card. Before it holds anything, the holder sets its PIN with the maker's tool ([Prepare a root card](/guides/prepare-a-root-card/)). ritueel then adopts it, which replaces the PUK and the management key with random ones sealed in the bundle ([record 0003](../decisions/0003-root-cards.md)); it registers the card, checks it before every ceremony, and keeps the evidence that a key was born on it. A root card is used on the holder's workstation, under the four conditions of [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md) (a touch for every signature, the number of signatures stated in the plan, no retry of a failed touch, and a check on a second device), or in the offline system, by the rules of the ceremony record ([record 0003](../decisions/0003-root-cards.md)).

## The four kinds

A card file names one of four kinds of card. A card has one kind and never changes it.

A server card works like a small do-it-yourself HSM, but it is an ordinary card, not a hardware security module product ([record 0003](../decisions/0003-root-cards.md)).

| Kind | What it is | What ritueel does with it |
|---|---|---|
| `root` | Holds root keys by row. | Adopts it, seals its secrets, checks its layout; used on the workstation or in the offline system, by the rules of the ceremony record. |
| `day-to-day` | A person's signing and authentication subkeys, and passkeys. | Adopts it; the Admin PIN is sealed. |
| `server` | Stays plugged into a server of a requester system and signs for its services. | Lists it and only ever reads it. Its slots follow the requester's layout. No adoption, no sealed file, no layout check. |
| `rehearsal` | Practice and tests (earlier pages and dated research call it a "test card"). It never holds a real key, may be reset, and serves only a test root. | Lists it. The M1 proofs and the drills use it. |

## Files

| Path | Written by | Holds |
|---|---|---|
| `want/cards/NAME.yaml` | A person | The card file: one for each card this bundle uses, of any of the four kinds. It holds the card's serial and kind, and the rows of other bundles that the card declares. |
| `cards/NAME.yaml` (proposed path; the bundle page has `seen/` and `sealed/`) | ritueel | The map of one card: every slot of its PIV, OpenPGP and FIDO2 applications and what it is used for. |
| `cards/NAME.sealed.age` (proposed path; the bundle page has `seen/` and `sealed/`) | ritueel | This bundle's own copy of the card's secrets (management key, PUK and, on a day-to-day card, the Admin PIN of the OpenPGP application), sealed to the same recipients as the key files ([record 0003](../decisions/0003-root-cards.md)). One file for each card that ritueel adopted, root and day-to-day. |
| `roots/<label>/attestation/slot-<slot>.pem` | ritueel | The attestation certificate of one key, as the card made it: one file for each key born for the root key, in the slots of this bundle's row. |
| `roots/<label>/attestation/card.pem` | ritueel | The token's own certificate (slot `f9`), which signed the slot certificates. |
| `roots/<label>/attestation/result.json` | ritueel | What ritueel read and checked, as below. |

The sealed file is not public material: it is safe only because the recipients' keys are. The other files are public material. A person writes the card file; ritueel writes the card map from the read-only check below, and nobody edits it by hand. The attestation files are written at the first `apply` and at an `apply` that adds a root key, once, and never changed: a replacement key is born beside the old keys, in the row kept free for it, and has its own files ([record 0003](../decisions/0003-root-cards.md)).

## The card file and the card map

:::note[Proposed]
The maintainer decided what the bundle holds for cards: one wanted card file for each card, which a person writes, and one card map for each card, which ritueel writes. The file names, the members and the values below are the proposed shape, awaiting his word, and are fixed with the card proofs (M1).
:::

A person writes the card file ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11). ritueel writes the card map from the read-only check, and nobody edits it ([record 0003](../decisions/0003-root-cards.md), rule 18). The plan names a card that the ceremony adopts, so that the person confirms it.

### The card file, `want/cards/NAME.yaml`

```yaml
version: 1
serial: "00000000"
kind: root
applications: [piv]
```

| Member | Meaning |
|---|---|
| `version` | `1`. |
| the file name | The holder's name for the card, not its serial ([record 0006](../decisions/0006-bundle-history-and-trust-files.md), rule 11). It names the card's map file and its sealed file. |
| `serial` | The serial number the card reports about itself, as a string of digits. It identifies the card in every later check. A serial is never reused for another holder's role ([record 0003](../decisions/0003-root-cards.md), rule 18). |
| `kind` | `root`, `day-to-day`, `server` or `rehearsal` ([the four kinds](/reference/cards/#the-four-kinds)). A card has one kind and never changes it. |
| `applications` | The applications of the card that this bundle uses: a list of `piv`, `openpgp` and `fido2`. |

A card file also declares the rows of other bundles that the card holds ([record 0003](../decisions/0003-root-cards.md), rule 8; [a pair shared by bundles](/reference/cards/#a-pair-shared-by-bundles)). Adoption replaces the management key by a random one that needs a touch to use, sealed in `cards/NAME.sealed.age`; nothing else is accepted for a root card (rule 10). The one-time-code application is switched off on the root and day-to-day cards that ritueel adopts (rule 16). The version of the slot map in force is written into every ceremony record (rule 4).

A serial number is the holder's own data and sits in the holder's bundle, not in this repository ([public content](/contributing/public-content/#hardware-tokens)).

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
| `root` | For a used slot of a root key: the root key's label. |
| `algorithm` | The key's algorithm. |
| `pin_rule`, `touch_rule` | `never`, `once`, `always` or `cached`, as the slot certificate states them. For a root key both are `always`. |
| `public_key_sha256` | The SHA-256 of the DER `SubjectPublicKeyInfo` of the public key. |
| `born_at` | The time the key was born, UTC. |
| `attestation` | The path of the attestation file of the key, in the bundle. |

The format is version 1 and is fixed with the card proofs (M1), when the read-only check meets a real card.

### A pair shared by bundles

A bundle that shares a pair of root cards with another keeps its own card files and its own sealed copy of the card secrets ([record 0003](../decisions/0003-root-cards.md)). As plain consequences: the card has one PIN, one PUK and one management key for all the bundles on it; a sealed copy that falls out of step with the card shows as check 7, `management-key-unsealed`; and a lost card is one transition in each bundle on it.

A second bundle cannot adopt the cards again. It gets its sealed copy by a request to the first bundle, which wraps the secrets for it; they never travel in the clear. Request and answer travel as in [record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md), rule 26. The ceremony record names the card's serial and never the other bundle ([record 0003](../decisions/0003-root-cards.md)). The six-monthly check and the proof of life run in each bundle and cover its own rows ([record 0007](../decisions/0007-changing-and-losing-a-root.md)).

:::note[Proposed]
How a second bundle lists a card that another bundle adopted is proposed, awaiting the maintainer's word, and is fixed with the card proofs (M1):

1. Each bundle's card files list the card for its own rows. The same serial may be in several bundles. The list of rows may be empty: a bundle that uses the card only for the passkey lists it with `applications: [fido2]`.
2. In `cards/NAME.yaml` a slot of another bundle's row is listed as `use: other-bundle` with its `row` and no key hash, because a hash would go stale when the other bundle replaces a root.
3. Check 9 compares this bundle's own rows exactly and the rest against the built-in layout. A row of another bundle that the card file declares is not a failure; an undeclared occupied row is a finding; a key outside the layout still fails with `card-layout`.
4. The plan takes the lowest row that is empty on the card, as the check reads it.
:::

## What is checked on a card

Checks 5 to 10 apply to adopted cards (root, day-to-day), and checks 8 to 10 to root cards. For a `server` card the read-only check lists what it finds (serial, model, firmware, applications, slots as found) and fails nothing about its layout. For a `rehearsal` card, check 3 refuses it for any ceremony that needs another kind (`card-wrong-role`), so a real root key can never be born on it. A test root is the one root a rehearsal card serves.

:::note[Proposed]
How a test root is born on a rehearsal card (the first `apply` of a bundle made with `new --test-root`) is proposed and fixed with the card proofs (M1), and so is which of the checks above run for a test root on a rehearsal card. No flag is added for it.
:::

Before anything is written, in this order. A check that cannot run is `not-run` and the ceremony stops: it is never reported as passed ([principle 4](/principles/)). The code is the reason code of the command's JSON `reasons`.

| # | Check | Code | Exit |
|---|---|---|---|
| 1 | Exactly one card is the one chosen: the card named with `--with` (name proposed), or the only card connected. | `card-ambiguous` | 2 |
| 2 | No other program holds the card (`scdaemon`, a PKCS#11 module). The message names the way to free it. | `card-held` | 4 |
| 3 | The serial is in a card file with the kind the ceremony needs, and the bundle's row is free or holds the key the bundle says; a card that is not adopted yet is adopted by the ceremony, and the plan says so. | `card-unknown`, `card-wrong-role` | 3 |
| 4 | The firmware is at least `policy.min_firmware`, and for a root card at least 5.7.4. | `firmware-old` | 3 |
| 5 | The PIN has at least three tries left. | `pin-tries-low` | 4 |
| 6 | The PIN, the PUK and the management key are not the factory values. | `pin-default`, `puk-default`, `management-key-default` | 4 |
| 7 | The management key is the sealed one: it opens with the secret sealed in the bundle, and the card needs a touch to use it. | `management-key-unsealed` | 3 |
| 8 | Every slot the ceremony will write is empty, and every slot it will use holds the key the bundle says. | `slot-occupied`, `slot-mismatch` | 3 |
| 9 | Every used root slot of this bundle's rows carries a placeholder certificate, and the whole card equals the built-in layout of its rows. Anything else on the card is reported. Proposed. A row of another bundle that the card file declares is not a failure; an undeclared occupied row is a finding; a key outside the layout still fails ([a pair shared by bundles](/reference/cards/#a-pair-shared-by-bundles)). | `card-layout` | 3 |
| 10 | After a key is made: its attestation chains to the maker's pinned root through the attestation bundle, its public key is the one the card reports, and its policies are what `policy` asks (PIN `always`, touch `always`). | `attestation-failed`, `policy` | 3 |

The firmware floor of check 4 is ritueel's own rule ([record 0003](../decisions/0003-root-cards.md)); that deleting one slot works on that firmware is tried on a rehearsal card in M1. Check 6 reads whether each secret is still at its factory value from the card's own report (firmware 5.3 and later), as `ykman piv info` does when it prints "Using default PIN" (ykman 5.8.0, source read 2026-11-02). ritueel never guesses a PIN to find out. Where a card cannot report it, the check is `not-run` and the card is refused. That the report spends no PIN try is measured on a rehearsal card before the store is called supported ([issue #11](https://github.com/truvity/ritueel/issues/11)).

Measured on 2026-11-12 with age-plugin-yubikey 0.5.1 on a YubiKey 5 with firmware 5.2.6: asked to generate a key with no slot named, the plug-in skipped a slot that held a key and a placeholder certificate (check 9; [record 0003](../decisions/0003-root-cards.md), rule 11), and took the next slot, which held a key but no certificate; it replaced that key without a question. So a key in a slot without a certificate is not protected. On a card at factory values the same run also changed the PIN, set the PUK equal to the new PIN and replaced the management key with one that the PIN protects. The limits are one card, one firmware, one version of the plug-in, and a placeholder made by the vendor tool, not yet by ritueel.

### Every six months

The card check above runs every six months, with a proof of life, between the yearly ceremonies. [record 0007](../decisions/0007-changing-and-losing-a-root.md) decides the rhythm; the proof of life is a short test that the card still works for its holder; its exact steps are written here when the check is built. Showing when a card was last checked in `ritueel status` is tracked in [issue #30](https://github.com/truvity/ritueel/issues/30).

## `result.json`

One canonical JSON object ([the common rules](/reference/ceremony-record/#common-rules)).

| Member | Meaning |
|---|---|
| `version` | `1`. |
| `store` | `piv`. |
| `serial`, `firmware`, `form_factor` | As read from the chain, not from the card's own claim. |
| `keys` | A list, one for each key: `{ "purpose", "row", "slot", "public_key_sha256", "pin_policy", "touch_policy" }`. `purpose` is `x509-root`, `openpgp-primary` or `ssh-break-glass`; `public_key_sha256` is the SHA-256 of the DER `SubjectPublicKeyInfo`; the policies are `never`, `once`, `always` and `cached` as the slot certificate states them. |
| `attestation_bundle` | `{ "version", "sha256" }`: the attestation bundle that verified the chain. |
| `extra_intermediates` | True when a file given by `--extra-intermediates` supplied an intermediate that the attestation bundle lacked. |
| `checked_at` | The ceremony time. |

## The attestation bundle

The chain of a slot certificate is checked with ritueel's own copy of the maker's roots and intermediates, not with piv-go's built-in list, which lacks the intermediate that firmware 5.8 uses ([Card libraries and tooling](/research/card-libraries-and-tooling-2026-11-01/), measured 2026-11-01).

- **What it is.** One PEM file in the source tree, embedded in the binary: the maker's current attestation root and every intermediate it publishes, for each maker. Beside it, in the source, the SHA-256 of the root's public key as a pin. A release carries the attestation bundle as it was on the day of the release, and `result.json` records its version.
- **What it trusts.** Only the pinned root. An intermediate is a helper that must chain to the root; nothing in a card's own answer is trusted ([the contract](/reference/hand-off-contract/#piv): "A root in the file is never trusted").
- **A card whose intermediate is missing** is refused with `attestation-failed` until the attestation bundle is refreshed. The holder may supply the missing intermediate with `--extra-intermediates FILE`; it is used only as a helper, so it still has to chain to the pinned root, and `result.json` says it was used.

### Refreshing it

A refresh is a reviewed change to the repository, made when a maker adds an intermediate or a root, and at least once before each release.

1. Fetch the maker's published files over HTTPS: for Yubico, the root and the intermediates file on `developers.yubico.com/PKI/` (read and fetched 2026-11-02: `Yubico Attestation Root 1`, and 15 intermediates).
2. Check that the root's public key still has the pinned SHA-256. A different root is not a refresh: it is a decision, and goes to the maintainer.
3. Replace the attestation bundle, and bump its version (the date).
4. Run the test below, and commit the attestation bundle with the output of the diff of the certificate subjects and validity in the message.

### The test

A test with no hardware verifies a recorded chain for every firmware family the project supports (5.7 and later; older firmware chains to the earlier PIV root and is not in the first version). It fails when a chain does not verify against the attestation bundle, and it has three negative cases: a wrong root, a missing intermediate and a modified extension. A card is not needed to run it; one run on a real rehearsal card checks the same chain end to end ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Other makers

A maker joins the attestation bundle ([record 0003](../decisions/0003-root-cards.md)) when a store for it is admitted, and a store is supported only after it is proven ([record 0002](../decisions/0002-where-a-key-lives.md)). A token that offers no attestation has no attestation bundle and cannot hold a root key that others rely on ([record 0002](../decisions/0002-where-a-key-lives.md)).

## Follow-ups

- The `piv` store, the card files and the card maps, the checks, the attestation bundle and its test ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- Measure that reading the factory-value report spends no PIN try, on firmware 5.8 ([issue #11](https://github.com/truvity/ritueel/issues/11)).

## Standards

| Standard | Used for |
|---|---|
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | Certificate path validation of the attestation chain. |
| [NIST SP 800-73-4](https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final) | The PIV interface: slots, PIN and management key. |
| [Yubico PIV attestation](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html) | The slot certificate, the token certificate and the extensions under `1.3.6.1.4.1.41482.3`. |
