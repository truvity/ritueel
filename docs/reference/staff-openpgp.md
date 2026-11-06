---
title: Staff OpenPGP
description: What ritueel does for staff keys that sluis binds and certifies, namely the card helper, the proof bundle, the attestation rule and the delegation.
sidebar:
  order: 16
---

*Not built yet. This is the page that [ADR 0014](/decisions/0014-staff-openpgp-primaries-born-on-cards-bound-and-certified-by-sluis-ritueel-makes-the-card-ready-and-runs-the-delegation/) leaves for the details; that record is `Accepted`. The code is [issue #103](https://github.com/truvity/ritueel/issues/103), after the first version. It builds on the `openpgp-card` store ([issue #18](https://github.com/truvity/ritueel/issues/18)). A person's own key is a different flow: [Personal OpenPGP](/reference/personal-openpgp/).*

A staff key is an OpenPGP primary born on the person's own card, bound to the person's identity and certified by sluis, not by ritueel. ritueel's part is three things: the company roots, the **delegation** in which the root makes a trust signature over sluis's certifying intermediate, and the **card helper** that makes a card ready and writes the proof bundle that `sluis key bind` reads. How sluis binds, records, certifies, renews, builds the staff keyring and syncs it is in the sluis ADR on key bindings (being written), and that record decides where the two differ.

## The card

A staff card is a YubiKey 5 with firmware 5.7.0 or newer, dedicated to the staff key. The floor is the one of every card in ritueel ([cards](/reference/cards/#the-attestation-bundle)): firmware 5.7 and newer chain to the maker's current attestation root. The OpenPGP applet holds one key in each slot (signature, decryption, authentication), so a staff card holds no personal key of [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/); a person who keeps both uses two cards. Each person has two staff cards, each with its own primary.

| Key | Slot | Algorithm | Key flags | Made by the helper |
|---|---|---|---|---|
| Primary | signature | ECDSA P-384, version 4, SHA-384 | certify and sign, `0x03` | Generated on the card. One user ID, `<name> <address>`, self-certified by the card. Expires after about 3 years (PX1), extended at the card. |
| Authentication subkey | authentication | ECDSA P-384 | authenticate, `0x20` | Generated on the card, bound by the primary, with a back-signature by the subkey, for SSH through `gpg-agent` ([the guide](/guides/openpgp-ssh-authentication/)). |

There is no encryption key. P-384 and SHA-384 are the rule of the [hand-off contract](/reference/hand-off-contract/#keys-and-hashes), so the card primary needs no exception to it. The primary expires after about three years (the maintainer's decision PX1, 2026-11-06) and the person extends it at the card with the PIN and a touch; a key on a lost card, or one nobody extends, ends by itself. The key is otherwise replaced on an event, as [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/#how-long-a-persons-primary-lives) says for a hardware key, and the company's trust in it also ends when sluis's certification ends. After an extension the person gives sluis the extended certificate, and sluis's App uploads the key again to the hosting account.

## The commands

| Command | Does | Needs the person |
|---|---|---|
| `ritueel staff card prepare --card SERIAL` | Checks the firmware floor; changes the PIN and the Admin PIN at the terminal, without echo; sets the touch policy for each key. Stores no PIN. | Yes |
| `ritueel staff proof make --card SERIAL --name NAME --address ADDRESS [--challenge TEXT] --out DIR` | One ceremony ([below](/reference/staff-openpgp/#the-ceremony-of-proof-make)): generates the primary and the authentication key on the card, reads the attestations, self-certifies, signs the challenge, and writes the proof bundle. Also writes the revocation signature, apart, to `--revocation-out`. | Yes |
| `ritueel staff proof check BUNDLE` | The helper's own check of a bundle, for the person to see before giving it to sluis: the same checks as [below](/reference/staff-openpgp/#what-a-binder-checks), offline. | No |
| `ritueel staff expiry extend --card SERIAL` | Extends the primary's expiry by a new self-certification made by the card, about 3 years from now, and rewrites the bundle for sluis. Warns when the expiry is within 6 months. | Yes |
| `ritueel staff user-id add --card SERIAL --address ADDRESS` | The mover: the card's primary certifies a new user ID, and the bundle is rewritten for a new bind. | Yes |

No command makes a network call. The bundle is files the person carries to `sluis key bind`. `--challenge` is the text sluis gives for the bind; its content and freshness are sluis's. Without it the possession proof is the self-certification alone, which proves the key but not that it is fresh.

### The ceremony of `proof make`

It is the six steps of every ceremony ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)), with the person's card as the store.

1. **Plan.** The card's serial and firmware, the slots to be generated, the user ID, the touch policy, and the challenge. A slot that already holds a key is not overwritten: the plan stops and says so, and the person decides to reset the applet with the maker's tool.
2. **Confirm** by typing the first eight characters of the plan digest.
3. **Reserve, and birth.** The attempt is written; the card generates the keys after the user PIN is verified at the terminal.
4. **Attest.** The attestation of each key is read with the maker's command and checked against the maker's pinned bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The card self-certifies the user ID, binds the authentication subkey and signs the challenge; each needs the PIN and a touch.
6. **Verify and record.** The certificate is parsed back, every signature verified, and the bundle and a local record are written.

A crash leaves what [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves) says a birth leaves: a key on the card with no record, found and finished or reset at the next run.

## The proof bundle

Version 1, a message of three files that share a stem, as in [the contract](/reference/hand-off-contract/#messages-and-files). JSON rules are those of the contract's files: one UTF-8 object, no member twice, an unknown member is an error, times in `YYYY-MM-DDThh:mm:ssZ`, certificates in standard Base64 of their DER.

| File | Holds |
|---|---|
| `<stem>.staff.pgp` | Binary OpenPGP: the primary public key, the user ID, the card's self-certification, the authentication subkey with its binding and its back-signature. Every signature carries the issuer fingerprint (hashed) and the issuer key ID (unhashed), as in [the contract](/reference/hand-off-contract/#issuer-key-id). |
| `<stem>.proof.json` | The proof, below. |
| `<stem>.possession.sig` | Binary OpenPGP: one signature packet of type `0x00` by the primary over the bytes of the challenge, SHA-384. Absent when no challenge was given. |

The revocation signature is not in the bundle. It is the person's, and anyone who holds it can revoke the key.

`<stem>.proof.json`:

| Member | Required | Meaning |
|---|---|---|
| `staff_proof` | yes | The bundle version, `1`. |
| `staff_sha256` | yes | SHA-256 of the `.staff.pgp` file. Binds the proof to its certificate. |
| `address` | yes | The address in the user ID. |
| `store` | yes | `openpgp-card`. |
| `evidence` | yes | `{ "primary": [<key cert>, <card cert>], "authentication": [<key cert>, <card cert>] }`: for each key, the certificate the card returns for it and then the card's attestation certificate that signed it, leaf first ([the contract](/reference/hand-off-contract/#openpgp-card)). |
| `firmware` | yes | The firmware version the helper read, as a claim. A binder reads it from the certificates, not from here. |
| `challenge` | when `.possession.sig` is present | The challenge text. |

## What a binder checks

sluis decides what it checks; this is what the bundle is built to let it check, and the helper's `proof check` makes the same checks offline. No check here is the helper trusting itself: a binder re-makes every one.

| # | Check |
|---|---|
| 1 | The version, `staff_sha256`, and that the files parse. |
| 2 | The primary is ECDSA P-384, version 4; the self-certification verifies and its key flags are `0x03`, taken from that signature and not from the attestation. |
| 3 | The user ID is `<name> <address>` with the `address` of the proof. Whether the address belongs to the authenticated person is the binder's. |
| 4 | The authentication subkey is ECDSA P-384, flags `0x20`, its binding verifies under the primary and its back-signature under the subkey. |
| 5 | Each attestation chain verifies to the maker's pinned root through its intermediates, every certificate valid; the attested public key is the key in the certificate; the firmware is 5.7.0 or newer. |
| 6 | The possession signature verifies under the primary over the challenge, and the challenge is the one the binder issued. |

## The attestation rule, and what is not yet known

The card attests a key that was generated on it. `ykman openpgp keys attest` takes the slots `sig`, `enc` and `aut`, and "an asymmetric key was generated on the YubiKey and therefore does not exist outside the device" is what it shows ([Yubico, read 2026-11-06](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)). The signature slot holds the card-born certify-and-sign primary, so the primary can be attested in principle. The attestation says nothing about key flags; those are in the self-certification and are checked from it.

**Unverified.** The Yubico pages read on 2026-11-06 ([the applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)) say that attestation exists from firmware 5.2.3 and list the slots, but do not say that a P-384 key in the signature slot is attested, that the same key can make certifications, or what the extensions of the attestation contain. The conformance test settles it:

- generate a P-384 primary in the signature slot of a test card, attest it, and check that the attested public key is the primary's;
- make a self-certification, a subkey binding and a certification of another key with it, and check them with `gpg`, `gpgv` and `sqv`;
- upload the certificate to a test account on the hosting platform, and sign and verify a commit with the card;
- extend the expiry on the card, upload the extended certificate to the same account, and see whether the platform accepts it over the stored one or needs the old key deleted first (unmeasured; its REST documentation lists create, list, get and delete only, read 2026-11-06);
- record the extensions of the attestation, to read the PIN and touch policy from them later.

## The delegation

The ceremony in which the company root delegates to sluis's certifying intermediate (O1 a). It is the OpenPGP hand-off for an intermediate with a new type, `openpgp-certifier`, and an ordinary root ceremony.

| Part | Value |
|---|---|
| Requester sends | The public key of the certifying intermediate, version 4, ECDSA P-384; a self-signature as the proof of possession; a proof file of where the key lives (a cloud key service or a card). |
| Certifier checks | The checks of [the contract](/reference/hand-off-contract/#what-the-certifier-checks-1) that apply to a key and its possession, the evidence of the store, and that the key is not already a primary on the root list. |
| What comes back | The intermediate's key with one certification by the root: type `0x13`, a Trust Signature subpacket with level 1 and amount 120, a Regular Expression subpacket limiting the user IDs to the company's domain (marked critical, null-terminated, RFC 9580 sections 5.2.3.21 and 5.2.3.22), exportable, key expiration and signature expiration of about 13 months. |
| Renewal | At the root's yearly ceremony, or under a cloud root's declared policy, like every intermediate. |
| Revocation | By the root, as for an intermediate ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). |

The contract gains the type with its checks and test vectors in a follow-up; until then this table is the specification and the contract is unchanged. Whether a verifier evaluates the trust signature, and the domain expression, is measured per verifier; `gpgv` does no web of trust at all.

## Follow-ups

- The helper, the bundle and its vectors ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The conformance test above, on a real test card ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The type `openpgp-certifier` in the contract, its vectors, and the delegation ceremony ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- Which verifiers evaluate the trust signature and its expression ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The attestation extensions of the OpenPGP applet ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Sources

| Source | What it fixes |
|---|---|
| [Yubico, ykman OpenPGP commands](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html), read 2026-11-06 | `keys attest` for the slots `sig`, `enc` and `aut`; what an attestation shows. |
| [Yubico, the OpenPGP applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), read 2026-11-06 | Attestation from firmware 5.2.3; one key in each slot; the algorithms of the applet. |
| [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), sections 5.2.3.21, 5.2.3.22 | The trust signature and the regular expression subpackets. |
