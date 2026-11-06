---
title: Staff OpenPGP
description: What ritueel does for staff keys that sluis holds, namely the card helper, the proof bundle, the attestation rule and the delegation.
sidebar:
  order: 16
---

*Not built yet. This is the page that [ADR 0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/) leaves for the details; that record is `Accepted`. The code is [issue #103](https://github.com/truvity/ritueel/issues/103), after the first version. It builds on the `openpgp-card` store ([issue #18](https://github.com/truvity/ritueel/issues/18)). A person's own key is a different flow: [Personal OpenPGP](/reference/personal-openpgp/).*

A staff key is an OpenPGP primary that sluis generates and seals for one person in one company, with subkeys that the person's card generates under it. sluis binds the subkeys, records the binding, certifies the primary, builds the staff keyring and syncs it; none of that is ritueel's. ritueel's part is three things: the company roots, the **delegation** in which the root makes a trust signature over a sluis key, and the **card helper** that makes a card ready and writes the proof bundle that `sluis key bind` reads. The binding is in sluis ADR 0043 on key bindings ([pull request #1493](https://github.com/truvity/sluis/pull/1493)), read at commit `9aa256c`; **that record decides where the two differ**, and the file names, the challenge, the notation name, the expression, the key identity and the lifetimes below are copied from it.

## The card

A staff card is a YubiKey 5 with **firmware 5.7.4 or newer**, dedicated to the staff subkeys. Firmware 5.7.4 and newer are signed under the maker's new root, "Yubico Attestation Root 1", the only attestation root a staff binding pins; older cards are out, and a person with an older card needs a newer one. That is stricter than the 5.7.0 of ritueel's other cards ([cards](/reference/cards/#the-attestation-bundle)), and the allowlist is sluis's: the helper mirrors it. The OpenPGP applet holds one key in each slot (signature, decryption, authentication), so a staff card holds no personal key of [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/); a person who keeps both uses two cards. Each person has two staff cards, each with its own subkeys, under the one primary.

| Key | Slot | Algorithm | Key flags | Made by the helper |
|---|---|---|---|---|
| Signing subkey | signature | ECDSA P-384, version 4, SHA-384 | sign, `0x02` | Generated on the card. A back-signature by the card over the person's primary and the subkey. |
| Authentication subkey | authentication | ECDSA P-384 | authenticate, `0x20` | Generated on the card, for SSH through `gpg-agent` ([the guide](/guides/openpgp-ssh-authentication/)), with a back-signature as above. |

There is no encryption key, and **no key on the card certifies**: the primary is sluis's. P-384 and SHA-384 are the rule of the [hand-off contract](/reference/hand-off-contract/#keys-and-hashes) for a subkey, so the card keys need no exception. The key flags are in the binding that sluis's primary makes. The binding of a subkey expires after 1095 days, about three years (the maintainer's decision PX1, 2026-11-06, carried to the subkeys); the person extends it with a proof from the card and sluis signs. A key nobody extends ends by itself.

**Only attested subkeys may appear.** The helper produces exactly the two keys above, both generated on the card and both attested, and puts nothing else in the bundle. A subkey made by another tool, an encryption subkey, a software subkey or one without an attestation is never in it. `proof check` and a binder refuse a bundle that holds one (`subkey-not-attested`). Every command that rewrites the bundle re-reads the card and re-checks this first.

## The commands

| Command | Does | Needs the person |
|---|---|---|
| `ritueel staff card prepare --card SERIAL` | Checks the firmware floor; changes the PIN and the Admin PIN at the terminal, without echo; sets the touch policy for each key. Stores no PIN. | Yes |
| `ritueel staff proof make --card SERIAL --primary FILE --out DIR` | One ceremony ([below](/reference/staff-openpgp/#the-ceremony-of-proof-make)): generates the signing and authentication keys on the card, reads the attestations, makes the back-signatures over the primary in `FILE`, and writes the subkey file and the proof, without a challenge signature. | Yes |
| `ritueel staff challenge sign --card SERIAL --challenge FILE --out DIR` | Signs a challenge from `sluis key bind` with the card's signing subkey, and writes `<stem>.possession.sig` into the bundle. The card is the one whose signing subkey has the key identity named in the challenge's `key` line: for a first bind that is the new card, and for `add`, `end` and `change` it is an existing bound card. See [the challenge](/reference/staff-openpgp/#the-challenge). | Yes |
| `ritueel staff proof refresh --card SERIAL --out DIR` | For an extension: re-reads the card's attestations and rebuilds the proof for the same subkeys. No key is made. A fresh `challenge sign` with `action: change` follows. | Yes |
| `ritueel staff proof check BUNDLE` | The helper's own check of a bundle, for the person to see before giving it to sluis: the same checks as [below](/reference/staff-openpgp/#what-a-binder-checks), offline. | No |

`FILE` is the public key of the person's primary, which `sluis key bind` gives. No command makes a network call. The files are carried by the person to `sluis key bind`, which reads **bundle version 1**; the bundle's format and its test vectors are shared by this repository and sluis, so that each side can be tested against the same files. The handshake is **key-first**: `sluis key bind` gives the primary; `proof make` generates on the card; `sluis key bind` then issues a challenge that names the person, the boundary and the key; `challenge sign` signs it. Each card has its own challenge. An extension ends the same way, with a fresh challenge. There is no command for a changed address: the primary is sluis's, so the user ID is sluis's to change, from its directory, and sluis asks nothing of the card for it.

### The ceremony of `proof make`

It is the six steps of every ceremony ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)), with the person's card as the store.

1. **Plan.** The card's serial and firmware, the slots to be generated, the fingerprint of the primary, and the touch policy. A slot that already holds a key is not overwritten: the plan stops and says so, and the person decides to reset the applet with the maker's tool.
2. **Confirm** by typing the first eight characters of the plan digest.
3. **Reserve, and birth.** The attempt is written; the card generates the keys after the user PIN is verified at the terminal.
4. **Attest.** The attestation of each key is read with the maker's command and checked against the maker's pinned bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The card makes the back-signature of each subkey over the primary and the subkey; each needs the PIN and a touch. The challenge is signed afterwards, by `challenge sign`.
6. **Verify and record.** The subkey file is parsed back, every back-signature verified, and the bundle and a local record are written.

A crash leaves what [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves) says a birth leaves: a key on the card with no record, found and finished or reset at the next run.

## The proof bundle

Version 1, a message of up to three files that share a stem, as in [the contract](/reference/hand-off-contract/#messages-and-files). JSON rules are those of the contract's files: one UTF-8 object, no member twice, an unknown member is an error, times in `YYYY-MM-DDThh:mm:ssZ`, certificates in standard Base64 of their DER.

| File | Holds |
|---|---|
| `<stem>.subkey.pgp` | Binary OpenPGP in the form of [the contract's subkey request](/reference/hand-off-contract/#the-request-1), for one primary: for each of the two subkeys, a Public-Subkey packet followed by one back-signature (type `0x19`) made by the card, with the issuer fingerprint (hashed) and the issuer key ID (unhashed) ([the contract](/reference/hand-off-contract/#issuer-key-id)). The back-signature of the signing subkey is the one OpenPGP requires; the one of the authentication subkey is the helper's addition (below). The primary is not in it. |
| `<stem>.proof.json` | The attestation statement and chain of each subkey, below. |
| `<stem>.possession.sig` | Binary OpenPGP: one version 4 standalone signature (type `0x02`) by the signing subkey, SHA-384, with the challenge as the value of a critical hashed notation named `bind-challenge@sluis.id`, flagged human-readable ([below](/reference/staff-openpgp/#the-challenge)). Written by `challenge sign`; absent until then. |

This is not an exchange of the contract: the primary is not on a root list of ritueel's, and the party that binds is sluis. The file form is the contract's so that one parser reads both.

`<stem>.proof.json`:

| Member | Required | Meaning |
|---|---|---|
| `bundle` | yes | The bundle version, `1`. |
| `primary` | yes | The version 4 fingerprint of the primary the back-signatures are for, 40 hexadecimal digits, as `sluis key bind --primary` gives it. sluis ADR 0043 does not say how the proof names the primary; this is the helper's choice, open in the pull request. |
| `key` | yes | The key identity of the signing subkey: the SHA-256 hash of its public key material, in 64 hexadecimal digits ([the challenge](/reference/staff-openpgp/#the-challenge)). |
| `subkey_sha256` | yes | SHA-256 of the `.subkey.pgp` file. Binds the proof to its subkeys. |
| `store` | yes | `openpgp-card`. |
| `evidence` | yes | `{ "signature": [<key cert>, <card cert>], "authentication": [<key cert>, <card cert>] }`: for each key, the certificate the card returns for it and then the card's attestation certificate that signed it, leaf first ([the contract](/reference/hand-off-contract/#openpgp-card)). |
| `firmware` | yes | The firmware version the helper read, as a claim. A binder reads it from the certificates, not from here. |

## What a binder checks

sluis decides what it checks; this is what the bundle is built to let it check, and the helper's `proof check` makes the same checks offline. No check here is the helper trusting itself: a binder re-makes every one.

| # | Check |
|---|---|
| 1 | The version, `subkey_sha256`, `key`, and that the files parse. |
| 2 | Each subkey is ECDSA P-384, version 4, with a back-signature of type `0x19` that verifies under the subkey over the primary named in `primary` and the subkey, and carries both issuer subpackets. |
| 3 | Each attestation chain verifies to the maker's pinned root through its intermediates, every certificate valid; the attested public key is the subkey's; the firmware is at or above the allowlist's floor. |
| 4 | The possession signature verifies under the signing subkey, is of type `0x02`, carries the challenge in a critical hashed notation `bind-challenge@sluis.id`, and the challenge is the one the binder issued: its eight lines, its `person`, `boundary`, `key` and `target`, its `nonce`, and an `expires` not passed. |
| 5 | The bundle holds no subkey other than the two attested ones (`subkey-not-attested`). |

The key flags of a subkey are those of the binding that the primary makes, which only the binder makes; nothing a card says about them is read.

## The challenge

The challenge is sluis's, and its bytes are defined by sluis ADR 0043, which wins; they are copied here so that the helper can be written from this page. **Eight lines of UTF-8 text, each ending in a line feed, in this order, with nothing before, between or after:**

```text
sluis-key-bind-v1
action: bind
person: <subject>
boundary: <boundary id>
key: <key identity of the signing key, 64 hex digits>
target: <key identity the action is about, 64 hex digits>
nonce: <256 random bits, 64 hex digits>
expires: <RFC 3339 UTC time, to the second, ending in Z>
```

- **`action`** is `bind`, `add`, `end` or `change`. For a first bind `key` and `target` are the same. For `add`, `end` and `change`, `key` is the existing key that vouches and `target` the key the action is about. The challenge lives 600 seconds and is used once.
- **The key identity** is the SHA-256 hash of the public key material of the card's signing subkey: the algorithm, the curve and the public point, and nothing else. It is not the version 4 fingerprint, which covers a creation time the holder chooses. ADR 0043 does not fix the byte encoding of what is hashed; the helper and sluis must agree on it, and it is open in the pull request.
- **The signature is not a document signature.** A plain signature of type `0x00` over a labelled text is hashed with the data it follows, and lenient formats tolerate extra lines, so a label inside such a text separates nothing. The proof is a **version 4 standalone signature (type `0x02`)**, which signs only its own subpackets, made by the signing subkey, with the challenge as the value of a **critical** hashed Notation Data subpacket named `bind-challenge@sluis.id`, flagged human-readable (RFC 9580, sections 5.2.1 and 5.2.3.24). It parses as no commit, tag, checksum or certification, and a verifier that does not know the critical notation must reject it.
- **What the label does not protect.** The card signs the digest it is handed and does not see the text. The protection is on the host: **the helper refuses before it signs** a challenge that lacks the label, has other lines, or has an `expires` in the past; it shows the whole challenge before it asks for the PIN; it checks that `key` is the key identity of the card it signs with; and it builds the type `0x02` packet itself. A hostile host or a hostile helper can ask the card to sign any digest, and the PIN and the touch are what stand between a card and an unwanted signature.
- **The conformance test** ([below](/reference/staff-openpgp/#the-attestation-rule-and-what-is-not-yet-known)) checks with `gpg` and `sqv` that the signature parses, and that neither accepts it as a signature over any document.

## The attestation rule, and what is not yet known

The card attests a key that was generated on it. `ykman openpgp keys attest` takes the slots `sig`, `enc` and `aut`, and "an asymmetric key was generated on the YubiKey and therefore does not exist outside the device" is what it shows ([Yubico, read 2026-11-06](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)). The signature and authentication slots hold the two subkeys, so both can be attested in principle. The attestation says nothing about key flags or about which primary the key belongs to; the first is the binding's, the second the back-signature's. No key on the card certifies, so the question of an attested certify-and-sign key does not arise.

**Unverified.** The Yubico pages read on 2026-11-06 ([the applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)) say that attestation exists from firmware 5.2.3 and list the slots, but do not say that a P-384 key in either slot is attested, or what the extensions of the attestation contain. sluis ADR 0043 records that Yubico says not to trust the fingerprint and date in the statement, so the attested public key is compared with the subkey's. Also unverified: that the card makes the type `0x19` back-signature and the type `0x02` challenge signature through the helper's library and through `gpg`, and that `gpg`, `sqv` and the hosting platform accept the result. The conformance test settles it, on a card of firmware 5.7.4 or newer and on an older one to see it refused:

- generate a P-384 signing key in the signature slot and a P-384 authentication key in the authentication slot, attest both, check the chain to "Yubico Attestation Root 1" (the name is to be confirmed against a real statement), check that an imported key has no attestation, and check that each attested public key is the subkey's;
- make the card's back-signatures (type `0x19`) over a software test primary, have that primary bind the subkeys (type `0x18`, with the back-signature embedded), and check the certificate with `gpg`, `gpgv` and `sqv`;
- make the possession signature (type `0x02`, critical notation) and check with `gpg` and `sqv` that it parses and that neither accepts it as a signature over any document; include signatures whose R or S has a leading zero octet (about one in 128), which the MPI form shortens; check that the helper refuses a challenge with a missing label or an extra line;
- certify the test primary under a trust signature with the expression below, and check that `gpg` with the root trusted and `sq-wot` accept an address in the domain and reject one outside it and one at a subdomain;
- upload the certificate, a software-held primary with card-born subkeys, certified, to a test account on the hosting platform, and sign and verify a commit with the card; this also tests whether the platform accepts a P-384 certificate with third-party certifications and a subkey with an embedded back-signature;
- extend the binding with a later expiry, upload the extended certificate to the same account, and see whether the platform accepts it over the stored one or needs the old key deleted first (unmeasured; its REST documentation lists create, list, get and delete only, read 2026-11-06);
- record the extensions of the attestation, to read the PIN and touch policy from them later.

## The delegation

The ceremony in which the company root delegates to sluis (O1 a). It is the OpenPGP hand-off for an intermediate with a new type, `openpgp-certifier`, and an ordinary root ceremony. It covers **two keys of each company**: the **certification key**, one online P-384 key per company behind sluis's key service, and the **keyring-signing key**, a separate key with which sluis signs the manifest of the staff keyring, so that one compromise gives the power to certify or the power to publish, not both. No certification key serves two companies. ritueel owns the root that can revoke either key.

| Part | Value |
|---|---|
| Requester sends | The public key to be certified, version 4, ECDSA P-384; a self-signature as the proof of possession; a `purpose`, `certify` or `keyring-sign`; for `certify`, the company's domain; a proof file of where the key lives (a cloud key service or a card). |
| Certifier checks | The checks of [the contract](/reference/hand-off-contract/#what-the-certifier-checks-1) that apply to a key and its possession, the evidence of the store, and that the key is not already a primary on the root list. |
| What comes back, for `certify` | The key with one certification by the root: type `0x13`, a Trust Signature subpacket with level 1 and amount 120, a Regular Expression subpacket (marked critical, null-terminated, RFC 9580 sections 5.2.3.21 and 5.2.3.22) with the expression below, exportable, key and signature expiration of 395 days. |
| What comes back, for `keyring-sign` | The key with one ordinary certification by the root (type `0x13`, no trust signature), exportable, 395 days, so that a verifier that holds only the root's fingerprint can check the manifest's signature. |
| Renewal | At the root's yearly ceremony, or under a cloud root's declared policy, like every intermediate. A compromised certification key is replaced through ritueel: sluis stops certifying first, the root revokes its trust signature and makes a new one, and sluis re-certifies every primary of that company. |
| Revocation | By the root, of either key, as for an intermediate ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). |

The contract gains the type with its checks and test vectors in a follow-up; until then this table is the specification and the contract is unchanged.

**The expression**, in the text sluis ADR 0043 fixes, is `<[^>@]+@example\.com>$`, with `example.com` the company's domain: the whole address, one `@`, the exact domain, and no subdomain. **An address at a subdomain needs a trust signature of its own.** `sluis key install` refuses a certification key whose trust signature has another expression, none, or a depth above 1. Another company has its own key, its own domain and its own signature.

**What a verifier relies on.** A verifier with a web of trust (`gpg` with the root trusted, or `sq-wot`) validates a primary through the root's trust signature and the company key's certification. `gpgv`, `sqv`, apt and rpm do no web of trust: they accept a signature if the signing subkey is in the keyring they are given, bound to a primary that has not expired or been revoked there. What they rely on is the keyring and the expiry of the primary and of the subkey.

## Follow-ups

- The helper, the bundle version 1 and its vectors, shared with sluis ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The conformance test above, on a real test card ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The type `openpgp-certifier` in the contract, its vectors, and the delegation ceremony ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- Which verifiers evaluate the trust signature and the expression above ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The attestation extensions of the OpenPGP applet ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Sources

| Source | What it fixes |
|---|---|
| [Yubico, ykman OpenPGP commands](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html), read 2026-11-06 | `keys attest` for the slots `sig`, `enc` and `aut`; what an attestation shows. |
| [Yubico, the OpenPGP applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), read 2026-11-06 | Attestation from firmware 5.2.3; one key in each slot; the algorithms of the applet. |
| [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), sections 5.2.1, 5.2.3.21, 5.2.3.22, 5.2.3.24 | The standalone signature, the trust signature, the regular expression and the notation subpackets. |
