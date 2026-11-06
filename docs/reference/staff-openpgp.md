---
title: Staff OpenPGP
description: What ritueel does for staff keys that sluis holds, namely the card helper, the proof bundle, the attestation rule and the delegation.
sidebar:
  order: 16
---

*Not built yet. This is the page that [ADR 0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/) leaves for the details; that record is `Accepted`. The code is [issue #103](https://github.com/truvity/ritueel/issues/103), after the first version. It builds on the `openpgp-card` store ([issue #18](https://github.com/truvity/ritueel/issues/18)). A person's own key is a different flow: [Personal OpenPGP](/reference/personal-openpgp/).*

A staff key is an OpenPGP primary that sluis generates and seals for one person in one company, with subkeys that the person's card generates under it. sluis binds the subkeys, records the binding, certifies the primary, builds the staff keyring and syncs it; none of that is ritueel's. ritueel's part is three things: the company roots, the **delegation** in which the root makes a trust signature over a sluis key, and the **card helper** that makes a card ready and writes the proof bundle that `sluis key bind` reads. The binding is in [sluis ADR 0043 on key bindings](https://github.com/truvity/sluis/blob/main/docs/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis.md); **that record decides where the two differ**, and the file names, the challenge, the notation name, the expression, the key identity and the lifetimes below are copied from it.

## The card

A staff card is a YubiKey 5 with **firmware 5.7.4 or newer**, dedicated to the staff subkeys. Firmware 5.7.4 and newer are signed under the maker's new root, "Yubico Attestation Root 1", the only attestation root a staff binding pins; older cards are out, and a person with an older card needs a newer one. That is stricter than the 5.7.0 of ritueel's other cards ([cards](/reference/cards/#the-attestation-bundle)), and the allowlist is sluis's: the helper mirrors it. The OpenPGP applet holds one key in each slot (signature, decryption, authentication), so a staff card holds no personal key of [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/); a person who keeps both uses two cards. Each person has two staff cards, each with its own subkeys, under the one primary.

| Key | Slot | Algorithm | Key flags | Made by the helper |
|---|---|---|---|---|
| Signing subkey | signature | ECDSA P-384, version 4, SHA-384 | sign, `0x02` | Generated on the card. A back-signature by the card over the person's primary and the subkey. |
| Authentication subkey | authentication | ECDSA P-384 | authenticate, `0x20` | Generated on the card, for SSH through `gpg-agent` ([the guide](/guides/openpgp-ssh-authentication/)). No back-signature; it proves possession by a challenge signature of its own. Optional: `proof make --no-authentication` omits it. |

**There is no encryption key on a staff card: the helper refuses to make one, and sluis refuses a bundle that holds one.** **No key on the card certifies**: the primary is sluis's. P-384 and SHA-384 are the rule of the [hand-off contract](/reference/hand-off-contract/#keys-and-hashes) for a subkey, so the card keys need no exception. The key flags are in the binding that sluis's primary makes. The binding of a subkey expires after 1095 days, about three years (the maintainer's decision PX1, 2026-11-06, carried to the subkeys); the person extends it with a proof from the card and sluis signs. A key nobody extends ends by itself.

**Only attested subkeys may appear.** The helper produces the signing subkey and, unless it is omitted, the authentication subkey, both generated on the card and both attested, and puts nothing else in the bundle. A subkey made by another tool, an encryption subkey, a software subkey or one without an attestation is never in it. `proof check` and a binder refuse a bundle that holds one (`subkey-not-attested`). Every command that rewrites the bundle re-reads the card and re-checks this first.

## The commands

| Command | Does | Needs the person |
|---|---|---|
| `ritueel staff card prepare --card SERIAL` | Checks the firmware floor; changes the PIN and the Admin PIN at the terminal, without echo; sets the touch policy for each key. Stores no PIN. | Yes |
| `ritueel staff proof make --card SERIAL --primary FILE --out DIR` | One ceremony ([below](/reference/staff-openpgp/#the-ceremony-of-proof-make)): generates the signing key and, unless `--no-authentication` is given, the authentication key on the card, reads the attestations, makes the back-signature of the signing subkey over the primary in `FILE`, and writes the subkey file and the proof, without a challenge signature. It has no option to make an encryption key. | Yes |
| `ritueel staff challenge sign --card SERIAL --challenge FILE --out DIR` | Signs a challenge from `sluis key bind` with every subkey on the card, the signing subkey and the authentication subkey if there is one, and writes one signature for each into `<stem>.possession.sig`. The card is the one whose signing subkey has the key identity named in the challenge's `key` line: for a first bind that is the new card, and for `add`, `end` and `change` it is an existing bound card. See [the challenge](/reference/staff-openpgp/#the-challenge). | Yes |
| `ritueel staff proof refresh --card SERIAL --out DIR` | For an extension: re-reads the card's attestations and rebuilds the proof for the same subkeys. No key is made. A fresh `challenge sign` with `action: change` follows. | Yes |
| `ritueel staff proof check BUNDLE` | The helper's own check of a bundle, for the person to see before giving it to sluis: the same checks as [below](/reference/staff-openpgp/#what-a-binder-checks), offline. | No |

`FILE` is the public key of the person's primary, which `sluis key bind` gives. **Adding a second card takes two challenges and so two runs of `challenge sign`**, one for each card: `challenge sign` selects the card whose signing subkey has the key identity named in the challenge's `key` line, and refuses a card that does not match. The old card runs it on the vouching challenge (`action: add`, `key` the old card, `target` the new one) and writes one signature, for its signing subkey only; the new card runs it on its own challenge and writes one signature for each of its subkeys, into the new bundle. The vouching signature is carried to `sluis key bind` with the new bundle. No command makes a network call. The files are carried by the person to `sluis key bind`, which reads **bundle version 1**; the bundle's format and its test vectors are shared by this repository and sluis, so that each side can be tested against the same files. The handshake is **key-first**: `sluis key bind` gives the primary; `proof make` generates on the card; `sluis key bind` then issues a challenge that names the person, the boundary and the key; `challenge sign` signs it. Each card has its own challenge. An extension ends the same way, with a fresh challenge. There is no command for a changed address: the primary is sluis's, so the user ID is sluis's to change, from its directory, and sluis asks nothing of the card for it.

### The ceremony of `proof make`

It is the six steps of every ceremony ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)), with the person's card as the store.

1. **Plan.** The card's serial and firmware, the slots to be generated, the fingerprint of the primary, and the touch policy. A slot that already holds a key is not overwritten: the plan stops and says so, and the person decides to reset the applet with the maker's tool.
2. **Confirm** by typing the first eight characters of the plan digest.
3. **Reserve, and birth.** The attempt is written; the card generates the keys after the user PIN is verified at the terminal.
4. **Attest.** The attestation of each key is read with the maker's command and checked against the maker's pinned bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The card makes the back-signature of the signing subkey over the primary and the subkey, with the PIN and a touch. The challenge is signed afterwards, by `challenge sign`.
6. **Verify and record.** The subkey file is parsed back, the back-signature verified, and the bundle and a local record are written.

A crash leaves what [0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves) says a birth leaves: a key on the card with no record, found and finished or reset at the next run.

## The proof bundle

Version 1, a message of up to three files that share a stem, as in [the contract](/reference/hand-off-contract/#messages-and-files). JSON rules are those of the contract's files: one UTF-8 object, no member twice, an unknown member is an error, times in `YYYY-MM-DDThh:mm:ssZ`, certificates in PEM, as in sluis ADR 0043.

| File | Holds |
|---|---|
| `<stem>.subkey.pgp` | Binary OpenPGP in the form of [the contract's subkey request](/reference/hand-off-contract/#the-request-1), for one primary: a Public-Subkey packet for each subkey, and after the signing subkey its back-signature (type `0x19`) made by the card, with the issuer fingerprint (hashed) and the issuer key ID (unhashed) ([the contract](/reference/hand-off-contract/#issuer-key-id)). The back-signature is from the signing subkey only. The primary is not in it. |
| `<stem>.proof.json` | The attestation statement and chain of each subkey, below. |
| `<stem>.possession.sig` | Binary OpenPGP: one version 4 standalone signature (type `0x02`) for each subkey, the signing subkey's first, each made by that subkey with SHA-384, each with the same challenge as the value of a critical hashed notation named `bind-challenge@sluis.id`, flagged human-readable ([below](/reference/staff-openpgp/#the-challenge)). Written by `challenge sign`; absent until then. |

This is not an exchange of the contract: the primary is not on a root list of ritueel's, and the party that binds is sluis. The file form is the contract's so that one parser reads both.

`<stem>.proof.json`, with exactly these members, shared with sluis (sluis ADR 0043):

| Member | Meaning |
|---|---|
| `bundle` | The bundle version, the number `1`. |
| `subkey_sha256` | SHA-256 of the bytes of `<stem>.subkey.pgp`, 64 hexadecimal digits, so that the proof cannot be moved to another file. |
| `primary` | The version 4 fingerprint of the person's primary, 40 hexadecimal digits, as `sluis key bind --primary` gives it. |
| `key` | The key identity of the signing subkey, 64 hexadecimal digits ([below](/reference/staff-openpgp/#the-key-identity)). |
| `subkeys` | An array with one object for each subkey: `slot` (`sig` or `aut`), `key` (that subkey's key identity), `statement` (the attestation certificate the card returns for it, PEM) and `chain` (the intermediate certificates that lead from it to the maker's root, an array of PEM). |

## What a binder checks

sluis decides what it checks; this is what the bundle is built to let it check, and the helper's `proof check` makes the same checks offline. No check here is the helper trusting itself: a binder re-makes every one.

| # | Check |
|---|---|
| 1 | The version, `subkey_sha256`, `key`, and that the files parse. |
| 2 | Each subkey is ECDSA P-384, version 4. The signing subkey has a back-signature of type `0x19` that verifies under it over the primary named in `primary` and the subkey, and carries both issuer subpackets. |
| 3 | Each `statement` and its `chain` verify to the maker's pinned root, every certificate valid; the attested public key is the subkey's; the firmware is at or above the allowlist's floor. |
| 4 | Each subkey has a possession signature in `.possession.sig` that verifies under it, is of type `0x02`, carries the challenge in a critical hashed notation `bind-challenge@sluis.id`, and the challenge is the one the binder issued: its eight lines, its `person`, `boundary`, `key` and `target`, its `nonce`, and an `expires` not passed. A statement copied from another card has no such signature and is refused. |
| 5 | The bundle holds no subkey other than the attested signing subkey and the attested authentication subkey, and no encryption subkey (`subkey-not-attested`). A bundle with only an authentication subkey is refused (`no-signing-subkey`): the signing subkey is the one that carries the back-signature and the key identity. |

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
- **The key identity** is the SHA-256 hash of the public key material of a subkey, over the exact bytes of [the next section](/reference/staff-openpgp/#the-key-identity). The identity that goes in `key` is that of the signing subkey. It is not the version 4 fingerprint, which covers a creation time the holder chooses.
- **The signature is not a document signature.** A plain signature of type `0x00` over a labelled text is hashed with the data it follows, and lenient formats tolerate extra lines, so a label inside such a text separates nothing. The proof is a **version 4 standalone signature (type `0x02`)**, which signs only its own subpackets, made by the signing subkey, with the challenge as the value of a **critical** hashed Notation Data subpacket named `bind-challenge@sluis.id`, flagged human-readable (RFC 9580, sections 5.2.1 and 5.2.3.24). It parses as no commit, tag, checksum or certification, and a verifier that does not know the critical notation must reject it.
- **What the label does not protect.** The card signs the digest it is handed and does not see the text. The protection is on the host: **the helper refuses before it signs** a challenge that lacks the label, has other lines, or has an `expires` in the past; it shows the whole challenge before it asks for the PIN; it checks that `key` is the key identity of the card it signs with; and it builds the type `0x02` packets itself. The same challenge is signed by every subkey on the card, and the helper checks that `key` names the signing subkey. A hostile host or a hostile helper can ask the card to sign any digest, and the PIN and the touch are what stand between a card and an unwanted signature.
- **The conformance test** ([below](/reference/staff-openpgp/#the-attestation-rule-and-what-is-not-yet-known)) checks with `gpg` and `sqv` that the signature parses, and that neither accepts it as a signature over any document.

## The key identity

For an OpenPGP ECDSA key on P-384, the bytes that are hashed are:

1. the algorithm octet `0x13` (19);
2. the curve OID length octet `0x05`;
3. the OID `2b 81 04 00 22` (1.3.132.0.34);
4. the MPI of the public point exactly as the key packet carries it: a two-octet bit count, `03 03` (771) for a 97-octet point whose first octet is `04`, and the 97 octets of the uncompressed point.

These are the public key fields of the key packet (RFC 9580, section 5.5.5.4) with the algorithm octet in front, without the version and the creation time. The identity is the SHA-256 of those bytes in 64 lower-case hexadecimal digits. The vector of sluis ADR 0043 (its public point, hashed bytes and identity `5f9e0d23…ab38`) is a case of this rule; I checked its identity and its version 4 fingerprint `50ca09b0…a3fc` with SHA-256 and SHA-1 on 2026-11-06, and it holds.

## Test vectors

The challenge signature has two vectors in the shared set, because a signature whose `r` or `s` has a leading zero octet (about one in 128) is shortened by the MPI form, and a verifier must pad it back to 48 octets before it checks it.

- **With a leading zero:** the vector of sluis ADR 0043, whose `s` is 375 bits. It is not copied here; that record is its source.
- **Without a leading zero:** the vector below, made for this page with a throwaway P-384 key whose private part is discarded. `r` is 383 bits and `s` is 384 bits. Checked on 2026-11-06: the signature verifies with a P-384 ECDSA verifier over the trailer of RFC 9580 section 5.2.4, the key identity and the fingerprint were recomputed from the key packet, and `gpg` 2.4.8 `--list-packets` parses both packets.

The public point (97 octets):

```text
04d70fa8341edb80c1246fecd45038b10e15e9a75ebabd0f4933123f94f5e206210cc0841d469277022ed434cf5daeea7df404af308ead7e6e3b96ff41aa4b050c63e3529b6d41207b5f60ff1d2239f3e7b98585d30d4e36e9cde45c6d87749825
```

The key identity (the SHA-256 of `13 05 2b81040022 0303` and the point):

```text
383b04e380843cd7046574ce0482c96028ee29c057dfb4f51473d8812cb6d0fd
```

The key packet (version 4, creation time 1767225600, that is 2026-01-01T00:00:00Z), with the version 4 fingerprint `eb1d3f5ec0bb00e31f0a65ad37615f232f1e138b`:

```text
c66f046955b90013052b81040022030304d70fa8341edb80c1246fecd45038b10e15e9a75ebabd0f4933123f94f5e206210cc0841d469277022ed434cf5daeea7df404af308ead7e6e3b96ff41aa4b050c63e3529b6d41207b5f60ff1d2239f3e7b98585d30d4e36e9cde45c6d87749825
```

The challenge (eight lines, a line feed after each; the key signs as its own signing subkey):

```text
sluis-key-bind-v1
action: bind
person: mfrggzdfmz2gq2lnmvzxi4tbnz
boundary: boundary-a
key: 383b04e380843cd7046574ce0482c96028ee29c057dfb4f51473d8812cb6d0fd
target: 383b04e380843cd7046574ce0482c96028ee29c057dfb4f51473d8812cb6d0fd
nonce: b481737d941108e39eda4ec5ddb75c8dd3ec476abdfeafbc8bf167d37dc10064
expires: 2026-01-01T00:10:00Z
```

The signature packet, a version 4 signature of type `0x02` with the challenge in a critical hashed notation `bind-challenge@sluis.id`, ECDSA on P-384 with SHA-384:

```text
c2c1430402130a018b05026955ba2c162104eb1d3f5ec0bb00e31f0a65ad37615f232f1e138bc0ac94800000000017014c62696e642d6368616c6c656e676540736c7569732e6964736c7569732d6b65792d62696e642d76310a616374696f6e3a2062696e640a706572736f6e3a206d667267677a64666d7a326771326c6e6d767a78693474626e7a0a626f756e646172793a20626f756e646172792d610a6b65793a20333833623034653338303834336364373034363537346365303438326339363032386565323963303537646662346635313437336438383132636236643066640a7461726765743a20333833623034653338303834336364373034363537346365303438326339363032386565323963303537646662346635313437336438383132636236643066640a6e6f6e63653a20623438313733376439343131303865333965646134656335646462373563386464336563343736616264666561666263386266313637643337646331303036340a657870697265733a20323032362d30312d30315430303a31303a30305a0a000a091037615f232f1e138bccf4017f5a3937a473f5a5be34e22a79a26b70cd782cd237b3a96dd883bfc62436406222df93bb842dcb6e810c33192cb1f14fc90180e8f6d96866e644c786a0b0864e6bca88d93aab903a1f4b0dff5e4ed2a60c04c7a69effb687ac63d6c0d20d9872e6d210
```

## The attestation rule, and what is not yet known

The card attests a key that was generated on it. `ykman openpgp keys attest` takes the slots `sig`, `enc` and `aut`, and "an asymmetric key was generated on the YubiKey and therefore does not exist outside the device" is what it shows ([Yubico, read 2026-11-06](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)). The signature and authentication slots hold the two subkeys, so both can be attested in principle. The attestation says nothing about key flags or about which primary the key belongs to; the first is the binding's, the second the back-signature's. No key on the card certifies, so the question of an attested certify-and-sign key does not arise.

**Unverified.** The Yubico pages read on 2026-11-06 ([the applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)) say that attestation exists from firmware 5.2.3 and list the slots, but do not say that a P-384 key in either slot is attested, or what the extensions of the attestation contain. sluis ADR 0043 records that Yubico says not to trust the fingerprint and date in the statement, so the attested public key is compared with the subkey's. Also **unverified:** that the card's signature slot makes the type `0x19` back-signature and the type `0x02` challenge signature, and that **the authentication slot makes a type `0x02` challenge signature**, through the helper's library and with the PIN and touch policy of the slot (if it cannot, an authentication subkey is not bound and the bound set is the signing subkey alone); that **`gpg --verify` and `sqv` reject a type `0x02` signature as a signature over any document**; and that `gpg`, `sqv` and the hosting platform accept a certificate whose subkeys were bound this way. The conformance test settles it, on a card of firmware 5.7.4 or newer and on an older one to see it refused:

- generate a P-384 signing key in the signature slot and a P-384 authentication key in the authentication slot (and check that the helper has no way to make a decryption key), attest both, check the chain to "Yubico Attestation Root 1" (the name is to be confirmed against a real statement), check that an imported key has no attestation, and check that each attested public key is the subkey's;
- make the card's back-signature (type `0x19`, signing subkey only) over a software test primary, have that primary bind the subkeys (type `0x18`, with the back-signature embedded), and check the certificate with `gpg`, `gpgv` and `sqv`;
- make a bundle with the signing subkey only (`proof make --no-authentication`) and check that a binder accepts it, and that a bundle with an authentication subkey and no signing subkey is refused (the helper makes none, and `proof check` refuses one);
- add a second card: the old card signs the vouching challenge and the new card its own, and check that `challenge sign` refuses a card whose signing key is not the `key` line;
- make the possession signatures (type `0x02`, critical notation), one from the signing slot and one from the authentication slot, and check with `gpg` and `sqv` that they parse and that neither accepts one as a signature over any document; check that a bundle with a statement copied from another card, and no matching signature for its subkey, is refused; check the two vectors above, with and without a leading zero, against the helper's output; include signatures whose R or S has a leading zero octet (about one in 128), which the MPI form shortens; check that the helper refuses a challenge with a missing label or an extra line;
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
| What comes back, for `certify` | The key with one certification by the root: type `0x13`, a Trust Signature subpacket with level 1 and amount 120, a Regular Expression subpacket (marked critical, null-terminated, RFC 9580 sections 5.2.3.21 and 5.2.3.22) with the expression below, exportable, with a Signature Expiration Time of 395 days. **No Key Expiration Time is set:** in a certification of someone else's key it has no effect, and only the Signature Expiration Time ends the certification. |
| What comes back, for `keyring-sign` | The key with one ordinary certification by the root (type `0x13`, no trust signature), exportable, with a Signature Expiration Time of 395 days (a Key Expiration Time would have no effect), so that a verifier that holds only the root's fingerprint can check the manifest's signature. |
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
