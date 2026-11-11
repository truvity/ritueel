---
title: Staff OpenPGP
description: What ritueel does for staff keys that sluis holds, namely the card helper, the proof bundle, the attestation rule and the delegation.
sidebar:
  order: 16
---

*Not built yet. This is the page that [ADR 0014](/decisions/0014-staff-openpgp-primaries-sealed-in-sluis-subkeys-born-on-cards-ritueel-makes-the-card-ready-and-runs-the-delegation/) leaves for the details; that record is `Accepted`. The code is [issue #103](https://github.com/truvity/ritueel/issues/103), built after the first signed release (M7). It builds on the `openpgp-card` store ([issue #18](https://github.com/truvity/ritueel/issues/18)). A person's own key is a different flow: [Personal OpenPGP](/reference/personal-openpgp/).*

A staff key is an OpenPGP primary that sluis generates and seals for one person in one company, with subkeys that the person's card generates under it. sluis binds the subkeys, records the binding, certifies the primary, builds the staff keyring and syncs it; none of that is ritueel's. ritueel's part is three things: the company roots, the **delegation** in which the root makes a trust signature over a sluis key, and the **card helper** that makes a card ready and writes the proof bundle that `sluis key bind` reads. The binding is in [sluis ADR 0043 on key bindings](https://github.com/truvity/sluis/blob/main/docs/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis.md), accepted and merged on sluis `main` ([pull request #1493](https://github.com/truvity/sluis/pull/1493)); **that record decides where the two differ**, and the file names, the challenge, the notation name, the expression, the key identity and the lifetimes below are copied from it.

## The card

A staff card is a YubiKey 5 with **firmware 5.7.4 or newer**, dedicated to the staff subkeys. Firmware 5.7.4 and newer are signed under the maker's new root, "Yubico Attestation Root 1", the only attestation root a staff binding pins; older cards are out, and a person with an older card needs a newer one. That is stricter than the 5.7.0 of ritueel's other cards ([cards](/reference/cards/#the-attestation-bundle)). The allowlist is sluis's and is defined on what the statement carries: a minimum firmware, a set of form factors and, optionally, a required FIPS flag (the statement carries no model name). A card whose statement verifies to the pinned root but is not on the allowlist gets the class `hardware-unlisted`, and staff company signing needs `hardware-attested`; the helper mirrors the allowlist and sluis's wins. The OpenPGP applet holds one key in each slot (signature, decryption, authentication), so a staff card holds no personal key of [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/); a person who keeps both uses two cards. Each person has two staff cards, each with its own subkeys, under the one primary. **A card serves one company (OC1 A):** sluis refuses a bundle whose card serial belongs to an active or pending binding of any tenant, so a person at two companies uses two cards for each.

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
| `ritueel staff challenge sign --card SERIAL --challenge FILE --out DIR` | Signs a challenge from `sluis key bind` with every subkey on the card, the signing subkey and the authentication subkey if there is one, and writes one signature for each into `<stem>.possession.sig`. The card is the one whose signing subkey has the key identity named in the challenge's `key` line: for `bind` that is the new card, for `vouch` and `end` it is another, bound card, and for `extend` and `change` it is the card itself. `vouch` and `end` are signed by the signing subkey alone; `bind`, `extend` and `change` by every subkey. See [the challenge](/reference/staff-openpgp/#the-challenge). | Yes |
| `ritueel staff proof refresh --card SERIAL --out DIR` | For an extension: re-reads the card's attestations and rebuilds the proof for the same subkeys. No key is made. A fresh `challenge sign` with `action: extend` follows. | Yes |
| `ritueel staff proof check BUNDLE` | The helper's own check of a bundle, for the person to see before giving it to sluis: the same checks as [below](/reference/staff-openpgp/#what-a-binder-checks), offline. | No |

`FILE` is the public key of the person's primary, which `sluis key bind` gives. **Adding a second card takes two challenges and so two runs of `challenge sign`**, one for each card: `challenge sign` selects the card whose signing subkey has the key identity named in the challenge's `key` line, and refuses a card that does not match. The old card runs it on the vouching challenge (`action: vouch`, `key` the old card, `target` the new one, `set` the new card's) and writes one signature, for its signing subkey only; the new card runs it on its own `bind` challenge and writes one signature for each of its subkeys, into the new bundle. sluis needs both. The vouching signature is carried to `sluis key bind` with the new bundle. No command makes a network call. The files are carried by the person to `sluis key bind`, which reads **bundle version 1**; the bundle's format and its test vectors are shared by this repository and sluis, so that each side can be tested against the same files. The handshake is **key-first**: `sluis key bind` gives the primary; `proof make` generates on the card; `sluis key bind` then issues a challenge that names the tenant, the person, the boundary, the signing key, the set of subkeys and the expiry the person asks for; `challenge sign` signs it. Each card has its own challenge. An extension ends the same way, with a fresh `extend` challenge that carries the stored set. There is no command for a changed address: the primary is sluis's, so the user ID is sluis's to change, from its directory, and sluis asks nothing of the card for it.

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
| 3 | Each `statement` and its `chain` verify to the maker's pinned root, every certificate valid; the attested public key is the subkey's; the firmware and the form factor are on the allowlist (otherwise the class is `hardware-unlisted`); every statement is of the same card, by its serial; the slot of the subkey (`sig` or `aut`) is the slot of its attestation. A statement that is present and does not verify is refused, not downgraded. |
| 4 | Each subkey has a possession signature in `.possession.sig` that verifies under it, is of type `0x02`, carries the challenge in a critical hashed notation `bind-challenge@sluis.id`, and the challenge is the one the binder issued: its eleven lines, its `tenant`, `person`, `boundary`, `key`, `target`, `set` and `expiry`, its `nonce`, and a `not-after` not passed. A statement copied from another card has no such signature and is refused. |
| 5 | The bundle holds no subkey other than the attested signing subkey and the attested authentication subkey, and no encryption subkey (`subkey-not-attested`). A bundle with only an authentication subkey is refused (`no-signing-subkey`): the signing subkey is the one that carries the back-signature and the key identity. |
| 6 | A subkey's creation time is not more than 5 minutes in the future and not more than 30 days before the binding, so a bundle is bound soon after `proof make`; a key identity that belongs to any binding in the boundary, in any state, is refused. |

The key flags of a subkey are those of the binding that the primary makes, which only the binder makes; nothing a card says about them is read. The class follows from the result: `hardware-attested`, `hardware-unlisted` or `unattested` (no statement). Only `hardware-attested` may be bound under the primary, put in the staff keyring or synced to the hosting platform; the others are recorded and audited and by default do nothing. A first binding, or a re-binding when every card is lost, is approved by an operator after the bundle has arrived, and a further card by a vouching signature of an existing one.

## The challenge

The challenge is sluis's, and its bytes are defined by sluis ADR 0043, which wins; they are copied here so that the helper can be written from this page. **Eleven lines of UTF-8 text, each ending in a line feed, in this order, with nothing before, between or after:**

```text
sluis-key-bind-v1
action: <bind, vouch, end, extend or change>
tenant: <tenant id>
person: <subject>
boundary: <boundary id>
key: <key identity of the signing key, 64 hex digits>
target: <key identity the action is about, 64 hex digits>
set: <SHA-256 of the bound set, 64 hex digits>
expiry: <RFC 3339 UTC time, to the second, ending in Z, or none>
nonce: <256 random bits, 64 hex digits>
not-after: <RFC 3339 UTC time, to the second, ending in Z>
```

- **`set` commits to the subkeys:** the SHA-256 of the concatenation of the 32-octet key identities of all subkeys of the card, sorted ascending as octet strings. **`expiry`** is the expiry of the binding that the person approves, or `none` for `end`. **`not-after`** is the end of the challenge's own life: it lives 600 seconds, long enough for a PIN and a touch, is used once, and only by the session that asked for it. The signed text names the tenant, the person, the exact set and the exact expiry, so a tap for one cannot authorise another.
- **`action`** is one of five, and the card that signs is the one `key` names:

| Action | Signed by | `key` | `target` | `set` | `expiry` |
|---|---|---|---|---|---|
| `bind` | Every subkey of the new card | The new card's signing subkey | The same | The new card's set | The expiry asked for |
| `vouch` | The signing subkey of an existing bound card | The existing card's signing subkey | The new card's signing subkey | The new card's set | The expiry asked for |
| `end` | The signing subkey of another bound card | That other card's signing subkey | The ending card's signing subkey | The ending card's set | `none` |
| `extend` | Every subkey of the card | The card's signing subkey | The same | The stored set, unchanged | The new expiry |
| `change` | Every subkey of the card | The card's signing subkey | The same | The new set | The binding's expiry |

  Adding a card takes two challenges with a nonce each, `bind` and `vouch`. An extension cannot widen the set: sluis refuses an `extend` whose `set` is not the stored one, and a wider or narrower set is a `change`.
- **The key identity** is the SHA-256 hash of the public key material of a subkey, over the exact bytes of [the next section](/reference/staff-openpgp/#the-key-identity). The identity that goes in `key` is that of the signing subkey. It is not the version 4 fingerprint, which covers a creation time the holder chooses; a key identity is unique across the boundary and in every state, and a revoked key is never bindable again.
- **The signature is not a document signature.** A plain signature of type `0x00` over a labelled text is hashed with the data it follows, and lenient formats tolerate extra lines, so a label inside such a text separates nothing. The proof is a **version 4 standalone signature (type `0x02`)**, which signs only its own subpackets, made by the signing subkey, with the challenge as the value of a **critical** hashed Notation Data subpacket named `bind-challenge@sluis.id`, flagged human-readable (RFC 9580, sections 5.2.1 and 5.2.3.24). It parses as no commit, tag, checksum or certification, and a verifier that does not know the critical notation must reject it.
- **What the label does not protect.** The card signs the digest it is handed and does not see the text. The protection is on the host: **the helper refuses before it signs** a challenge that lacks the label, has other lines, or has a `not-after` in the past; it shows the whole challenge before it asks for the PIN; it checks that `key` is the key identity of the card it signs with; and it builds the type `0x02` packets itself. For `bind`, `extend` and `change` the same challenge is signed by every subkey on the card; for `vouch` and `end` by the signing subkey alone. The helper checks that `key` names the signing subkey. A hostile host or a hostile helper can ask the card to sign any digest, and the PIN and the touch are what stand between a card and an unwanted signature.
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

- **With a leading zero:** the vector of sluis ADR 0043, whose `s` is 374 bits (47 octets). It is not copied here; that record is its source. I checked its signature on 2026-11-07 with a P-384 ECDSA verifier over the trailer of RFC 9580 section 5.2.4, and its key identity `5f9e0d23…ab38`, and both hold.
- **Without a leading zero:** the vector below, made for this page with a throwaway P-384 key whose private part is discarded, for the eleven-line challenge. `r` and `s` are both 384 bits. Checked on 2026-11-07: the signature verifies with a P-384 ECDSA verifier over the trailer of RFC 9580 section 5.2.4, the key identity, the set digest and the fingerprint were recomputed from the key packet, and `gpg` 2.4.8 `--list-packets` parses both packets.

The public point (97 octets):

```text
0415152948e9fc32d17088b259bb57a6fe199fd1892d43c5f3991cc887a363937e42919a0a14561bca246e3fb9f904569abe259a5c7625b9c30423a88c7add346ed5436b102bab4a310c3b99bb765a6354d4a6420dacfff6a2a986b5cb2da11e38
```

The key identity (the SHA-256 of `13 05 2b81040022 0303` and the point):

```text
fce97a3bf80079b7bbb69ac7a416ed3c28933002ff33f5847d2389cbb16d8d53
```

The key packet (version 4, creation time 1767225600, that is 2026-01-01T00:00:00Z), with the version 4 fingerprint `86a28829a47fc6fa54f8ef1c045645a261a92af1`:

```text
c66f046955b90013052b8104002203030415152948e9fc32d17088b259bb57a6fe199fd1892d43c5f3991cc887a363937e42919a0a14561bca246e3fb9f904569abe259a5c7625b9c30423a88c7add346ed5436b102bab4a310c3b99bb765a6354d4a6420dacfff6a2a986b5cb2da11e38
```

The challenge (eleven lines, a line feed after each; the key signs as its own signing subkey, and `set` is the SHA-256 of that one 32-octet key identity):

```text
sluis-key-bind-v1
action: bind
tenant: tenant-a
person: mfrggzdfmz2gq2lnmvzxi4tbnz
boundary: boundary-a
key: fce97a3bf80079b7bbb69ac7a416ed3c28933002ff33f5847d2389cbb16d8d53
target: fce97a3bf80079b7bbb69ac7a416ed3c28933002ff33f5847d2389cbb16d8d53
set: f5fe16040482b039d48c880c0371eadb91bff6d0c1c1cbcc85bd2cb5a96fc65d
expiry: 2028-12-31T00:00:00Z
nonce: 22f91e3c98ab66c3c39d473ddc369de638388913dfdf171b577a257d31d1fd0e
not-after: 2026-01-01T00:10:00Z
```

The signature packet, a version 4 signature of type `0x02` with the challenge in a critical hashed notation `bind-challenge@sluis.id`, ECDSA on P-384 with SHA-384:

```text
c2c1b90402130a020105026955b93c16210486a28829a47fc6fa54f8ef1c045645a261a92af1c1229480000000001701c262696e642d6368616c6c656e676540736c7569732e6964736c7569732d6b65792d62696e642d76310a616374696f6e3a2062696e640a74656e616e743a2074656e616e742d610a706572736f6e3a206d667267677a64666d7a326771326c6e6d767a78693474626e7a0a626f756e646172793a20626f756e646172792d610a6b65793a20666365393761336266383030373962376262623639616337613431366564336332383933333030326666333366353834376432333839636262313664386435330a7461726765743a20666365393761336266383030373962376262623639616337613431366564336332383933333030326666333366353834376432333839636262313664386435330a7365743a20663566653136303430343832623033396434386338383063303337316561646239316266663664306331633163626363383562643263623561393666633635640a6578706972793a20323032382d31322d33315430303a30303a30305a0a6e6f6e63653a20323266393165336339386162363663336333396434373364646333363964653633383338383931336466646631373162353737613235376433316431666430650a6e6f742d61667465723a20323032362d30312d30315430303a31303a30305a0a000a0910045645a261a92af13ef50180d5f6105a014e6c7080c2710fd86240916ce9cefba79209c90cfd1a75c7f24bb2aa71203cb1a06ecafad48a66e31d64f20180ae6fa1aef39d1428eb222f3f6ec6fa9d5c37a136024da762e95d57524b4eb3da587d7297d47de01a3bab5bcf333f1e86
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
- The conformance test above, on a real rehearsal card ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The type `openpgp-certifier` in the contract, its vectors, and the delegation ceremony ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- Which verifiers evaluate the trust signature and the expression above ([issue #103](https://github.com/truvity/ritueel/issues/103)).
- The attestation extensions of the OpenPGP applet ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Sources

| Source | What it fixes |
|---|---|
| [Yubico, ykman OpenPGP commands](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html), read 2026-11-06 | `keys attest` for the slots `sig`, `enc` and `aut`; what an attestation shows. |
| [Yubico, the OpenPGP applet](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), read 2026-11-06 | Attestation from firmware 5.2.3; one key in each slot; the algorithms of the applet. |
| [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), sections 5.2.1, 5.2.3.21, 5.2.3.22, 5.2.3.24 | The standalone signature, the trust signature, the regular expression and the notation subpackets. |
