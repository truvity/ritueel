# 0014 — Staff OpenPGP: primaries sealed in sluis, subkeys born on cards; ritueel makes the card ready and runs the delegation

**Status:** Accepted
**Date:** 2026-11-06

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) leaves company-wide OpenPGP to a record of its own, and [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) decides a person's own key. A company that wants its staff to sign commits needs a key it can recognise as its own, stop trusting when the person leaves, and attribute to one person on a hosting platform. This record decides the part of that which belongs to ritueel; the rest belongs to sluis, which holds the primaries. The tracking issue is [#103](https://github.com/truvity/ritueel/issues/103).

The maintainer decided on 2026-11-06:

> **G1 A:** "OpenPGP keys born on cards", with no SSH-signing fallback.
>
> **G2c A:** start with the OpenPGP applet. Add per-purpose PIV keys once a `gpg.program` signer exists.
>
> **G4 A:** keys born on the card, with the attestation recorded in ritueel's ledger; PIN and Admin PIN changed at issue; a second card per person; cards shipped through Yubico Delivery; touch policy decided per key.
>
> **G5 A**, for a leaver: remove them from the org and delete their keys from their GitHub account; let the sluis certification lapse and drop the key from the staff keyring; revoke only on compromise.
>
> **C1:** the maintainer migrates their own key (a software primary with imported subkeys) through ritueel's flow: "Ritueel will help me rotate master keys; after that we continue as we agree".
>
> **GH1 A:** the keys synced to a person's own GitHub account are only the company-issued ones.
>
> **O1 a** (2026-11-01): the company root delegates, by a domain-scoped trust signature made at a ritueel ceremony, to an online certifier in sluis ([sluis ADR 0024](https://github.com/truvity/sluis/blob/main/docs/decisions/0024-root-custody-and-the-signing-api/)).
>
> **SK1 E, BK1 A, BK2 A, BK3 A.**
>
> **PX1 yes** (2026-11-06).
>
> **BD1 B and BD2 B** (2026-11-06): "because we manage per-company identities (employees) and comporise of company key is much worse then just persons".

G4's "ritueel's ledger" is, under SK1 E, the binding record that sluis keeps; the helper keeps a local record only.

In the maintainer's decisions of the same day, as the author reads them: staff keys are **key bindings inside sluis**, and **each person's OpenPGP primary is generated and sealed inside sluis, per company** (BD1 B, BD2 B). A card-born key is a **subkey** under that primary: the person generates it on their own card and binds it with `sluis key bind`, after a fresh hardware step-up, presenting the card's attestation, the card's back-signature over the person's primary, and a signature on sluis's challenge. sluis checks all of it on the server, binds the subkey under the primary, records the binding, and certifies the primary under the root's trust signature (O1 a). Customers of sluis also bind keys, per company. A software key can be bound, with its own class, but company signing for staff refuses it (G1 A, BK2). Sealed software keys for non-human identities are a later feature (BK3 A) and nothing more is decided here. sluis produces the staff keyring from its bindings and syncs it to the hosting platform. BK1 A is that ritueel provides the card helper below. PX1 yes is that a card key does expire, after 1095 days (about three years), and is extended with a proof from the card; under this model sluis signs the extension.

These decisions replace three earlier ones of the same day: a per-person primary held by the company through ritueel in a cloud key service (G2a, G2b), and a primary born on the person's card (SK1 E as first read); the roads not taken say why.

The binding, the record, the primary and its sealing, the certification, the renewal, the keyring and the sync are sluis's, and are decided in sluis ADR 0043 on key bindings ([pull request #1493](https://github.com/truvity/sluis/pull/1493)), which is being rewritten for this model. This record states them only as far as ritueel's part cannot be read without them, and **it is the sluis record that decides if the two differ.**

## Decision

### Staff keys and personal keys are two flows

A **staff key** is an OpenPGP primary that sluis holds, sealed, for one person in one company, with card-born subkeys under it, for the staff address. A **personal key** is a person's own ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)), **and that flow is unchanged:** a person's own primary is theirs, in their file, and ritueel's part is the ceremony of 0012. Only a staff key is bound, certified and synced by the company. The OpenPGP applet of a card holds one key in each of its slots, so a card that holds staff subkeys holds no personal key: a person who has both uses two cards.

### What ritueel does and what sluis does

| ritueel | sluis |
|---|---|
| Holds the company roots; runs their ceremonies and transitions ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). | Generates and seals each person's primary, per company, behind its key service. |
| **The delegation ceremony:** the root makes a domain-scoped trust signature over the certifier, per company, if sluis ADR 0043 keeps one, and a certification over the key that signs the staff keyring, with a hand-off (below). | Receives them, installs them, and warns before they expire, as for every intermediate ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)). |
| **The card helper:** makes a person's card ready, generates the subkey candidates on it, and writes the proof bundle (below). It makes no network call. Its job is the card side only. | `sluis key bind`: the fresh hardware step-up, the check of the bundle on the server, the binding of the subkeys under the primary, the record, the certification, and the renewal. |
| Personal keys (0012). | The staff keyring, built from the bindings, and its sync to the hosting platform; ending a binding for a leaver or a lost card. |
| Teaches all of it. | The audit record of every bind, renewal and unbind. |

ritueel holds no staff primary, binds no subkey, certifies no person and runs no ceremony per person. The reasons are in the roads not taken.

### The card helper and the proof bundle

- **The helper makes a card ready and produces the bundle (BK1 A).** It checks the firmware floor, changes the PIN and the Admin PIN at the terminal and sets the touch policy per key (G4 A), generates a signing key and an authentication key on the card's OpenPGP applet, reads the card's attestation of both, makes the card's back-signature over the person's primary, and writes the **proof bundle**. It makes no key that is not a subkey candidate: the primary is sluis's. **The handshake is key-first:** the primary's public key and a challenge come from `sluis key bind`; the helper generates on the card, writes the bundle, and a second helper command signs the challenge with the card (below). It has no online dependency on sluis: the files are carried by the person to `sluis key bind`, which reads bundle version 1; the bundle's format, and the test vectors for it, are shared by both repositories.
- **The card keys** are generated on the card as version 4 ECDSA on P-384: a signing subkey (key flag `0x02`) in the signature slot, and an authentication subkey (`0x20`) in the authentication slot, for SSH through `gpg-agent`, as in 0012. There is no encryption subkey. No key on the card certifies: the primary is not there. Each subkey has a back-signature (type `0x19`) made by the card over the person's primary and the subkey, in the form of [the hand-off contract](/reference/hand-off-contract/#the-request-1), with the issuer fingerprint and the issuer key ID. GnuPG and Sequoia refuse a signing subkey without a good back-signature, and the contract asks for one on an authentication subkey too, since it is also the proof that the card holds the key.
- **Expiry and extension.** A card subkey is bound for 1095 days (PX1), and is extended with a proof from the card: the person re-presents the same subkeys with a fresh attestation and a signature on a fresh challenge, and sluis signs the new binding. The card makes no certification and no expiry change. A key nobody extends, because the card is lost or the person forgot, ends by itself.
- **P-384 is the contract's rule, and it is kept.** The [hand-off contract](/reference/hand-off-contract/#keys-and-hashes) accepts P-384 only for a subkey, with SHA-384, and the card layer was measured with P-384 on firmware 5.8 ([card libraries](/research/card-libraries-and-tooling-2026-11-01/)). The algorithm of the primary is sluis's. The contract is not extended for the bundle: the bundle goes from ritueel's helper to sluis, the contract from a system that holds intermediates to ritueel's root, and the bundle is specified on [the reference page](/reference/staff-openpgp/#the-proof-bundle) with its own version, reusing the contract's subkey file.
- **Only attested subkeys may appear.** The helper produces exactly two subkey candidates, both generated on the card and both attested, and puts nothing else in the bundle. A subkey from another tool, an encryption subkey, a software subkey or one the card did not attest is never in it; `proof check` and sluis refuse a bundle that holds one (`subkey-not-attested`). Every command that rewrites the bundle re-reads the card and re-checks this first.
- **The firmware floor is 5.7.4,** for staff cards, as the allowlist of sluis ADR 0043 pins it. Firmware 5.7.4 and newer are signed under the maker's new root, "Yubico Attestation Root 1", the only attestation root of staff bindings. Older cards are out: they chain to the earlier root, which a staff binding does not pin. This is stricter than the 5.7.0 of ritueel's other cards ([cards](/reference/cards/#the-attestation-bundle)). The helper mirrors the floor; the allowlist is sluis's and wins. The OpenPGP applet attests keys since 5.2.3, so the floor is an evidence rule, not the applet's.
- **The attestation rule.** The card attests a key that was generated on it. `ykman openpgp keys attest` takes the slots `sig`, `enc` and `aut` ([Yubico, read 2026-11-06](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)), and the signature and authentication slots are where the two subkeys live, so both can be attested. What the attestation proves is that the key was generated on the device; the key flags are in the binding that sluis's primary makes, and the algorithm in the key. The question of the earlier design, whether the attestation covers a card-born key that certifies, no longer arises, since no key on the card certifies. **Unverified:** the Yubico pages read on 2026-11-06 do not state that a P-384 key in either slot is covered, and the encoding of the attestation extensions is not measured ([#18](https://github.com/truvity/ritueel/issues/18)); sluis ADR 0043 records that Yubico says not to trust the fingerprint and date in the statement, so the attested public key is compared with the subkey's. A conformance test on a real test card settles it before the helper is called built (see Follow-ups).
- **The helper's own checks are a convenience.** It checks the bundle before it writes it (`proof check`), and the attestation chain, the back-signatures, the challenge signature and the firmware again. **sluis does not trust any of it:** it checks the bundle itself, on the server. A bundle from a modified helper, or one built by hand, is as good as its evidence, and the evidence is the card's attestation chain and the possession proofs, which sluis verifies.
- **The possession proof on the challenge is a domain-separated signature.** A plain document signature over a label proves nothing about what else the same signature could mean, so the proof is a standalone signature (type `0x02`), which signs only its own subpackets, with the challenge in a critical hashed notation, made by the signing subkey. Such a signature parses as no commit, tag, checksum or certification. The exact challenge bytes are defined by sluis ADR 0043. The helper refuses a challenge that lacks the label that ADR fixes or has extra lines, shows the challenge in full to the person, and checks that the key it names is the card's subkey, before it signs. Each card has its own challenge, since each card has its own subkeys. The conformance test checks with `gpg` and `sqv` that the signature parses, and that neither accepts it as a signature over any document.

### Two cards, and a lost card

- **Each person has two cards (G4 A),** and each card holds its own subkeys: a card-born key cannot be copied, so the second card has subkeys of its own, bound under the same primary; SK2 to SK5 are replaced. A person therefore has one staff primary and four card subkeys, all in the keyring and on the hosting account under one fingerprint. The second card is kept in a second place.
- **A lost card is answered with new subkeys under the same primary.** The person's other card keeps working. The lost card's subkeys are revoked by sluis (a subkey revocation by its primary; hard if the card was stolen, soft if it is merely retired) and dropped from the keyring and the hosting account (G5 A). The person's fingerprint does not change, which is what a card-born primary could not give: attribution on the hosting platform and the identity others have certified survive a lost card. The person gets a new card and runs the helper again, with a new binding.
- **PIN, Admin PIN and touch** are set by the helper at issue and never stored by ritueel (G4 A). **Cards ship through Yubico Delivery;** ritueel does not order, ship or reset cards for anyone.
- **The binding record is sluis's.** Under SK1 E the record of a binding, with the attestation it was made on, is kept in sluis. The helper keeps the bundle and its own local record in the person's directory, and nothing is recorded in a ritueel ledger for a staff binding.

### The delegation ceremony

- **The root makes a trust signature over the certifier** (O1 a), **per company**: an OpenPGP certification of the key that certifies the primaries of that company, if sluis ADR 0043 keeps such a key, at level 1 (a trusted introducer), amount 120 (complete trust), with a regular expression that limits what it may certify to user IDs in that company's domain (RFC 9580, sections 5.2.3.21 and 5.2.3.22), marked critical, exportable, and valid for about 13 months like every intermediate. The expression is `<[^@<>]+@example\.com>$`, with `example.com` the company's domain: it starts at the `<`, takes a local part with no `@`, `<` or `>`, and ends at the `>`; **the domain is the apex only, and a subdomain address does not match.** Another company has its own key, its own domain and its own signature. The root stays offline, and a certifier can certify only addresses of its company's domain.
- **A separate key is covered by the same ceremony: the key that signs the staff keyring.** sluis signs the keyring with a dedicated key, separate from the certifier, so that signing a list and certifying a person stay two keys with two uses. The root makes an ordinary certification, with no trust signature, over the keyring-signing key, valid for about 13 months, so that a verifier that holds only the root's fingerprint can check the keyring's signature. ritueel owns the root that can revoke both keys, and the delegation ceremony covers both.
- **The hand-off** is the existing one for an intermediate, with a new OpenPGP type `openpgp-certifier`: sluis sends the public key to be certified, a self-signature as proof of possession, a `purpose` (`certify` or `keyring-sign`), the company's domain for `certify`, and the proof file of where the key lives (a cloud key service or a card), and gets back the key with the root's certification. The type is added to [the hand-off contract](/reference/hand-off-contract/) with its checks and vectors in a follow-up; until then nothing in the contract changes.
- **It renews like any intermediate,** at the root's yearly ceremony or under a cloud root's declared policy ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)). That is the one yearly act on the staff path, and it is the root's, not the staff's.
- **What each verifier relies on.** `gpgv` and `sqv` rely on the staff keyring and on each key's own expiry: they check a signature against a key they hold and its validity period, and they do not read the trust signature. Only a verifier that evaluates a web of trust reads it, and then only when the root is marked trusted in the verifier's keyring. Which verifiers of the matrix evaluate a trust signature with a domain expression is **unverified**, and a follow-up measures it.

### The flows

Who does each step: **ritueel** (the helper or the delegation ceremony), **sluis** (outside this repository), or the **person** or **operator**.

**Joiner**

| # | Step | Who |
|---|---|---|
| 1 | The operator orders two cards through Yubico Delivery. | operator |
| 2 | sluis makes and seals the person's primary for the company when the person joins. | sluis |
| 3 | The person prepares each card with the helper: firmware floor, PIN and Admin PIN, touch policy. | ritueel |
| 4 | The person starts `sluis key bind` after a fresh hardware step-up and gets the primary's public key and a challenge for each card. On each card the helper generates the two subkeys, reads the attestations, makes the back-signatures over the primary, and writes the bundle; then `staff challenge sign` signs the challenge. | person, sluis, ritueel |
| 5 | sluis checks the bundle on the server, binds the subkeys under the primary, records the binding, and certifies the primary. | sluis |
| 6 | sluis puts the key in the staff keyring, which it signs with its dedicated key, and syncs it to the person's own hosting account, once the person has authorised its App. | sluis |

**Mover** (a change of name or address). The primary is sluis's, so the user ID is sluis's to change: it adds the user ID with the primary, certifies it only for an address its directory lists for the authenticated person, and syncs the key. The card and the helper are not involved, since nothing on the card changes. Whether sluis wants a fresh proof from the card for a changed address is its record's; the helper's `challenge sign` serves it if so.

**Yearly.** None for the staff. sluis renews each certification by itself, about every 13 months, and the person does nothing. The only yearly act is the root's renewal of the delegation.

**Extension, about every 1095 days.** The person re-presents the same subkeys to `sluis key bind` with a fresh step-up: `staff proof refresh` re-reads the card's attestations and rebuilds the bundle, and `staff challenge sign` signs a fresh challenge. sluis re-verifies, signs the new binding with a later expiry, records it, warns before the old one, and its App uploads the key again to the hosting account. A person who does not extend, or who has lost the card, loses the subkeys at their expiry.

**Leaver, and a lost card.** sluis ends the binding, which lets the certification lapse, drops the key from the staff keyring and deletes it from the hosting account (only company-issued keys, GH1 A). **No revocation:** old commits stay verified on the hosting platform by design. The key is revoked only on a compromise (G5 A). A lost card ends only that card's subkeys, as above.

### The security risk, and what controls it

**The risk.** sluis holds the primary of every person. Whoever controls its signer can bind a subkey of their own under any person's primary, which then signs as that person, and whoever controls the certifier can certify any key for any address of the company's domain. That is the staff form of the limit [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit) accepts for a root, and it is sluis's to defend: its server checks the attestation and the possession proofs, behind a fresh hardware step-up, which is what the earlier design could not give, since its checks ran on the client. The maintainer weighed this and chose sealed primaries per company and per person (BD1 B, BD2 B): one person's primary is one person's loss, where a key shared by a company is the whole company's.

**What controls it from ritueel's side.** The trust signature is limited to the company's domain by the regular expression, cannot certify beyond one level, expires in about 13 months, and is made again only at a ceremony; so a compromised certifier is ended by not renewing it, and at once by a revocation from the root ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). Each company has its own, so one company's compromise does not reach another's domain. The helper's checks are not a control against anyone (above). How sluis defends its sealed primaries, its certifier and its records is its own record.

**What stays.** Anyone who can make sluis bind a subkey can make it "the company's"; and a card with its PIN and touch policy is the person's private key, as for any card. The record states the limit and does not hide it.

### The maintainer's own key

The maintainer's current key, a software primary with subkeys imported into cards, is neither a staff key nor, any longer, the company identity: those subkeys were not born on a card and cannot be attested (principle 1). The maintainer's company identity is now a primary that sluis holds, with subkeys born on a staff card, bound with the helper as its first real use (C1). The maintainer's personal key is re-made by the flow of 0012, with a new offline primary whose subkeys are born on a different card. "Ritueel will help me rotate master keys; after that we continue as we agree."

### Choices of the author

These are the author's way of filling what the decisions left open, and the maintainer can overrule each:

- **P-384 and the signature and authentication slots for the card subkeys;** no encryption subkey.
- **The binding of a card subkey expires after 1095 days, read from PX1,** and the extension is a proof from the card with sluis signing it. PX1 was decided for a card-born primary; the author carries it to the subkeys.
- **The certifier is per company,** with an apex-only domain expression, and the keyring-signing key is a second key under the same ceremony; both are conditional on what sluis ADR 0043 keeps.
- **BK1 A, BK2 A and BK3 A are read from the maintainer's relayed answers as:** the helper is ritueel's (BK1); a software key can be bound with its own class and staff company signing refuses it (BK2); sealed software keys for non-human identities are a later feature (BK3).
- **The old key of the maintainer is removed from the hosting account by hand,** and the personal key is re-made by the flow of 0012.
- **The person is present** whenever a subkey is born or a challenge is signed: it needs the card, its PIN and a touch.
- **A staff card is dedicated:** it holds no personal key.

## Consequences

- ritueel runs no service for staff: no per-person key service, no batch ceremony, no audit-trail reconciliation, no staff keyring builder. It keeps the roots, the delegation, the personal flow and a helper.
- ritueel grows the card helper (commands, a proof bundle format with its vectors) and one new hand-off type, `openpgp-certifier`, with the trust signature and its checks.
- The staff path depends on sluis for everything the person experiences: the primary, bind, renewal, the staff keyring and its sync. Until sluis ADR 0043 is accepted and built, this record's staff path is a target and nothing runs.
- A person's fingerprint survives a lost card and a replaced card, which a card-born primary could not give; the cost is that sluis holds the primary.
- A person holds two cards, and a third if they also keep a personal key.
- The company's trust in a person depends on a trust signature that only a ritueel ceremony can renew, so the root's yearly act includes it, once for each company.
- The conformance test is the gate for calling the helper built: nothing about the attestation of a card-born subkey has been run.
- The extension about every 1095 days is a recurring staff act, and it makes the hosting platform's stored copy stale until sluis uploads the key again. Whether the platform accepts a newer certificate over the stored one, or needs a delete and a create, is unmeasured: its REST documentation lists create, list, get and delete for a GPG key and says nothing about refreshing (read 2026-11-06).

## Roads not taken

- **A card-born primary, bound and certified by sluis (SK1 E as first read).** The private key never leaves the card and sluis holds no key that signs as a person, but the primary is the card's: a lost card changes the person's fingerprint and every attribution and certification with it, the company cannot rotate or recover an identity it manages, and a company that manages per-company identities of employees gets its identity from a device it does not hold; the maintainer chose a sealed primary per person and per company instead (BD1 B, BD2 B).
- **A per-person primary in a cloud key service, held by ritueel's side.** The company could rebind subkeys and a leaver needs no card, but the attestation and presence checks would run in ritueel on the client, so anyone who can call the cloud signer can bind a subkey of their own, it binds the staff path to one cloud provider, and it adds a yearly batch ceremony and a detection pipeline to catch misuse; sluis does the same work with the checks on its server.
- **ritueel holds the staff primaries.** The roots are ritueel's and the staff are not: a command-line tool with a ceremony per person is not a service that binds on demand, and a staff primary held by an offline tool would need a person at ritueel for every joiner and lost card ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).
- **One company primary holding everyone's subkeys.** One key to certify and revoke, but a hosting platform ties a key to one account, so attribution to a person breaks; every employee's user ID would sit on one key; and revoking one person would churn the whole key for everyone.
- **An SSH-signing fallback for people without a card.** Easy to start, but it has no OpenPGP identity and nothing the company can certify, and two standards would have to be taught and checked; the maintainer ruled it out (G1).
- **ritueel certifies each person online.** One fewer system for the staff path, but ritueel is a command-line tool and not a network service ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)), and a root that signs every joiner is not offline.
- **The person's staff key as a subkey under their personal primary.** One identity, but then the company would certify a key it does not control and could not unbind it, and the personal primary is the person's own (0012).
- **Subkeys made in software and imported into the card.** The usual practice, with a backup of the subkeys, but the key existed outside its store and cannot be attested; it is also the maintainer's own old key.
- **Ed25519 for the card subkeys.** Native on the applet, but the card layer was measured with P-384, the contract accepts nothing else for a subkey, and the verifier matrix has no Ed25519 subkey on a card.
- **A copy of the subkeys on the second card.** One set of keys per person, but a card-born key cannot be copied without having existed outside its device; the second card has subkeys of its own.
- **A plain document signature (type `0x00`) over a labelled challenge.** The simplest packet, but a label is not domain separation: the same signature form is what a tool takes for a document signature. A standalone signature with the challenge in a critical notation signs nothing else.
- **The keyring signed by the certifier.** One key fewer, but certifying a person and signing a list would share a key, and revoking one use would revoke both; a dedicated key keeps them apart under one root.
- **Revoking a leaver's key.** Looks final, but the hosting platform never re-checks old commits, so it changes nothing there; it is kept for a compromise.
- **The helper talks to sluis.** The challenge and the upload would be automatic, but the helper would depend on a network service and on sluis being up; the bundle is files the person carries.

## Follow-ups

- Build the card helper (`staff card prepare`, `staff proof make`, `staff proof refresh`, `staff challenge sign`, `staff proof check`) and the proof bundle version 1 with test vectors shared with sluis, which reads the same bundle in `sluis key bind` ([#103](https://github.com/truvity/ritueel/issues/103)).
- Run the conformance test on a real test card of firmware 5.7.4 or newer: generate the P-384 signing and authentication keys on the card; attest each and check the chain to "Yubico Attestation Root 1" and the attested public key; make the card's back-signatures (type `0x19`) over a software test primary and have that primary bind the subkeys; check the certificate with `gpg`, `gpgv` and `sqv`; make the challenge signature (type `0x02`, critical notation) and check that `gpg` and `sqv` parse it and that neither accepts it as a signature over a document; upload the certificate, with a software-held primary and card-born subkeys, to a test account on the hosting platform, and sign and verify a commit with the card; extend the binding, upload it again over the stored one, and see whether the platform accepts it ([#103](https://github.com/truvity/ritueel/issues/103)).
- Add the type `openpgp-certifier` and the trust signature to the hand-off contract, with its checks and vectors, and build the delegation ceremony ([#103](https://github.com/truvity/ritueel/issues/103)).
- Measure which verifiers of the matrix evaluate a trust signature with the domain regular expression ([#103](https://github.com/truvity/ritueel/issues/103)).
- Write the guides: prepare a staff card, bind a card (with the sluis page), a lost card, and which key is which ([#103](https://github.com/truvity/ritueel/issues/103)).
- Measure the encoding of the OpenPGP applet's attestation extensions, then read PIN and touch policy from them ([#18](https://github.com/truvity/ritueel/issues/18)).
