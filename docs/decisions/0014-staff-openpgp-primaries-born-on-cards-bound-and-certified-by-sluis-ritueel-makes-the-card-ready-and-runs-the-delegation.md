# 0014 — Staff OpenPGP: primaries born on cards, bound and certified by sluis; ritueel makes the card ready and runs the delegation

**Status:** Accepted
**Date:** 2026-11-06

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) leaves company-wide OpenPGP to a record of its own, and [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) decides a person's own key. A company that wants its staff to sign commits needs a key it can recognise as its own, stop trusting when the person leaves, and attribute to one person on a hosting platform. This record decides the part of that which belongs to ritueel; the rest belongs to sluis, which holds the intermediate. The tracking issue is [#103](https://github.com/truvity/ritueel/issues/103).

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
> **O1 a** (2026-11-01): the company root delegates, by a domain-scoped trust signature made at a ritueel ceremony, to an online certifier in sluis ([sluis ADR 0024](https://github.com/truvity/sluis/blob/main/docs/decisions/0024-root-custody-and-the-signing-api.md)).
>
> **SK1 E, BK1 A, BK2 A, BK3 A.**
>
> **PX1 yes** (2026-11-06).

G4's "ritueel's ledger" is, under SK1 E, the binding record that sluis keeps; the helper keeps a local record only.

In the maintainer's later decisions of the same day, as the author reads them: staff keys are **key bindings inside sluis**. A person generates a primary on their own card and binds it to their identity with `sluis key bind`, after a fresh hardware step-up, presenting the proof of possession and the card's attestation. sluis checks both on the server, records the person, the key, its kind, class and expiry, and certifies the key with one intermediate, under the root's trust signature (O1 a). There are no per-person cloud keys and no yearly ceremony for staff; sluis renews the certification by itself. A software key can be bound, with the class `software`, but company signing for staff refuses it (G1 A). Sealed software keys for non-human identities are a later feature (BK3 A) and nothing more is decided here. sluis produces the staff keyring from its bindings and syncs it to the hosting platform (GH3 changed: sluis now makes the keyring as well, and signs it with a dedicated key). BK1 A is that ritueel provides the card helper below. PX1 yes is that the card primary does expire, after 1095 days (about three years), and is extended at the card with its PIN and a touch; afterwards sluis's App uploads the key again to the hosting account. A lost or forgotten key therefore dies by itself. These decisions replace two earlier ones of the same day, a per-person primary held by the company through ritueel (G2a) and kept in a cloud key service (G2b); the roads not taken say why.

The binding, the record, the certification, the renewal, the keyring and the sync are sluis's, and are decided in sluis ADR 0043 on key bindings ([pull request #1493](https://github.com/truvity/sluis/pull/1493)). This record states them only as far as ritueel's part cannot be read without them, and it is the sluis record that decides if the two differ.

## Decision

### Staff keys and personal keys are two flows

A **staff key** is an OpenPGP primary born on a card, bound in sluis and certified by the company, for the staff address. A **personal key** is a person's own ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)), **and that flow is unchanged:** a person's own primary is theirs, in their file, and ritueel's part is the ceremony of 0012. Only a staff key is bound, certified and synced by the company. The OpenPGP applet of a card holds one key in each of its slots, so a card that holds a staff key holds no personal key: a person who has both uses two cards.

### What ritueel does and what sluis does

| ritueel | sluis |
|---|---|
| Holds the company roots; runs their ceremonies and transitions ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). | Holds the certifying intermediate and uses it online. |
| **The delegation ceremony:** the root makes a domain-scoped trust signature over the certifying intermediate, and a certification over the key that signs the staff keyring, with a hand-off (below). | Receives both, installs them, and warns before it expires, as for every intermediate ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)). |
| **The card helper:** makes a person's card ready, generates the key on it, and writes the proof bundle (below). It makes no network call. | `sluis key bind`: the fresh hardware step-up, the check of the bundle on the server, the record (person, key, kind, class, expiry), the certification, and its renewal. |
| Personal keys (0012). | The staff keyring, built from the bindings, and its sync to the hosting platform; unbinding a leaver or a lost card. |
| Teaches all of it. | The audit record of every bind, renewal and unbind. |

ritueel holds no staff key, binds no key, certifies no person and runs no ceremony per person. The reasons are in the roads not taken.

### The card helper and the proof bundle

- **The helper makes a card ready and produces the bundle (BK1 A).** It checks the firmware floor, changes the PIN and the Admin PIN at the terminal and sets the touch policy per key (G4 A), generates the primary and an authentication key on the card's OpenPGP applet, reads the card's attestation of both, and writes the certificate and the proof. It makes the person's revocation signature at birth and writes it apart from the bundle ([revocation material](/reference/revocation-material/)); the person keeps it. **The handshake is key-first:** the key is generated on the card first; `sluis key bind` then issues a challenge for that key, and a second helper command signs it with the card (below). It has no online dependency on sluis: the files are carried by the person to `sluis key bind`, which reads bundle version 1; the bundle's format, and the test vectors for it, are shared by both repositories.
- **The primary** is generated on the card, in the signature slot, as version 4 ECDSA on P-384 with key flags certify and sign (`0x03`), with one user ID, the person's name and staff address, and no encryption subkey. The authentication key becomes an authentication subkey (`0x20`), bound by the primary, for SSH through `gpg-agent`, as in 0012. **The primary expires 1095 days (about three years) after it is made** (PX1 yes), and the person extends it at the card with the PIN and a touch, to 1095 days from the extension, before it ends; a key nobody extends, because the card is lost or the person forgot, ends by itself, even if nothing else removes it. The card cannot be copied, so the key is otherwise replaced on an event ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/#how-long-a-persons-primary-lives)), and the company's trust in it also ends when sluis's certification lapses or is removed (G5 A).
- **Only attested subkeys may appear.** The helper produces exactly two keys, the primary and the authentication subkey, both generated on the card and both attested, and exports a minimal certificate with those two and nothing else. A subkey the person added by another tool, an encryption subkey, a subkey made in software or one the card did not attest, is never put in the bundle; `proof check` and sluis refuse a bundle that holds one (`subkey-not-attested`), and a subkey that is not in the bundle is not the company's, since sluis certifies the bundle as presented. Every command that rewrites a certificate, the extension and the user-ID change included, re-reads the card and re-checks this before it writes.
- **P-384 is the contract's rule, and it is kept.** The [hand-off contract](/reference/hand-off-contract/#keys-and-hashes) accepts P-384 only, with SHA-384, and the card layer was measured with P-384 on firmware 5.8 ([card libraries](/research/card-libraries-and-tooling-2026-11-01/)). The card primary is P-384 with SHA-384, so it needs no exception. The contract is not extended for the bundle: the bundle goes from ritueel's helper to sluis, the contract from a system that holds intermediates to ritueel's root, and the bundle is specified on [the reference page](/reference/staff-openpgp/#the-proof-bundle) with its own version.
- **The firmware floor is 5.7.4,** for staff cards. Firmware 5.7.4 and newer are signed under the maker's new root, "Yubico Attestation Root 1", which is the only attestation root of staff bindings, as in sluis ADR 0043. Older cards are out: they chain to the earlier root, which a staff binding does not pin. This is stricter than the 5.7.0 of ritueel's other cards ([cards](/reference/cards/#the-attestation-bundle)), because the binder pins one root. The OpenPGP applet attests keys since 5.2.3, so the floor is an evidence rule, not the applet's.
- **The attestation rule.** The card attests a key that was generated on it. `ykman openpgp keys attest` takes the slots `sig`, `enc` and `aut` ([Yubico, read 2026-11-06](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html)), and the signature slot is where a card-born certify-and-sign primary lives, so the primary can be attested. What the attestation proves is that the key was generated on the device. It does not prove the key flags, which are in the self-certification the card makes, so a verifier takes the flags from that signature and never from the attestation. **Unverified:** Yubico's pages say that attestation exists from firmware 5.2.3 for keys generated on the device, but the pages read on 2026-11-06 do not state that the signature-slot key of a P-384 primary is covered, nor that the same key can make certifications; and the encoding of the attestation extensions is not measured ([#18](https://github.com/truvity/ritueel/issues/18)). A conformance test on a real test card settles it before the helper is called built (see Follow-ups).
- **The helper's own checks are a convenience.** It checks the bundle before it writes it (`proof check`), and the attestation chain, the possession proof and the firmware again. **sluis does not trust any of it:** it checks the bundle itself, on the server. A bundle from a modified helper, or one built by hand, is as good as its evidence, and the evidence is the card's attestation chain and the possession proof, which sluis verifies.
- **The possession proof is a domain-separated signature, made on a challenge sluis gives.** A plain document signature over a label proves nothing about what else the same signature could mean, so the proof is a standalone signature (type `0x02`), which signs only its own subpackets, with the challenge in a critical hashed notation. Such a signature parses as no commit, tag, checksum or certification. The exact challenge bytes are defined by sluis ADR 0043. The helper refuses a challenge that lacks the label that ADR fixes or has extra lines, shows the challenge in full to the person, and checks that the key it names is the card's key, before it signs. Each card has its own challenge, since each card has its own key and binding. The conformance test checks with `gpg` and `sqv` that the signature parses, and that neither accepts it as a signature over any document.

### Two cards, and a lost card

- **Each person has two cards (G4 A),** and each card holds its own primary: a card-born key cannot be copied, so the second card has a key of its own and its own binding in sluis; SK2 to SK5 are replaced by SK1 E. A person therefore has two staff fingerprints, both certified, both in the keyring and both on the hosting account. The second card is kept in a second place.
- **A lost card is answered with a new key and a new fingerprint.** The person's other card keeps working. The lost card's binding is removed in sluis, which drops the key from the keyring and the hosting account (G5 A); the key is revoked, from the revocation signature made at birth, only if the card was stolen, or the key is believed compromised. The person gets a new card and runs the helper again, with a new binding.
- **PIN, Admin PIN and touch** are set by the helper at issue and never stored by ritueel (G4 A). **Cards ship through Yubico Delivery;** ritueel does not order, ship or reset cards for anyone.
- **The binding record is sluis's.** Under SK1 E the record of a binding, with the attestation it was made on, is kept in sluis. The helper keeps the bundle and its own local record in the person's directory, and nothing is recorded in a ritueel ledger for a staff binding.

### The delegation ceremony

- **The root makes a trust signature over the certifying key** (O1 a): an OpenPGP certification of sluis's certifying intermediate, level 1 (a trusted introducer), amount 120 (complete trust), with a regular expression that limits what the intermediate may certify to user IDs in the company's domain (RFC 9580, sections 5.2.3.21 and 5.2.3.22), marked critical, exportable, and valid for about 13 months like every intermediate. The expression is `<[^@<>]+@example\.com>$`, with `example.com` the company's domain: it starts at the `<`, takes a local part with no `@`, `<` or `>`, and ends at the `>`; **the domain is the apex only, and a subdomain address does not match.** The root stays offline, and the intermediate can certify only addresses of the domain, which is the root's side of what sluis ADR 0043 enforces on its own (it certifies only verified addresses of the person in the root's domain).
- **A second key is covered by the same ceremony: the key that signs the staff keyring.** sluis produces the staff keyring and signs it with a dedicated key, separate from the certifying intermediate, so that signing a list and certifying a person stay two keys with two uses. The root makes an ordinary certification, with no trust signature, over the keyring-signing key, valid for about 13 months, so that a verifier that holds only the root's fingerprint can check the keyring's signature. ritueel owns the root that can revoke both keys, and the delegation ceremony covers both.
- **The hand-off** is the existing one for an intermediate, with a new OpenPGP type `openpgp-certifier`: sluis sends the public key of the key to be certified, a self-signature as proof of possession, a `purpose` (`certify` or `keyring-sign`), and the proof file of where the key lives (a cloud key service or a card), and gets back the key with the root's certification. The type is added to [the hand-off contract](/reference/hand-off-contract/) with its checks and vectors in a follow-up; until then nothing in the contract changes.
- **It renews like any intermediate,** at the root's yearly ceremony or under a cloud root's declared policy ([0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#renewal-of-a-cloud-root-under-a-policy)). That is the one yearly act on the staff path, and it is the root's, not the staff's.
- **What each verifier relies on.** `gpgv` and `sqv` rely on the staff keyring and on each key's own expiry: they check a signature against a key they hold and its validity period, and they do not read the trust signature. Only a verifier that evaluates a web of trust reads it, and then only when the root is marked trusted in the verifier's keyring. So the keyring and the 1095-day expiry are what most verifiers use, and the certification is for the tools that evaluate trust. Which verifiers of the matrix evaluate a trust signature with a domain expression is **unverified**, and a follow-up measures it.

### The flows

Who does each step: **ritueel** (the helper or the delegation ceremony), **sluis** (outside this repository), or the **person** or **operator**.

**Joiner**

| # | Step | Who |
|---|---|---|
| 1 | The operator orders two cards through Yubico Delivery. | operator |
| 2 | The person prepares each card with the helper: firmware floor, PIN and Admin PIN, touch policy. | ritueel |
| 3 | On each card, the helper generates the primary and the authentication key, reads the attestations, makes the revocation signature, and writes the certificate and the proof. | ritueel |
| 4 | The person starts `sluis key bind` for that key, after a fresh hardware step-up; sluis issues a challenge that names the person, the boundary and the key. The helper signs it with the card (`staff challenge sign`). sluis checks the bundle, records the binding, and certifies the key. Each card has its own challenge. | person, ritueel, sluis |
| 5 | sluis puts the key in the staff keyring, which it signs with its dedicated key, and syncs it to the person's own hosting account, once the person has authorised its App. | sluis |

**Mover** (a change of name or address). The new user ID is certified by the card's primary, which needs the card, its PIN and a touch, so the helper makes it with the person present. That is a new proof: the person signs a fresh challenge for the same key with the card, and sluis re-checks the whole bundle, the attestation, the certificate and that the address is one its directory lists for the authenticated person, as sluis ADR 0043 requires of any presented key. No address can be added to a key without the card, and none is accepted without sluis's check. How sluis re-binds a changed identity is in its record.

**Yearly.** None for the staff. sluis renews each certification by itself, about every 13 months, and the person does nothing. The only yearly act is the root's renewal of the delegation.

**Extension, about every 1095 days.** The person extends the primary's expiry at the card with the helper (`staff expiry extend`), which needs the card, its PIN and a touch, and re-checks the card's keys as above. The person then signs a challenge for the extended key (`staff challenge sign`) and presents it to `sluis key bind`; sluis accepts it only as the same key with a later expiry, after a fresh step-up. sluis records the new expiry, warns before the old one, and its App uploads the key again to the hosting account. A person who does not extend, or who has lost the card, loses the key at its expiry.

**Leaver, and a lost card.** sluis unbinds the key, which lets the certification lapse, drops it from the staff keyring and deletes it from the hosting account (only company-issued keys, GH1 A). **No revocation:** old commits stay verified on the hosting platform by design. The key is revoked only on a compromise (G5 A), with the revocation signature made at birth.

### The security risk, and what controls it

**The risk.** sluis's certifying intermediate is the one key that makes a key "the company's" for the whole domain. Whoever controls it can certify any key for any address in the domain, and the hosting sync would publish it. That is the staff form of the limit [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit) accepts for a root, and it is sluis's to defend; ritueel can limit it from the root.

**What controls it from ritueel's side.** The trust signature is limited to the company's domain by the regular expression, cannot certify beyond one level, expires in about 13 months, and is made again only at a ceremony; so a compromised intermediate is ended by not renewing it, and at once by a revocation from the root ([0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)). A staff key does not exist in any service that ritueel runs, so there is no per-person key to misuse, and the helper's checks are not a control against anyone (above): the control is sluis's server-side check of attestation and possession, behind a fresh hardware step-up. How sluis defends its intermediate and its records is its own record.

**What stays.** Anyone who can make sluis certify a key can make it "the company's"; and a card with its PIN and touch policy is the person's private key, as for any card. The record states the limit and does not hide it.

### The maintainer's own key

The maintainer's current key, a software primary with subkeys imported into cards, is not a staff key: it was not born on a card and cannot be attested (principle 1). It is also not a personal key in the sense of 0012, which the maintainer would re-make with it. The maintainer therefore does two things with the helper and the ceremony of 0012: makes a staff key on a staff card and binds it in sluis, as the first real use of the helper (C1), and rotates the personal key by the flow of 0012, with a new offline primary whose subkeys are born on a different card. "Ritueel will help me rotate master keys; after that we continue as we agree."

### Choices of the author

These are the author's way of filling what the decisions left open, and the maintainer can overrule each:

- **P-384 and the signature slot for the primary,** and an authentication key as a subkey; no encryption subkey.
- **The mover's new proof and the certificate re-check on every rewrite** are the author's alignment with sluis ADR 0043.
- **BK1 A, BK2 A and BK3 A are read from the maintainer's relayed answers as:** the helper is ritueel's (BK1); a software key can be bound as class `software` and staff company signing refuses it (BK2); sealed software keys for non-human identities are a later feature (BK3).
- **The old key of the maintainer is removed from the hosting account by hand,** and the personal key is re-made by the flow of 0012.
- **The person is present** whenever a key is born or a user ID is added: it needs the card, its PIN and a touch.
- **A staff card is dedicated:** it holds no personal key.

## Consequences

- ritueel runs no service for staff: no per-person key service, no batch ceremony, no audit-trail reconciliation, no staff keyring builder. It keeps the roots, the delegation, the personal flow and a helper.
- ritueel grows the card helper (commands, a proof bundle format with its vectors) and one new hand-off type, `openpgp-certifier`, with the trust signature and its checks.
- The staff path depends on sluis for everything the person experiences: bind, renewal, the staff keyring and its sync. Until sluis ADR 0043 on key bindings is accepted and built, this record's staff path is a target and nothing runs.
- A person holds two cards and two staff fingerprints, and a third card if they also keep a personal key.
- The company's trust in a person depends on a trust signature that only a ritueel ceremony can renew, so the root's yearly act includes it.
- The conformance test is the gate for calling the helper built: nothing about the attestation of a card-born primary has been run.
- The staff have one recurring act of their own, the extension at the card about every three years, and it makes the hosting platform's stored copy stale until sluis uploads the key again. Whether the platform accepts a newer certificate over the stored one, or needs a delete and a create, is unmeasured: its REST documentation lists create, list, get and delete for a GPG key and says nothing about refreshing (read 2026-11-06).

## Roads not taken

- **A per-person primary in a cloud key service, held by the company.** The company could rebind subkeys and a leaver needs no card, but the attestation and presence checks run in ritueel on the client, so anyone who can call the cloud signer can bind a subkey of their own, the company itself can mint subkeys as any person, the design binds the staff path to one cloud provider, and it adds a yearly batch ceremony and a detection pipeline to catch misuse.
- **Sealed per-person software primaries held by the company.** No card needed and a central place for the keys, but a compromise of the place exposes every person at once, and a key that can be copied cannot be attested, which principle 1 rules out; sluis may later hold sealed keys for non-human identities, which is a different thing (BK3).
- **One company primary holding everyone's subkeys.** One key to certify and revoke, but a hosting platform ties a key to one account, so attribution to a person breaks; every employee's user ID would sit on one key; and revoking one person would churn the whole key for everyone.
- **An SSH-signing fallback for people without a card.** Easy to start, but it has no OpenPGP identity and nothing the company can certify, and two standards would have to be taught and checked; the maintainer ruled it out (G1).
- **No calendar expiry on the primary.** Nothing for the person to extend and nothing to re-upload, but a key on a lost or forgotten card, or one that nobody remembers, would stay valid until someone removes it; the maintainer chose an expiry (PX1 yes) so that such a key dies by itself.
- **The keyring signed by the certifying intermediate.** One key fewer, but certifying a person and signing a list would share a key, and revoking one use would revoke both; a dedicated key keeps them apart under one root.
- **ritueel certifies each person online.** One fewer system for the staff path, but ritueel is a command-line tool and not a network service ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)), and a root that signs every joiner is not offline.
- **The person's staff key as a subkey under their personal primary.** One identity, but then the company would certify a key it does not control and could not unbind it, and the personal primary is the person's own (0012).
- **Subkeys made in software and imported into the card.** The usual practice, with a backup of the subkeys, but the key existed outside its store and cannot be attested; it is also the maintainer's own old key.
- **Ed25519 for the card primary.** Native on the applet, but the card layer was measured with P-384, the contract accepts nothing else, and the verifier matrix has no Ed25519 primary on a card.
- **A copy of the key on the second card.** One fingerprint per person, but a card-born key cannot be copied without having existed outside its device; the second card has its own key and its own binding.
- **Revoking a leaver's key.** Looks final, but the hosting platform never re-checks old commits, so it changes nothing there; it is kept for a compromise.
- **A plain document signature (type `0x00`) over a labelled challenge.** The simplest packet, but a label is not domain separation: the same signature form is what a tool takes for a document signature. A standalone signature with the challenge in a critical notation signs nothing else.
- **The helper talks to sluis.** The challenge and the upload would be automatic, but the helper would depend on a network service and on sluis being up; the bundle is files the person carries.

## Follow-ups

- Build the card helper (`staff card prepare`, `staff proof make`, `staff challenge sign`, `staff proof check`) and the proof bundle version 1 with test vectors shared with sluis, which reads the same bundle in `sluis key bind` ([#103](https://github.com/truvity/ritueel/issues/103)).
- Run the conformance test on a real test card (it includes extending the expiry on the card, uploading the extended certificate to the test account over the stored one, and checking that the possession signature (type `0x02`, with the critical notation) parses in `gpg` and `sqv` and is accepted by neither as a signature over a document, with a card of firmware 5.7.4 or newer): generate a P-384 certify-and-sign primary in the signature slot, attest it, make a certification and a binding with it, check them with `gpg`, `gpgv` and `sqv`, upload the certificate to a test account on the hosting platform, and sign and verify a commit ([#103](https://github.com/truvity/ritueel/issues/103)).
- Add the type `openpgp-certifier` and the trust signature to the hand-off contract, with its checks and vectors, and build the delegation ceremony ([#103](https://github.com/truvity/ritueel/issues/103)).
- Measure which verifiers of the matrix evaluate a trust signature with the domain regular expression ([#103](https://github.com/truvity/ritueel/issues/103)).
- Write the guides: prepare a staff card, bind a key (with the sluis page), a lost card, and which key is which ([#103](https://github.com/truvity/ritueel/issues/103)).
- Measure the encoding of the OpenPGP applet's attestation extensions, then read PIN and touch policy from them ([#18](https://github.com/truvity/ritueel/issues/18)).
