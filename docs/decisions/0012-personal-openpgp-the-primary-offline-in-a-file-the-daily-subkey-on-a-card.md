# 0012 — Personal OpenPGP: the primary offline in a file, the daily subkey on a card

**Status:** Accepted
**Date:** 2026-11-02

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) puts a person's own OpenPGP key in scope: a primary, a daily subkey born on a card, and keyring upkeep. [0003](/decisions/0003-key-stores-and-the-card-layer/#the-openpgp-card-store-and-personal-openpgp) gives the `openpgp-card` store, in which the card makes the subkey and its back-signature and an offline software primary makes the binding, "the same hand-off as a service's subkey, with the person's card as the requester". [Issue #18](https://github.com/truvity/ritueel/issues/18) builds it in M4. This record decides where the primary lives, what a personal directory is, how it differs from a company's, which subkeys the first version makes ([issue #81](https://github.com/truvity/ritueel/issues/81)), and how long a person's primary lives ([issue #82](https://github.com/truvity/ritueel/issues/82)). The maintainer decided the last two on 2026-11-02.

## Decision

This record is for a person's own key. A key the company issues to staff is born on a card, bound and certified by sluis, and ritueel only makes the card ready: [0014](/decisions/0014-staff-openpgp-primaries-born-on-cards-bound-and-certified-by-sluis-ritueel-makes-the-card-ready-and-runs-the-delegation/).

- **The primary is certify-only, version 4, ECDSA on P-384, and lives in the `software` store, in the encrypted file backend, offline.** It is not on a card, not in 1Password and not in the system keyring. A person uses it a few times a year, so the protection that matters is that it is off the network, and the protection against loss is a copy: a primary born on a card has no copy, and losing it loses the identity every contact has certified. The records say, as for every software key, that it can be copied ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store)). The passphrase is in the person's password manager.
- **A personal directory is an ordinary directory** with `kind: personal`: one root that has an OpenPGP primary and no X.509 key, no CA bundle, no CRL, no root list and no SSH CA key list. It uses the same engine, the same six steps, the same records and the same hand-off files; [the reference](/reference/personal-openpgp/) lists what changes. The `init` that makes it makes the primary and its revocation signatures ([0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/)).
- **The identity is the person's own,** a name and an address, unlike a root's release identity ([0006](/decisions/0006-release-keys-and-the-keyring-package/)).
- **Two subkeys are born on the card's OpenPGP applet: a signing subkey and an authentication subkey.** Each is made in one ceremony, with the card as the requester and the primary binding it, and the signing subkey carries its back-signature. The authentication subkey serves SSH through `gpg-agent` (the [guide](/guides/openpgp-ssh-authentication/) exists), and a lost card loses nothing by it: a new one is made. There is **no encryption subkey** in the first version: a key born on a card cannot be copied, so a lost card would lose the mail it decrypted ([principle 1](/principles/)), a key imported into the card is refused by the same principle, and nothing needs it yet (principle 8). An encryption subkey would get its own record, which states the loss of mail plainly. Each subkey is bound for about 13 months and renewed by re-signing at the yearly ceremony, like an intermediate; the primary is valid about three years and extended at each use ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)). Keyring upkeep is that renewal, with the expiry warnings of `status`.
- **A lost card is answered by the primary,** which revokes the subkey and binds a new one. The primary's own revocation signatures are for the day the primary is lost.
- **The output is the person's public certificate,** as binary and armoured files, to import into `gpg` and to upload to a hosting platform ([Sign git commits and tags](/guides/openpgp-sign-git/)). No package is built.

### How long a person's primary lives

**The three-year replacement rule of principle 3 applies to a software primary.** The primary of the first version is an encrypted file, which can be copied and read without a trace, so a calendar bound limits how long an unnoticed copy is useful and keeps the replace path exercised. For a person that is a new key every three years at most, which every contact certifies again; the guide says so before the first one is made.

**A primary on hardware (a card) or in a cloud KMS is replaced on events, not by calendar.** Such a key cannot be copied, so what ages it is what happens to the device, the service or the algorithm. The events are:

- **an advisory about the device or its firmware** that affects the key. In 2024 a side channel in the ECDSA implementation of a cryptographic library used inside some security keys let an attacker with physical access and specialised equipment recover an ECDSA private key (CVE-2024-45678, [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-45678), [the researchers' write-up](https://ninjalab.io/eucleak/), both read 2026-11-02). The devices already made accepted no firmware update ([the maker's advisory](https://www.yubico.com/support/security-advisories/ysa-2024-03/), read 2026-11-02), so the remedy was a new device, and a key made in the old one had to be replaced;
- **deprecation of its algorithm**;
- **loss, or the end of life of the card.**

At the yearly ceremony the holder also **reviews the advisories** for the devices, services and algorithms in use, and records that they did. The first version builds the software primary only ([issue #18](https://github.com/truvity/ritueel/issues/18)); a primary on a card or in a KMS is not served (see Consequences), and this rule is what it will follow if it is.

## Consequences

- A person's primary is a copy by nature. The guide says to keep two encrypted copies in different places, and the restore drill checks one.
- A person's software primary is replaced every three years at most, and every contact certifies the new one. The cost is the person's, and the guide says so.
- A lost card loses no mail, because nothing is encrypted to it; the person who wants an encrypted-mail key makes one outside ritueel until a record decides otherwise.
- The yearly ceremony gains one step, the advisory review, and the record of it.
- The hand-off contract gains a second capability for subkeys, `authenticate` (key flag `0x20`), before the first release.
- One engine, one set of files, and so one set of tests: the personal case is a configuration of the company case, with the X.509 half switched off.
- A person with no card can still run a personal directory for a drill, with the subkey in software, as a test.
- A person who wants their primary on a card of their own is not served; the `openpgp-card` store makes subkeys. A primary on a card is the same decision as a root card and costs two cards.

## Roads not taken

- **The primary on a card.** The key cannot be copied, but a card has no backup, and a lost primary is a lost identity; the redundancy a person needs is a copy.
- **The primary in 1Password or the keyring.** Convenient, but whoever unlocks the vault or any program of the user once the keyring is unlocked has the master key ([0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store)).
- **A separate tool for personal keys.** Smaller each, but the ceremony, the records and the checks would be written twice ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).
- **The daily subkey generated in software and moved to the card.** The usual practice and a backup of the subkey, but the key would have existed outside its store, which principle 1 rules out.
- **A release identity for a person.** A name that outlives the person, but a person's key is certified by contacts under their own name.
- **Signing subkey only.** The contract as written and the least code, but a person who wants SSH through `gpg-agent` would make that subkey by hand, outside the record.
- **Signing, authentication and encryption, all born on the card.** A complete personal key, but a lost card loses the mail it decrypted, and the person would have to accept that in every record.
- **An encryption subkey made in software and moved to the card.** The usual practice, and the subkey can be backed up, but the key existed outside its store, which principle 1 rules out.
- **The primary lives until an event, whatever its store.** What most people do, but a copyable file ages unobserved and the replace path is exercised only by accident.
- **Replace every primary at most every three years, whatever its store.** One rule, but a calendar forces a new key on a card that cannot be copied, at the cost of every contact, when an advisory or a lost card is what ends it.
- **Replace a primary every six years.** Halves the cost to the person, but the number is invented and no standard gives it.

## Follow-ups

- Build `init --kind personal`, `personal subkey add`, the renewal and the output ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Add the `authenticate` capability to the hand-off contract and its test vectors, and the authentication subkey to the personal reference and guide ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Add the yearly advisory review to the yearly guide and the personal guide ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Measure the attestation extensions of the OpenPGP applet, then read PIN and touch policy from them ([issue #18](https://github.com/truvity/ritueel/issues/18)).
