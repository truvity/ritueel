# 0012 — Personal OpenPGP: the primary offline in a file, the daily subkey on a card

**Status:** Proposed
**Date:** 2026-11-02

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) puts a person's own OpenPGP key in scope: a primary, a daily subkey born on a card, and keyring upkeep. [0003](/decisions/0003-key-stores-and-the-card-layer/#the-openpgp-card-store-and-personal-openpgp) gives the `openpgp-card` store, in which the card makes the subkey and its back-signature and an offline software primary makes the binding, "the same hand-off as a service's subkey, with the person's card as the requester". [Issue #18](https://github.com/truvity/ritueel/issues/18) builds it in M4. Not decided: where the primary lives, what a personal directory is, how it differs from a company's, which subkeys the first version makes, and how long a person's primary lives.

## Decision

- **The primary is certify-only, version 4, ECDSA on P-384, and lives in the `software` store, in the encrypted file backend, offline.** It is not on a card, not in 1Password and not in the system keyring. A person uses it a few times a year, so the protection that matters is that it is off the network, and the protection against loss is a copy: a primary born on a card has no copy, and losing it loses the identity every contact has certified. The records say, as for every software key, that it can be copied ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/), [0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store)). The passphrase is in the person's password manager.
- **A personal directory is an ordinary directory** with `kind: personal`: one root that has an OpenPGP primary and no X.509 key, no CA bundle, no CRL, no root list and no SSH CA key list. It uses the same engine, the same six steps, the same records and the same hand-off files; [the reference](/reference/personal-openpgp/) lists what changes. The `init` that makes it makes the primary and its revocation signatures ([0010](/decisions/0010-readiness-is-made-at-birth-and-proved-by-a-drill/)).
- **The identity is the person's own,** a name and an address, unlike a root's release identity ([0006](/decisions/0006-release-keys-and-the-keyring-package/)).
- **The daily subkey is born on the card's OpenPGP applet,** with its back-signature, in one ceremony: the card is the requester, the primary binds. It is bound for about 13 months and renewed by re-signing at the yearly ceremony, like an intermediate; the primary is valid about three years and extended at each use ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#validity-renewal-and-replacement)). Keyring upkeep is that renewal, with the expiry warnings of `status`.
- **A lost card is answered by the primary,** which revokes the subkey and binds a new one. The primary's own revocation signatures are for the day the primary is lost.
- **The output is the person's public certificate,** as binary and armoured files, to import into `gpg` and to upload to a hosting platform ([Sign git commits and tags](/guides/openpgp-sign-git/)). No package is built.

:::caution[Open]
Two questions could change this record, both for the maintainer, and are tracked with [issue #18](https://github.com/truvity/ritueel/issues/18). The record is `Proposed` until they are decided; the first version builds what the principles say meanwhile.

1. **Which subkeys.** The contract binds signing subkeys only, and the first version builds that. An authentication subkey (SSH through `gpg-agent`, the [guide](/guides/openpgp-ssh-authentication/) exists) is cheap and loses nothing if the card is lost. An encryption subkey born on a card cannot be copied, so a lost card loses the mail it decrypted ([principle 1](/principles/)), and an imported one is refused by the same principle.
2. **How long a person's primary lives.** Principle 3 replaces key material on an event or at most every three years. For a company root that is a transition that outsiders handle; for a person it means every contact certifying a new key. The first version applies the principle.
:::

## Consequences

- A person's primary is a copy by nature. The guide says to keep two encrypted copies in different places, and the restore drill checks one.
- One engine, one set of files, and so one set of tests: the personal case is a configuration of the company case, with the X.509 half switched off.
- A person with no card can still run a personal directory for a drill, with the subkey in software, as a test.
- A person who wants their primary on a card of their own is not served; the `openpgp-card` store makes subkeys. A primary on a card is the same decision as a root card and costs two cards.

## Roads not taken

- **The primary on a card.** The key cannot be copied, but a card has no backup, and a lost primary is a lost identity; the redundancy a person needs is a copy.
- **The primary in 1Password or the keyring.** Convenient, but whoever unlocks the vault or any program of the user once the keyring is unlocked has the master key ([0003](/decisions/0003-key-stores-and-the-card-layer/#the-software-store)).
- **A separate tool for personal keys.** Smaller each, but the ceremony, the records and the checks would be written twice ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)).
- **The daily subkey generated in software and moved to the card.** The usual practice and a backup of the subkey, but the key would have existed outside its store, which principle 1 rules out.
- **A release identity for a person.** A name that outlives the person, but a person's key is certified by contacts under their own name.
- **Encryption and authentication subkeys in the first version.** A complete personal key, but each is a decision in the open question above, and nothing waits on them.

## Follow-ups

- Build `init --kind personal`, `personal subkey add`, the renewal and the output ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Measure the attestation extensions of the OpenPGP applet, then read PIN and touch policy from them ([issue #18](https://github.com/truvity/ritueel/issues/18)).
