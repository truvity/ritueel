---
title: Personal OpenPGP
description: The personal directory and its ritueel.yaml, what differs from a company directory, the profiles of the primary and daily subkey, and the two commands.
sidebar:
  order: 15
---

*Not built yet. This is the page that [ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) leaves for the details, and that record is `Accepted`. It decides the profile and how long a person's primary lives; [ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/) decides the two stages of the key, the day-to-day subkeys and how a subkey is retired. The [hand-off contract](/reference/hand-off-contract/#openpgp-subkey) carries the signing and the authentication capability, with their test vectors. The code is [issue #18](https://github.com/truvity/ritueel/issues/18): stage one is M3, and stage two is M6. How to use the result is in [Sign git commits and tags](/guides/openpgp-sign-git/) and [Your own OpenPGP key](/guides/personal-openpgp/).*

A key the company issues to staff is a different flow, with the primary held by sluis: [Staff OpenPGP](/reference/staff-openpgp/). A person's own OpenPGP key is the same ritual as a service's subkey: a key is made in a store and bound under a primary. Here the primary is the person's, offline in a key file, and the subkeys are born on the person's cards. ritueel runs it with the engine of the company case, with the X.509 half switched off.

## The directory

```yaml
version: 1
kind: personal
person:
  name: Ada Example
  address: ada@example.com
policy:
  stores: [openpgp-card]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: false
  validity_months: 13
intermediates:
  - name: daily
    type: openpgp-subkey
    capability: sign
  - name: ssh
    type: openpgp-subkey
    capability: authenticate
```

`kind: personal` replaces `name` and `release_address` with `person` (a name of 1 to 64 characters and an address) and is otherwise [the same file](/reference/directory/#ritueelyaml). It is additive: a file without `kind` is a company directory, as before.

| Part | In a company directory | In a personal directory |
|---|---|---|
| Roots | `A` and `B` (two cards), or one cloud root. | One root, `A`, with an OpenPGP primary and no X.509 key. |
| `root.json` | Has `x509_spki_sha256`. | Has no X.509 member. |
| Trust products | Root list, CA bundle, CRLs, SSH CA key list, keyring package. | The person's public certificate, `products/<sequence>/<fingerprint>.pgp` and `.asc`. |
| Hand-off check 3 | The primaries equal those on the root list. | They equal the directory's one primary ([the contract](/reference/hand-off-contract/#what-the-certifier-checks-1)). |
| Target of the root set | 2 or 1. | 1; `status` raises no `root-set` finding for it. |
| `root add`, `retire`, `revoke` | [As the transitions page says](/reference/transitions/). | The same, with the OpenPGP half only: no cross-certificate. |
| The software root | A test root only for a company. | The real primary, in the encrypted file backend ([the software store](/reference/software-store/)). |

## The profiles

The primary is the profile of [the OpenPGP primary](/reference/directory/#the-openpgp-primary) with two changes: its one user ID is `<name> <address>` of the person, and it is made in the `software` store with the encrypted file backend, whose key file is `A.openpgp.key.age` in the key directory, opened as [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/) says. It is valid 36 months and extended at each use. In stage one an existing primary may be adopted instead ([below](/reference/personal-openpgp/#stage-one-an-adopted-primary)).

The two subkeys are the subkeys of [the contract](/reference/hand-off-contract/#openpgp-subkey): ECDSA P-384, version 4, a back-signature made by the subkey, a binding of about 13 months. The signing subkey (`daily` above) has key flags `0x02`; the authentication subkey (`ssh` above) has `0x20` and serves SSH through `gpg-agent` ([the guide](/guides/openpgp-ssh-authentication/)). One set of signing and authentication subkeys is born on each day-to-day card.

The encryption subkey is the exception: it is made in software, loaded onto each day-to-day card, and has a wrapped backup in the directory, so that a lost card does not lose the mail it decrypted ([ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#day-to-day-cards)). The personal ceremony itself makes it and the primary binds it; it is not a capability of the hand-off contract. The wrapped backup's format and the command are fixed with stage one ([issue #18](https://github.com/truvity/ritueel/issues/18)). The touch setting of each key is the holder's choice, and [the guide](/guides/personal-openpgp/) says what each choice costs.

## The commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init --kind personal --store software --backend file --key-dir DIR --revocation-dir DIR` | Makes the directory, the primary and its revocation signatures ([revocation material](/reference/revocation-material/)), and the first certificate. | Yes |
| `ritueel personal subkey add NAME --card SERIAL` | One ceremony: the card makes the subkey of the entry `NAME`, with its capability, and its back-signature, the primary binds it, and the certificate is rebuilt. It writes the request and the proof into `requests/` like any requester, then answers them. | Yes |

Everything else is planned: the renewal plan (`ritueel due`, then `ritueel run PLAN --confirm DIGEST`) renews the binding and extends the primary, `status` warns at 60, 30 and 14 days for the binding and at 6 months, 3 months and 30 days for the primary, and `revocation make`, `revocation check` and `drill restore` work as for a root.

### The ceremony of `personal subkey add`

1. **Plan.** The card's serial and slot, the creation time of the subkey, the validity of the binding and the number of touches. The subkey is a birth, so the binding is a derived signature ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)).
2. **Confirm** by typing the first eight characters of the plan digest, as always.
3. **Reserve, and birth.** The attempt is written; the card makes the key on its OpenPGP applet and the back-signature, after the user PIN is verified at the terminal.
4. **Attest.** The card's attestation of the key is read with the maker's command (`80 FB 01 00` on a YubiKey) and checked against the bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions under `1.3.6.1.4.1.41482.5` is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The primary's key file is opened as [ADR 0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-directory/) says, and the primary binds the subkey. The fingerprint is shown first.
6. **Verify and record,** and write the certificate.

A lost card is answered with `ritueel personal subkey add` on a new card after the primary has revoked the old subkey (a subkey revocation, type `0x28`, made by the primary at that ceremony). No pre-made file is needed, because the primary is a file.

## Stage one: an adopted primary

A person who already has a primary, with years of certifications, may adopt it as it is, as a software key in a key file ([ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#stage-one)). This is the one stated exception to "nothing is imported".

- The key is marked `adopted` in its `root.json` ([the directory](/reference/directory/#rootjson)).
- It may be RSA-4096 and without expiry on arrival, so it is outside the P-384 profile above until it is replaced.
- It gets an expiry at adoption, and is replaced within three years of adoption, or moved to stage two.

The adoption command is fixed with the code ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Stage two: card-born primaries

Decided, not built; it depends on the root cards and their proofs (M1, M6). Two primaries are born, one on each root card, in the personal root's row ([ADR 0016](/decisions/0016-several-roots-share-one-pair-of-root-cards-and-the-directory-keeps-a-card-inventory/#the-rows)). One is published; the other is a standby that the published one certifies. The old key vouches for the published one, with an overlap, and then ends ([ADR 0009](/decisions/0009-root-transitions-vouch-overlap-retire-and-revoke/)).

## Retiring a subkey

A subkey that is replaced is retired by a revocation with the reason "superseded", dated on the day of the switch, or by expiry; "compromised" is for compromise only ([ADR 0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#retiring-a-subkey)). What the verifiers do with each was measured on 2026-11-10: [the research note](/research/openpgp-subkey-retirement-2026-11-10/).

## Follow-ups

- `init --kind personal`, `personal subkey add`, the adoption of a primary, the day-to-day subkeys and the encryption subkey with its wrapped backup, the output and the tests on a test card ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Stage two on the root cards, after the card proofs ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- The schema of `ritueel.yaml` for `kind` and `person`, and the vectors of the `openpgp-card` proof ([issue #18](https://github.com/truvity/ritueel/issues/18)).
