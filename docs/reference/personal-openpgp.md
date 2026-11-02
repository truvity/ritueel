---
title: Personal OpenPGP
description: The personal directory and its ritueel.yaml, what differs from a company directory, the profiles of the primary and daily subkey, and the two commands.
sidebar:
  order: 15
---

*Not built yet. This is the page that [ADR 0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) leaves for the details, and that record is still `Proposed`: two questions are open, and this page is the first version as the principles settle it. The code is [issue #18](https://github.com/truvity/ritueel/issues/18), in M4. How to use the result is in [Sign git commits and tags](/guides/openpgp-sign-git/) and [Your own OpenPGP key](/guides/personal-openpgp/).*

A person's OpenPGP key is the same ritual as a service's subkey: a key is made in a store and bound under a primary. Here the primary is the person's, offline in a file, and the subkey is born on the person's card. ritueel runs it with the engine of the company case, with the X.509 half switched off.

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

The primary is the profile of [the OpenPGP primary](/reference/directory/#the-openpgp-primary) with two changes: its one user ID is `<name> <address>` of the person, and it is made in the `software` store with the encrypted file backend, whose key file is `A.openpgp.key.age` in the key directory. It is valid 36 months and extended at each use.

The daily subkey is the signing subkey of [the contract](/reference/hand-off-contract/#openpgp-signing-subkey): ECDSA P-384, version 4, key flags `0x02`, a back-signature made by the subkey, a binding of about 13 months. Which other kinds a person may have is [an open question](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/).

## The commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init --kind personal --store software --backend file --key-dir DIR --revocation-dir DIR` | Makes the directory, the primary and its revocation signatures ([revocation material](/reference/revocation-material/)), and the first certificate. | Yes |
| `ritueel personal subkey add NAME --card SERIAL` | One ceremony: the card makes the subkey and its back-signature, the primary binds it, and the certificate is rebuilt. It writes the request and the proof into `requests/` like any requester, then answers them. | Yes |

Everything else is a command that exists already. `ritueel yearly` renews the binding and extends the primary, `status` warns at 60, 30 and 14 days for the binding and at 6 months, 3 months and 30 days for the primary, and `revocation make`, `revocation check` and `drill restore` work as for a root.

### The ceremony of `personal subkey add`

1. **Plan.** The card's serial and slot, the creation time of the subkey, the validity of the binding and the number of touches. The subkey is a birth, so the binding is a derived signature ([ADR 0008](/decisions/0008-the-operator-prepares-the-holder-and-ritueel-creates-attests-and-verifies-the-root/#births-and-what-a-crash-leaves)).
2. **Confirm** by typing the first eight characters of the plan digest, as always.
3. **Reserve, and birth.** The attempt is written; the card makes the key on its OpenPGP applet and the back-signature, after the user PIN is verified at the terminal.
4. **Attest.** The card's attestation of the key is read with the maker's command (`80 FB 01 00` on a YubiKey) and checked against the bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions under `1.3.6.1.4.1.41482.5` is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The passphrase of the primary is asked at the terminal, without echo, and the primary binds the subkey. The fingerprint is shown first.
6. **Verify and record,** and write the certificate.

A lost card is answered with `ritueel personal subkey add` on a new card after the primary has revoked the old subkey (a subkey revocation, type `0x28`, made by the primary at that ceremony). No pre-made file is needed, because the primary is a file.

## Follow-ups

- `init --kind personal`, `personal subkey add`, the output and the tests on a test card ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- The schema of `ritueel.yaml` for `kind` and `person`, and the vectors of the `openpgp-card` proof ([issue #18](https://github.com/truvity/ritueel/issues/18)).
