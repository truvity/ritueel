---
title: Personal OpenPGP
description: The personal bundle and its ritueel.yaml, what differs from a company bundle, the profiles of the primary and daily subkey, and the two commands.
sidebar:
  order: 15
---

*Not built yet. This is the page that [record 0008](../decisions/0008-a-persons-own-key.md) leaves for the details, and that record is `Accepted`. It decides the profile, how long a person's primary lives, the two stages of the key, the day-to-day subkeys and how a subkey is retired. The [hand-off contract](/reference/hand-off-contract/#openpgp-subkey) carries the signing and the authentication capability, with their test vectors. The code is [issue #18](https://github.com/truvity/ritueel/issues/18): stage one is M3, and stage two is M6. How to use the result is in [Sign git commits and tags](/guides/openpgp-sign-git/) and [Your own OpenPGP key](/guides/personal-openpgp/). The commands, words and file names on this page are from before the decisions of 2026-11-12; the design is at https://ritueel.id/design/.*

There is no key the company issues to staff: every person uses OpenPGP as their own key ([record 0008](../decisions/0008-a-persons-own-key.md)). A person's own OpenPGP key is the same ritual as a service's subkey: a key is made in a store and bound under a primary. Here the primary is the person's, offline in a key file, and the subkeys are born on the person's cards. ritueel runs it with the engine of the company case, with the X.509 half switched off.

## The bundle

A person's own key is one trust domain, so it has a bundle of its own. A person who also runs a company keeps the personal bundle apart from the company's, and the same pair of root cards may serve both ([record 0003](../decisions/0003-root-cards.md)).

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

`kind: personal` replaces `name` and `release_address` with `person` (a name of 1 to 64 characters and an address) and is otherwise [the same file](/reference/bundle/#ritueelyaml). It is additive: a file without `kind` is a company bundle, as before.

| Part | In a company bundle | In a personal bundle |
|---|---|---|
| Roots | `A` and `B` (two cards), or one cloud root. | One root, `A`, with an OpenPGP primary and no X.509 key. |
| `root.json` | Has `x509_spki_sha256`. | Has no X.509 member. |
| Trust files | Root list, CA bundle, CRLs, SSH CA key list, keyring package. | The person's public certificate, `trust/<number>/<fingerprint>.pgp` and `.asc`. |
| Hand-off check 3 | The primaries equal those on the root list. | They equal the bundle's one primary ([the contract](/reference/hand-off-contract/#what-the-certifier-checks-1)). |
| Target of the root set | 2 or 1. | 1; `status` raises no `root-set` finding for it. |
| `root add`, `retire`, `revoke` | [As the transitions page says](/reference/transitions/). | The same, with the OpenPGP half only: no cross-certificate. |
| The software root | A test root only for a company. | The real primary, in the encrypted file backend ([the software store](/reference/software-store/)). |

## The profiles

The primary is the profile of [the OpenPGP primary](/reference/bundle/#the-openpgp-primary) with two changes: its one user ID is `<name> <address>` of the person, and it is made in the `software` store with the encrypted file backend, whose key file is `A.openpgp.key.age` in the key directory, opened as [record 0002](../decisions/0002-where-a-key-lives.md) says. It is valid 36 months and extended at each use. In stage one an existing primary may be adopted instead ([below](/reference/personal-openpgp/#stage-one-an-adopted-primary)).

The two subkeys are the subkeys of [the contract](/reference/hand-off-contract/#openpgp-subkey): ECDSA P-384, version 4, a back-signature made by the subkey, a binding of about 13 months. The signing subkey (`daily` above) has key flags `0x02`; the authentication subkey (`ssh` above) has `0x20` and serves SSH through `gpg-agent` ([the guide](/guides/openpgp-ssh-authentication/)). One set of signing and authentication subkeys is born on each day-to-day card.

The encryption subkey is the exception: it is made in software, loaded onto each day-to-day card, and has a wrapped backup in the bundle, so that a lost card does not lose the mail it decrypted ([record 0008](../decisions/0008-a-persons-own-key.md)). The personal ceremony itself makes it and the primary binds it; it is not a capability of the hand-off contract. The wrapped backup's format and the command are fixed with stage one ([issue #18](https://github.com/truvity/ritueel/issues/18)). The touch setting of each key is the holder's choice, and [the guide](/guides/personal-openpgp/) says what each choice costs.

## The commands

| Command | Does | Needs a person |
|---|---|---|
| `ritueel init --kind personal --store software --backend file --key-dir DIR --revocation-dir DIR` | Makes the bundle, the primary and its revocation signatures ([revocation material](/reference/revocation-material/)), and the first certificate. | Yes |
| `ritueel personal subkey add NAME --card SERIAL` | One ceremony: the card makes the subkey of the entry `NAME`, with its capability, and its back-signature, the primary binds it, and the certificate is rebuilt. It writes the request and the proof into `requests/` like any requester, then answers them. | Yes |
| `ritueel personal userid change` | Proposed; the name is not decided. One ceremony: the primary certifies the new user ID and makes it primary, and the old user ID gets a revocation that says it is no longer valid (record 0008, rule 17). The fingerprint and all trust stay. The certificate is rebuilt. | Yes |

Everything else is planned: the renewal plan (`ritueel due`, then `ritueel run PLAN`) renews the binding and extends the primary, `status` warns at 60, 30 and 14 days for the binding and at 6 months, 3 months and 30 days for the primary, and `revocation make`, `revocation check` and `drill restore` work as for a root.

### The ceremony of `personal subkey add`

1. **Plan.** The card's serial and slot, the creation time of the subkey, the validity of the binding and the number of touches. The subkey is a birth, so the binding is a derived signature ([record 0005](../decisions/0005-a-ceremony-and-where-it-runs.md)).
2. **Confirm** by typing the first eight characters of the plan digest, as always.
3. **Reserve, and birth.** The attempt is written; the card makes the key on its OpenPGP applet and the back-signature, after the user PIN is verified at the terminal.
4. **Attest.** The card's attestation of the key is read with the maker's command (`80 FB 01 00` on a YubiKey) and checked against the attestation bundle ([cards](/reference/cards/#the-attestation-bundle)). Until the encoding of the extensions under `1.3.6.1.4.1.41482.5` is measured, the key is recorded as attested and no PIN or touch policy is enforced from it.
5. **Sign.** The primary's key file is opened as [record 0002](../decisions/0002-where-a-key-lives.md) says, and the primary binds the subkey. The fingerprint is shown first.
6. **Verify and record,** and write the certificate.

A lost card is answered with `ritueel personal subkey add` on a new card after the primary has revoked the old subkey (a subkey revocation, type `0x28`, made by the primary at that ceremony). No pre-made file is needed, because the primary is a file.

## Stage one: an adopted primary

A person who already has a primary, with years of certifications, may adopt it as it is, as a software key in a key file ([record 0008](../decisions/0008-a-persons-own-key.md)). This is the one stated exception to "nothing is imported".

- The key is marked `adopted` in its `root.json` ([the bundle](/reference/bundle/#rootjson)).
- It may be RSA-4096 and without expiry on arrival, so it is outside the P-384 profile above until it is replaced.
- It gets an expiry at adoption, and is replaced within three years of adoption, or moved to stage two.

The adoption command is fixed with the code ([issue #18](https://github.com/truvity/ritueel/issues/18)).

## Stage two: card-born primaries

Decided, not built; it depends on the root cards and their proofs (M1, M6). Card-born primaries come after adoption ([record 0008](../decisions/0008-a-persons-own-key.md)).

:::note[Proposed]
The layout is awaiting the maintainer. Two primaries are born, one on each root card, in the personal bundle's row ([record 0003](../decisions/0003-root-cards.md)). One is published; the other is a standby that the published one certifies. The old key vouches for the published one, with an overlap, and then ends ([record 0007](../decisions/0007-changing-and-losing-a-root.md)). Record 0008 names the standby primary only as the answer to a card that has no backup, and fixes no layout. Record 0008 lists the layout under Not yet proven or only proposed.
:::

## Retiring a subkey

A subkey that is replaced is retired by a revocation with the reason "superseded", dated on the day of the switch, or by expiry; "compromised" is for compromise only ([record 0008](../decisions/0008-a-persons-own-key.md)). What the verifiers do with each was measured on 2026-11-10: [the research note](/research/openpgp-subkey-retirement-2026-11-10/).

## Changing a name or address

Adding and retiring a user ID of an OpenPGP primary is a ceremony like any other: a new self-certification by the primary, and the old user ID gets a revocation that says it is no longer valid, not compromised. The fingerprint and all trust stay, which a new key for a new address would lose. It is offered in the command line and in the page (Make a plan), and for a person's own key it is part of M3 ([record 0008](../decisions/0008-a-persons-own-key.md), rule 17). A published copy of the old user ID cannot be withdrawn; the revocation is what servers and hosts can show. After the ceremony ritueel prints the next steps; the guide is [After a ceremony](/guides/after-a-ceremony/).

## Follow-ups

- `init --kind personal`, `personal subkey add`, the adoption of a primary, the day-to-day subkeys and the encryption subkey with its wrapped backup, the output and the tests on a rehearsal card ([issue #18](https://github.com/truvity/ritueel/issues/18)).
- Stage two on the root cards, after the card proofs ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- The schema of `ritueel.yaml` for `kind` and `person`, and the vectors of the `openpgp-card` proof ([issue #18](https://github.com/truvity/ritueel/issues/18)).
