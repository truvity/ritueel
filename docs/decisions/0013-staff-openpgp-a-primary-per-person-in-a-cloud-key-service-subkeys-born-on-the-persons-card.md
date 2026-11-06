# 0013 — Staff OpenPGP: a primary per person in a cloud key service, subkeys born on the person's card

**Status:** Accepted
**Date:** 2026-11-06

## Context

[0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/) leaves company-wide OpenPGP to a record of its own, and [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) decides a person's own key: a primary in an offline file that the person holds, and subkeys born on the person's card. A company that wants its staff to sign commits and tags needs something else on top: a key that the company can recognise as its own, can stop trusting when the person leaves, and can attribute to one person on a hosting platform. This record decides that key. The tracking issue is [#103](https://github.com/truvity/ritueel/issues/103). The questions and the options were put to the maintainer, who decided on 2026-11-06:

> **G1 A:** "OpenPGP keys born on cards", with no SSH-signing fallback.
>
> **G2a A, Variant 2:** each person has one primary key, held by the company through ritueel. Subkeys are born on the person's card, never extractable. ritueel binds them under that primary after it checks the card attestation, with the person present. Joiner, mover and leaver are ritueel automation. The company root certifies each person's primary with a domain-scoped trust signature; sluis makes that signature online (O1 a, [sluis ADR 0024](https://github.com/truvity/sluis/blob/main/docs/decisions/0024-root-custody-and-the-signing-api.md)).
>
> **G2b A:** the per-person primary lives in AWS KMS. The maintainer said KMS supports Ed25519; the check is below, with P-384 (ECDSA) as the fallback.
>
> **G2c A:** start with the OpenPGP applet. Add per-purpose PIV keys once a `gpg.program` signer exists.
>
> **G4 A:** keys born on the card, with the attestation recorded in ritueel's ledger; PIN and Admin PIN changed at issue; a second card per person; cards shipped through Yubico Delivery; touch policy decided per key.
>
> **G5 A**, for a leaver: remove them from the org and delete their keys from their GitHub account (sluis's App does this); let the sluis certification lapse and drop the key from the staff keyring; revoke only on compromise.
>
> **C1:** the maintainer migrates their own key (a software primary with imported subkeys) through ritueel's flow: "Ritueel will help me rotate master keys; after that we continue as we agree".
>
> **GH1 A, GH3 A:** sluis's GitHub App syncs only the company-issued keys to each person's own GitHub account. ritueel produces the keyring; sluis syncs it.

The check that G2b asks for, read on 2026-11-06 (the details and sources are on [the reference page](/reference/staff-openpgp/#the-primary-in-aws-kms)): AWS KMS has a key spec `ECC_NIST_EDWARDS25519` with the signing algorithm `ED25519_SHA_512`, which is pure Ed25519 and takes a raw message of up to 4096 bytes. OpenPGP version 4 signs a hash of the data, and RFC 9580 (section 12.7) says that this hash is fed as the message to PureEdDSA. A 48- or 64-byte digest sent to KMS as a raw message is therefore exactly what an EdDSA (legacy, algorithm 22) signature needs. This is documented and has not been run; a conformance test comes before the first key is made (see Follow-ups).

## Decision

### Staff keys and personal keys are two flows

A **staff key** is an OpenPGP key that the company issues to a member of staff, for the staff address, under the rules below. A **personal key** is a person's own ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)). **The personal flow stays for personal keys, unchanged:** a person's own primary is theirs, in their file, and ritueel does not hold it. A person may have both. Only a staff key is synced to the person's hosting account by the company, and only a staff key is certified by the company.

### One primary per person, held by the company in a cloud key service

- **Each person has one primary,** certify-only, version 4, **Ed25519 (EdDSA legacy, algorithm 22)**, born in an AWS KMS key of the spec `ECC_NIST_EDWARDS25519`. The company holds it through ritueel. If the conformance test shows that a verifier people use refuses it, the primary is **ECDSA on P-384**, the profile of [0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/) and the [contract](/reference/hand-off-contract/#keys-and-hashes), and nothing else in this record changes. The fallback is decided here; the test chooses between two decided profiles.
- **Who can use the key.** Only ritueel's ceremony role may `Sign`, only with multi-factor authentication, only with `ED25519_SHA_512` on a raw message. The admin role creates, tags, disables and re-enables the key and can never sign; no other principal can sign; there is no renewal role. The key sits in an account of the operator's that is not the root account, because the root account holds roots only ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/)). The key policy and the checks are on [the reference page](/reference/staff-openpgp/#the-key-policy); they follow [the cloud root](/reference/kms-root/) with the changes the page lists.
- **A staff primary is not a root.** It anchors one person, and nothing else is rooted in it. Its evidence is the kind the `aws-kms` store always gives ([0003](/decisions/0003-key-stores-and-the-card-layer/#what-a-store-can-prove-decides-what-it-may-hold)): the key, its policy and its audit trail, read from the service.
- **The user ID** is the person's name and staff address, made at the ceremony that creates the key. The primary is in KMS and can sign again, so a further address (for example the one a hosting platform verifies) is a later ceremony, not a lost chance.
- **Expiry.** The primary is valid about 36 months and is extended at each yearly re-binding while the person is on staff. A key in a cloud service cannot be copied, so it is replaced on an event, not by calendar ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/#how-long-a-persons-primary-lives)): an advisory about the service or the algorithm, a compromise, or the person's leaving. A leaver's primary is simply not extended.
- **There is no replica and no escrow.** Losing a staff primary costs one person a new primary and a new certification, the joiner flow again, not an identity others rely on as they do on a root.

### Subkeys are born on the person's card and bound after a check, with the person present

- **Two subkeys per card, a signing and an authentication subkey,** are born on the OpenPGP applet of the person's card, as in 0012, and never leave it. The card is a YubiKey; a token that cannot attest is not a staff card (G1: the key is born on the card, and the proof is the card's attestation). **There is no encryption subkey and no SSH-signing fallback.**
- **Two cards per person,** each with its own subkeys, both bound under the primary at the joiner ceremony. The second card is kept in a second place; a lost card is answered by revoking its subkeys and ordering a new card, and the person is never without a signing key.
- **ritueel binds a subkey only after it has checked the card.** The card's attestation chain verifies against the maker's pinned bundle; the card's serial is the one the operator registered for this person when the card was issued; the subkey's back-signature verifies; the card meets the firmware floor. The attestation is recorded in the ledger. The binding is the [hand-off contract's](/reference/hand-off-contract/#openpgp-subkey) OpenPGP subkey exchange, with the person's card as requester and the person's one primary as the certifier's one primary ([the same rule as for a personal directory](/reference/personal-openpgp/)).
- **The person is present.** The card's PIN is verified, and its touch given, by the person; the person reads the plan (their name, the card's serial, the subkey fingerprints) and types its digest ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/)). A binding never runs without them, and ritueel never runs one unattended.
- **Binding lasts about 13 months** and is re-signed at a **yearly ceremony in a batch**: one plan lists every active person's bindings, one confirmation, one multi-factor session. A re-binding creates no key, so no card is needed; it still runs under the ceremony role, and there is no unattended renewal for staff keys (see the risk below).
- **PINs and touch.** The PIN and the Admin PIN are changed at issue, typed at the terminal and never stored by ritueel; the person keeps them in their password manager. The touch policy is decided per key and written in the plan, not fixed by ritueel.
- **Cards ship through Yubico Delivery.** ritueel does not order, ship or reset cards for anyone; the operator registers a card's serial for a person when it is issued.

### The flows

Who does each step: **ritueel** (a command the operator and the person run), **sluis** (the system that holds intermediates, outside this repository), or the **operator** (the company's own process, which ritueel only records). ritueel never reaches a hosting platform.

**Joiner**

| # | Step | Who |
|---|---|---|
| 1 | The operator orders two cards through Yubico Delivery and registers their serials against the person's name and address. | operator, ritueel (records) |
| 2 | The person prepares each card: firmware floor checked, PIN and Admin PIN changed, touch policy set per key. | ritueel |
| 3 | The primary is born in KMS and its user ID is made; the key is tagged with the person's handle. | ritueel |
| 4 | With the person present, each card makes a signing and an authentication subkey; the attestation is read, checked and recorded; the primary binds the four subkeys. | ritueel |
| 5 | The person's certificate is added to the staff keyring, which is rebuilt. | ritueel |
| 6 | sluis, having authenticated the person against the company's directory, certifies the primary for the staff address with an expiry. | sluis |
| 7 | The person authorises sluis's GitHub App once; the App adds the fingerprints of the company-issued keys in the keyring to the person's own account. | person, sluis |

**Mover** (a change of name or address; a change of team changes no key)

| # | Step | Who |
|---|---|---|
| 1 | The operator records the change. | operator, ritueel (records) |
| 2 | The primary certifies the new user ID and revokes the old one. No subkey is made, so the person need not be present; the operator confirms the plan, which names the change. | ritueel |
| 3 | The staff keyring is rebuilt. | ritueel |
| 4 | sluis certifies the new address and lets the old certification lapse, then syncs the keyring. | sluis |

**Lost or replaced card.** The person's other card keeps working. With the person present, ritueel revokes the lost card's subkeys (soft if the card is merely retired, hard if it was stolen) and binds the subkeys of a new card as in the joiner flow, then rebuilds the keyring; sluis syncs it.

**Leaver**

| # | Step | Who |
|---|---|---|
| 1 | The operator marks the person as left in the ledger. ritueel stops re-binding them and disables their KMS key, so nothing can be bound under it again. It is not deleted. | operator, ritueel |
| 2 | The person is removed from the organisation and their keys are deleted from their hosting account. | sluis (its App), operator |
| 3 | sluis stops certifying the primary, and the certification lapses at its expiry. | sluis |
| 4 | The key is dropped from the staff keyring; its certificate stays in the ledger's archive. The keyring is rebuilt and published. | ritueel |
| 5 | **No revocation.** Old commits stay verified on the hosting platform by design. The key is revoked only on a compromise, with the revocation signatures made at birth ([revocation material](/reference/revocation-material/)); a hard revocation drops the key from the keyring ([0006](/decisions/0006-release-keys-and-the-keyring-package/#revocation)). | ritueel |

### The staff keyring

ritueel builds the **staff keyring** with the same builder and the same package layout as the release keyring ([0006](/decisions/0006-release-keys-and-the-keyring-package/#the-keyring-package), [the reference](/reference/keyring-package/)): one complete public certificate for every active person, with the user ID, the subkeys ever bound and their bindings, and soft revocations. It carries no certification by sluis, which ritueel does not make. The release keyring and the staff keyring are two packages and are never mixed: a person's key is not a release key. ritueel does not sign or publish the package; the operator's pipeline does. **sluis consumes it** to sync keys to the hosting accounts, and should add only a subkey whose binding verifies under a primary that sluis itself certified.

### The company root and sluis

The company root certifies each person's primary with a domain-scoped trust signature. The root stays offline: at a ritueel ceremony it delegates, by a trust signature limited to the company's domain, to a certification key that sluis holds; **sluis makes the per-person certification online, with an expiry,** and stops when the person leaves ([O1 a](https://github.com/truvity/sluis/blob/main/docs/decisions/0024-root-custody-and-the-signing-api.md)). The delegation waits for the real roots and the adoption drill ([#48](https://github.com/truvity/ritueel/issues/48)); a staff primary can exist before it, uncertified.

### The security risk, and its mitigations

**The risk.** Whoever controls the primary can bind a subkey they hold, and that subkey signs as the person: commits that verify as them, and a key the company's own sync would then publish. It is the staff form of the limit [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit) accepts for a root, but spread over many identities that each have less to lose.

**Mitigations,** each a rule that the reference page makes checkable:

1. **Narrow use of the key.** Ceremony role only, multi-factor authentication, a fixed algorithm and message type; the admin role cannot sign; no renewal role, because an unattended principal that can sign could bind anything. ritueel reads the policy at every ceremony and refuses one that has another signer.
2. **A binding needs the right card.** The attestation must chain to the maker, the serial must be the one registered to this person, and the person must be present. An attacker needs the ceremony role, the multi-factor device and a card the operator registered, or the operator's records.
3. **Every signature is accounted for.** ritueel compares the key's audit trail with the ledger: a `Sign` with no ledger entry is an incident. The operator keeps an alarm on every `Sign`.
4. **Everything is bounded in time.** Bindings last about 13 months, sluis's certification has an expiry, and a leaver's key is disabled.
5. **Downstream does not trust the keyring blindly.** sluis syncs a subkey only under a primary it certified. A hosting platform cannot restrict signers to the company's keys; a check of commit signers against the staff keyring is a separate, later decision.
6. **Roles apart.** The guide advises that, where a company has two operators, one holds the admin role and the other the ceremony role. ritueel does not require it: a one-person company is a valid user ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit)).

**What stays.** An insider who holds the ceremony role and its multi-factor device, and an attested card registered to the person, can bind a subkey. It is visible afterwards, in the ledger, the audit trail and the keyring, but not prevented. This is the accepted limit, stated plainly in the teaching pages and not hidden.

### The maintainer's own key

The maintainer's current key, a software primary with subkeys imported into cards, is not a staff key: its subkeys were not born on a card and cannot be attested ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/), principle 1). The maintainer runs the joiner flow for themselves, as its first real use, and so rotates to a staff key. The old key is then retired from company use: removed from the hosting account by hand, kept as a personal key if wanted, revoked only on a compromise.

## Consequences

- A company gets keys it can attribute, certify and stop trusting, with no secret held outside a cloud key service or a card. A person's private key never exists outside the card that made it.
- ritueel grows a staff directory, `ritueel staff` commands for joiner, mover, leaver and card replacement, a `staff-primary` purpose for the `aws-kms` store, and a staff profile in the hand-off contract with test vectors for the Ed25519 primary. It also grows the batch yearly ceremony and the audit-trail comparison. [The reference page](/reference/staff-openpgp/) holds the details, marked not built.
- The primary of the contract was ECDSA on P-384 with SHA-384 because a KMS P-384 key signs only 48-byte digests. Ed25519 has no such limit, so the staff primary signs a 64-byte SHA-512 digest as a raw message; the contract names the profile before the first release.
- The company pays for one KMS key for each person, and a batch ceremony each year in which every person's binding is re-signed.
- A staff primary has no replica. A lost Region or a deleted key means a new joiner flow for that person.
- The personal flow is untouched. The guides must say which key is which, and when a person should have both.
- sluis owns the online certification and the hosting sync: two things outside this repository that this record depends on and does not specify. They are listed in the pull request that adds this record.
- A staff address that a person does not control on the hosting platform gives no verified commits there; verifying the address is the person's step on the platform, and the guide says so.

## Roads not taken

- **One company primary holding everyone's subkeys.** One key to certify and revoke, but a hosting platform ties a key to one account, so attribution to a person breaks; every employee's user ID would sit on one key; and revoking one person would churn the whole key for everyone.
- **An SSH-signing fallback for people without a card.** Easy to start, but it has no OpenPGP identity and nothing the company can certify, and two standards would have to be taught and checked; the maintainer ruled it out (G1).
- **The primary on the person's card.** No file or service to guard, but a card has no copy, so a lost card loses the identity, and the company could neither bind nor stop a key it does not hold.
- **The personal flow's shape for staff: a primary in an offline file, held by the company.** One flow for both, but a copyable file for every person is a copy to guard for each of them, where a cloud key cannot be copied at all.
- **The person holds the primary and the company only certifies it.** Least for the company to run, but a leaver walks away with the key, the card and the identity, and the company cannot bind or stop anything.
- **Subkeys made in software and imported into the card.** The usual practice, with a backup of the subkeys, but the key existed outside its store and cannot be attested, which principle 1 rules out; it is also the maintainer's own old key.
- **A P-384 primary from the start.** Matches the rest of the contract and needs no test, but the maintainer chose Ed25519; P-384 is kept as the decided fallback.
- **Unattended yearly re-binding under a renewal role.** No batch ceremony, but a role that can sign with no multi-factor authentication can bind any subkey, which is the risk this record is built around; a batch ceremony costs one confirmation a year.
- **Per-purpose PIV keys now.** A key for each use, but git cannot call them until a `gpg.program` signer exists; they are added then (G2c).
- **A replica for every staff primary.** Survives a lost Region, but costs a key and a policy to keep in step for each person, to protect an identity a joiner flow replaces.
- **Revoking a leaver's key.** Looks final, but the hosting platform never re-checks old commits, so it changes nothing there, and it would cost a hard revocation in every keyring; it is kept for a compromise.
- **ritueel syncs the keys to the hosting platform.** One fewer system, but ritueel is a command-line tool and not a network service ([0001](/decisions/0001-scope-roots-and-transitions-systems-like-sluis-hold-intermediates/)); sluis's App holds the account permission.
- **A second card made only after a loss.** Fewer cards to buy, but a lost card leaves the person unable to sign until a new one arrives and is bound.

## Follow-ups

- Build the staff directory, the `staff` commands, the `staff-primary` purpose of the `aws-kms` store and the batch yearly ceremony ([#103](https://github.com/truvity/ritueel/issues/103)).
- Run the Ed25519 conformance test: a signature by a KMS `ECC_NIST_EDWARDS25519` key over an OpenPGP version 4 hash, as a certificate, a binding and a revocation, accepted by `gpg`, `gpgv`, `sqv` and the hosting platform's key upload; it also settles the byte layout of the 64-byte raw signature in the two MPIs ([#103](https://github.com/truvity/ritueel/issues/103)).
- Add the staff profile (Ed25519 primary, SHA-512) to the hand-off contract and its test vectors ([#103](https://github.com/truvity/ritueel/issues/103)).
- Write the guides: joiner, mover, leaver, card replacement, and which key is which ([#103](https://github.com/truvity/ritueel/issues/103)).
- Measure the encoding of the OpenPGP applet's attestation extensions, then read PIN and touch policy from them ([#18](https://github.com/truvity/ritueel/issues/18)).
