# 0008 — The operator prepares the holder; ritueel creates, attests and verifies the root

**Status:** Accepted
**Date:** 2026-11-11

## Context

M4 puts the roots in a cloud root account and M6 on root cards. [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) fixes who holds a root, [0003](/decisions/0003-key-stores-and-the-card-layer/) the slot map and the stores, and [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) the six steps and the refusals. Four things are still open for the code of [issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12) and [issue #30](https://github.com/truvity/ritueel/issues/30):

- **What exists before `init`.** A card with its PIN changed and adopted by ritueel (its PUK and management key replaced), and a cloud account with its roles. Somebody has to make them, and the tool must not grow into an installer for either.
- **How a key's birth fits a plan.** The plan fixes every byte that will be signed, but the root certificate of a new key contains a public key that does not exist yet.
- **What a cloud root has to look like.** [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) says the evidence is the key's description and policy, and the contract wants one principal that may sign. Neither says what the policy is, who makes it, or what is read back.
- **What the bundle keeps** for a card and for a KMS key: the inventory of cards that [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) mentions and the attestation files.

## Decision

### The boundary

**The operator prepares the holder. ritueel creates the keys, attests them and verifies them.** A careful person could set a card's PIN with the maker's tool and prepare an account with their own infrastructure code; those steps need no secret that ritueel may hold, and they differ for every site. The steps where a key is born, a signature is made and a fact must be checked are the ritual, and ritueel carries them out. It creates no account and no role, and keeps no PIN that the holder types. At adoption it replaces the secrets it can generate (the management key and the PUK, and on a day-to-day card the Admin PIN of the OpenPGP application) with random ones and seals them in the bundle ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)); the mission test still holds ([mission test 2](/contributing/design/#the-mission-is-the-test)).

### Root cards

- **The holder sets each card's PIN with the maker's tool** before adoption ([Prepare a root card](/guides/prepare-a-root-card/)); ritueel's adoption of the card then replaces the PUK and the management key ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)). The PIN goes in the holder's password manager, as before ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-yearly-ceremony)).
- **The management key is a random key that needs a touch to use, sealed in the bundle, and nothing else is accepted** for a root card. A thief with the card and its PIN can no longer replace a root key.
- **ritueel reads, and refuses.** It reads from the card whether the PIN, the PUK and the management key are still the factory values and refuses if so, because the order is: the holder sets the PIN, adoption replaces the PUK and the management key, then `init`; it never guesses a PIN to find out. A card that cannot report it is refused, not assumed fine.
- **The inventory is the card's identity** in the bundle ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-inventory)): it lists the card by name and serial and maps every slot to its use, ritueel writes it from a read-only check, a card may hold several roots, each by its row, and a serial is never reused for another holder's role. The checks and the files are in [the root cards reference](/reference/cards/).
- **The maker's attestation bundle** is shipped in the repository with its refresh step, as [0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) decided. A card whose intermediate is missing is refused until the attestation bundle is refreshed; the holder may supply the missing intermediate with `--extra-intermediates`, which is a helper only: it must chain to the pinned root.

### The cloud root

- **The operator provides the dedicated account, an admin role and a ceremony role.** The admin role creates and reads, and can never sign; the reference key policy lets only a break-glass principal, which the operator also provides, replicate a key or move its primary Region ([0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#the-reference-key-policy)). The ceremony role may `Sign` digests, and is the only principal that may sign anything new; ritueel asks for no particular sign-in ([0013](/decisions/0013-the-kms-ceremony-role-is-the-only-signer-and-ritueel-asks-nothing-of-its-sign-in/)). Controls around them (an alarm on `Sign`, the audit trail) are the operator's and are taught, not checked ([Prepare the cloud root](/guides/prepare-the-cloud-root/)).
- **ritueel makes the keys, and the policy.** At `init` it creates the three keys of a root (the X.509 root, the OpenPGP primary and the break-glass SSH CA key) as multi-Region keys born in KMS, replicates each to the declared Region, and gives each key, and each replica, the one key policy that it renders from `ritueel.yaml` (the order of the first replica and the refusal of replicas is in [0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#the-reference-key-policy)). A key policy is not shared between the keys of a multi-Region set, so the replica's policy is checked on its own.
- **Or ritueel adopts an existing key** ([0018](/decisions/0018-a-cloud-root-may-be-an-existing-key-that-ritueel-adopts/#adopting-a-key)) and creates nothing; both ways leave the same checks, the same evidence files and the same records.
- **ritueel reads it all back, every time it signs.** The checks, with their reason codes, are in [The cloud root in AWS KMS](/reference/kms-root/#the-checks). A changed policy is shown in the plan and confirmed by the person; it is never silently accepted.
- **The confirmation is the typed plan digest plus the ceremony role's session,** as in [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards). ritueel holds no credential and checks no sign-in method; the person arrives with the session.

### Renewal of a cloud root under a policy

Later (M7): this section is decided and not built now.

- **A cloud root may be renewed without a person.** The operator may declare a **renewal policy** in `ritueel.yaml` and create a **renewal role**: a second `kms:Sign` principal on the X.509 root key and the OpenPGP primary, sign-only, assumable only by the operator's scheduler identity. The operator's scheduler runs `ritueel renew` under it; ritueel stays a command-line tool and holds no key and no credential.
- **The renewal role may sign only what the bundle already holds:** the same key, subject, constraints and profile for an intermediate, and the same content of the root list, the CA bundle, the SSH CA key list and the CRLs, and the root's own certificate and primary, each with a new validity. A byte that names a key, a name, a root or a constraint the bundle does not hold is refused. It can extend trust; it can never create it, and it never revokes. New keys, changes of the root set and revocations stay ceremonies; [Re-sign](/learn/re-sign/#what-may-run-unattended) has the table of which acts are which.
- **ritueel refuses any third `Sign` principal** on a root key, and a renewal role that the policy does not declare (`extra-sign-principal`). It reads the key policy back at every run, as at every ceremony. The policy, the checks and the codes are in [The cloud root in AWS KMS](/reference/kms-root/#renewal-under-a-policy).
- **A card root cannot be renewed this way:** its PIN and touch are physical. It has the yearly ceremony and the reminders of `status`.

### Births, and what a crash leaves

- **A key that is born in a ceremony is not in the plan.** The plan fixes everything else: the store, the card's serial and slot or the Region, the algorithm, the OpenPGP creation time, the serials, the validity and the number of touches. A signature that covers a new key (the root certificate, the primary's self-signature and revocation signatures, a vouching signature) is listed without `tbs_sha256`, marked as derived. The verify step checks each such artifact against the profile and the key that was actually born, with code that did not sign it, and the record carries the digests ([the plan](/reference/ceremony-record/#the-plan)).
- **The fingerprint is shown before each touch** ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony), step 4), so a new key is seen before any root signs for it.
- **The attempt is written before the first birth, not only before the first signature,** because a generated key overwrites a slot or creates a billable key. Each key is appended to a **birth journal** beside the attempt as soon as it exists: its store, serial or ARN, purpose and public key digest. If the run stops, `status` is critical as for any unresolved attempt, and `records close` prints the journal.
- **ritueel does not resume a birth and does not undo one.** A card key that was born and not recorded is removed by deleting that one slot ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#rules-for-a-shared-card); 5.7.4 is the firmware floor, and that deleting one slot works there is tried on a rehearsal card in M1); a KMS key is left for the operator to schedule for deletion with the admin role. ritueel never deletes a key.

## Consequences

- The tool stays small: no account management, no PIN of the holder's, and nothing to get wrong when a site's setup is unusual. The cost is that adoption starts with preparation steps in other tools (a card's PIN, an account's roles), which the guides walk through and `init` checks.
- Once built (M7), a cloud root under a renewal policy will not need a person in month 12. Its trust stops only if the scheduler is broken for a month and nobody reads the alerts.
- Once built (M7), the renewal role is a standing credential on the root keys. Misused, it keeps an intermediate that should have lapsed working until a person revokes it at a ceremony; it cannot add a key, a name or a root. Every use is a `Sign` call under its own principal in the audit trail.
- A KMS root's trust rests on the account's roles and on ritueel reading the policy every time. A role that the operator makes too wide is caught by the checks only where the policy says so; the roles' own permissions are the operator's to keep tight.
- The plan of a ceremony that makes keys is not byte-exact for the new keys: the person confirms where keys will be born and what profile they get, then sees the fingerprints before touching. This applies to the software roots of M2 as well, whose `init` makes keys too.
- A crash during `init` costs the holder a slot deletion (tried on a rehearsal card in M1) or a KMS deletion. That is the price of never resuming into a state ritueel cannot prove.
- The `piv` and `openpgp-card` stores need cgo and a PC/SC library. A build without cgo leaves them out and reports them as not built (exit code 2), so a consumer that uses software roots keeps a static binary ([issue #10](https://github.com/truvity/ritueel/issues/10) sets the build tag). Opening a key file with a passkey must work in that static build too; that is to be proven in M1 ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#decided-not-yet-proven)).

## Roads not taken

- **ritueel also sets the PIN.** One tool from box to root, but the holder must choose and type the PIN, and ritueel would have to hold it.
- **A typed or PIN-protected management key.** Nothing stored on the card (typed), or one secret fewer (PIN-protected), but a thief with the card and its PIN could replace a root key, or the holder has a second secret per card to keep and type; the random touch-protected key sealed in the bundle ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)) removes both.
- **A default management key left in place.** Nothing to prepare, but anyone with the card could replace a root key in its slot; refused outright.
- **ritueel creates the account and the roles.** One command for a cloud root, but it would need account-creating rights, differ for every organisation and become an infrastructure tool; a policy it cannot trust is worse than a role it did not make.
- **Verify the roles' permissions as well as the key policy.** A tighter check, but IAM policies, boundaries and organisation policies make it a guess; the key policy is what the service enforces for this key.
- **One key policy copied to the replica by the service.** Less to check, but a multi-Region set shares no policy, so the replica would carry the default one.
- **Generate the keys before the plan, so that every byte is fixed.** An exact plan, but the key would exist, and a slot be overwritten, before the person confirmed anything.
- **Resume a half-finished birth.** Saves a slot deletion, but needs state ritueel cannot verify on a card, and a resumed key was never seen by the person in a plan.
- **One `Sign` principal only, with the reminder automated.** No new path to the root keys, but the cloud root would still stop being renewed in month 13 when no person came, and a renewal whose every byte is fixed by the bundle and the clock gains nothing from a person.
- **KMS grants instead of a renewal role.** No change to the key policy, but a grant cannot limit what is signed any better and is less visible than a statement the checks read; root keys refuse grants.
- **A person-gated renewal role.** One more barrier, but a scheduler cannot answer it, so it would be the ceremony role again.
- **A second confirmation after each birth.** More caution, but the fingerprint before each touch already gives the person the chance to stop, and a second prompt is the key press habit that [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) refuses.

## Follow-ups

- Build the `piv` store, the card inventory and adoption, the checks, the attestation bundle and its test, and measure that the factory-value report spends no PIN try ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- Build the `aws-kms` store, the `aws_kms` block, the key policy and the checks, against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- The commands, the births, the birth journal and the card and KMS reason codes ([issue #30](https://github.com/truvity/ritueel/issues/30)).
- The build tag for the stores that need cgo ([issue #10](https://github.com/truvity/ritueel/issues/10)).
- Later (M7): `ritueel renew`, the renewal policy and its checks ([issue #12](https://github.com/truvity/ritueel/issues/12), [issue #30](https://github.com/truvity/ritueel/issues/30)).
