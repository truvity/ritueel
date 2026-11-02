# 0008 — The operator prepares the holder; ritueel creates, attests and verifies the root

**Status:** Accepted
**Date:** 2026-11-02

## Context

M2 puts the roots on two cards or in a cloud root account. [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) fixes who holds a root, [0003](/decisions/0003-key-stores-and-the-card-layer/) the slot map and the stores, and [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) the six steps and the refusals. Four things are still open for the code of [issue #11](https://github.com/truvity/ritueel/issues/11), [issue #12](https://github.com/truvity/ritueel/issues/12) and [issue #30](https://github.com/truvity/ritueel/issues/30):

- **What exists before `init`.** A card with its PIN, PUK and management key changed, and a cloud account with its roles. Somebody has to make them, and the tool must not grow into an installer for either.
- **How a key's birth fits a plan.** The plan fixes every byte that will be signed, but the root certificate of a new key contains a public key that does not exist yet.
- **What a cloud root has to look like.** [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) says the evidence is the key's description and policy, and the contract wants one principal that may sign. Neither says what the policy is, who makes it, or what is read back.
- **What the directory keeps** for a card and for a KMS key: the registry that [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) mentions and the attestation files.

## Decision

### The boundary

**The operator prepares the holder. ritueel creates the keys, attests them and verifies them.** A careful person could prepare a card with the maker's tool and an account with their own infrastructure code; those steps need no secret that ritueel may hold, and they differ for every site. The steps where a key is born, a signature is made and a fact must be checked are the ritual, and ritueel carries them out. It changes no PIN, creates no account and no role, and keeps no secret ([mission test 2](/contributing/design/#the-mission-is-the-test)).

### Root cards

- **The holder prepares each card with the maker's tool** before `init`: a new PIN, a new PUK, and a new management key that the card stores protected by the PIN ([Prepare a root card](/guides/prepare-a-root-card/)). The PINs and PUKs go in the holder's password manager, as before ([0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-yearly-ceremony)).
- **The management key is PIN-protected, and nothing else is accepted** in the first version. It is one secret fewer for the holder to keep, and it adds nothing to what a thief with the card and the PIN can do: a replaced root key is not the pinned one. A card with a typed management key is refused with a message that names the maker's command; a typed mode arrives with a holder who needs it.
- **ritueel reads, and refuses.** It reads from the card whether the PIN, the PUK and the management key are still the factory values and refuses if so; it never guesses a PIN to find out. A card that cannot report it is refused, not assumed fine.
- **The registry is the card's identity** in the directory: `cards.yaml` binds a serial to a root, is written by the ceremony that first uses the card, and a serial is never reused for another role. The checks and the files are in [Root cards, the registry and the attestation bundle](/reference/cards/).
- **The maker's attestation bundle** is shipped in the repository with its refresh step, as [0003](/decisions/0003-key-stores-and-the-card-layer/#the-piv-store-and-the-root-cards) decided. A card whose intermediate is missing is refused until the bundle is refreshed; the holder may supply the missing intermediate with `--extra-intermediates`, which is a helper only: it must chain to the pinned root.

### The cloud root

- **The operator provides the dedicated account, an admin role and a ceremony role.** The admin role creates, replicates and reads, and can never sign. The ceremony role may `Sign`, only with multi-factor authentication, and is the only principal that may sign anything new. Controls around them (an organisation policy, an alarm on `Sign`) are the operator's and are taught, not checked ([Prepare the cloud root](/guides/prepare-the-cloud-root/)).
- **ritueel makes the keys, and the policy.** At `init` it creates the three keys of a root (the X.509 root, the OpenPGP primary and the break-glass SSH CA key) as multi-Region keys born in KMS, replicates each to the declared Region, and gives each key, and each replica, the one key policy that it renders from `ritueel.yaml`. A key policy is not shared between the keys of a multi-Region set, so the replica's policy is checked on its own.
- **ritueel reads it all back, every time it signs.** The checks, with their reason codes, are in [The cloud root in AWS KMS](/reference/kms-root/#the-checks). A changed policy is shown in the plan and confirmed by the person; it is never silently accepted.
- **The confirmation is the typed plan digest plus the ceremony role's session,** as in [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#kms-roots-and-wizards). The multi-factor code is typed at the terminal and never stored.

### Renewal of a cloud root under a policy

- **A cloud root may be renewed without a person.** The operator may declare a **renewal policy** in `ritueel.yaml` and create a **renewal role**: a second `kms:Sign` principal on the X.509 root key and the OpenPGP primary, sign-only, with no multi-factor authentication, assumable only by the operator's scheduler identity. The operator's scheduler runs `ritueel renew` under it; ritueel stays a command-line tool and holds no key and no credential.
- **The renewal role may sign only what the ledger already holds:** the same key, subject, constraints and profile for an intermediate, and the same content of the root list, the CA bundle, the SSH CA key list and the CRLs, and the root's own certificate and primary, each with a new validity. A byte that names a key, a name, a root or a constraint the ledger does not hold is refused. It can extend trust; it can never create it, and it never revokes. New keys, changes of the root set and revocations stay ceremonies; [Re-sign](/learn/re-sign/#what-may-run-unattended) has the table of which acts are which.
- **ritueel refuses any third `Sign` principal** on a root key, and a renewal role that the policy does not declare (`extra-sign-principal`). It reads the key policy back at every run, as at every ceremony. The policy, the checks and the codes are in [The cloud root in AWS KMS](/reference/kms-root/#renewal-under-a-policy).
- **A card root cannot be renewed this way:** its PIN and touch are physical. It has the yearly ceremony and the reminders of `status`.

### Births, and what a crash leaves

- **A key that is born in a ceremony is not in the plan.** The plan fixes everything else: the store, the card's serial and slot or the Region, the algorithm, the OpenPGP creation time, the serials, the validity and the number of touches. A signature that covers a new key (the root certificate, the primary's self-signature and revocation signatures, a vouching signature) is listed without `tbs_sha256`, marked as derived. The verify step checks each such artifact against the profile and the key that was actually born, with code that did not sign it, and the record carries the digests ([the plan](/reference/ceremony-record/#the-plan)).
- **The fingerprint is shown before each touch** ([0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/#six-steps-every-ceremony), step 4), so a new key is seen before any root signs for it.
- **The attempt is written before the first birth, not only before the first signature,** because a generated key overwrites a slot or creates a billable key. Each key is appended to a **birth journal** beside the attempt as soon as it exists: its store, serial or ARN, purpose and public key digest. If the run stops, `status` is critical as for any unresolved attempt, and `records close` prints the journal.
- **ritueel does not resume a birth and does not undo one.** A card key that was born and not recorded is abandoned by resetting the card with the maker's tool, which the holder does; a KMS key is left for the operator to schedule for deletion with the admin role. ritueel never deletes a key.

## Consequences

- The tool stays small: no account or PIN management, and nothing to get wrong when a site's setup is unusual. The cost is that adoption starts with two preparation steps in other tools, which the guides walk through and `init` checks.
- A cloud root under a renewal policy no longer needs a person in month 12. Its trust stops only if the scheduler is broken for a month and nobody reads the alerts.
- The renewal role is a standing credential on the root keys. Misused, it keeps an intermediate that should have lapsed working until a person revokes it at a ceremony; it cannot add a key, a name or a root. Every use is a `Sign` call under its own principal in the audit trail.
- A KMS root's trust rests on the account's roles and on ritueel reading the policy every time. A role that the operator makes too wide is caught by the checks only where the policy says so; the roles' own permissions are the operator's to keep tight.
- The plan of a ceremony that makes keys is not byte-exact for the new keys: the person confirms where keys will be born and what profile they get, then sees the fingerprints before touching. This applies to the software roots of M1 as well, whose `init` makes keys too.
- A crash during `init` costs the holder a card reset or a KMS deletion. That is the price of never resuming into a state ritueel cannot prove.
- The `piv` and `openpgp-card` stores need cgo and a PC/SC library. A build without cgo leaves them out and reports them as not built (exit code 2), so a consumer that uses software roots keeps a static binary ([issue #10](https://github.com/truvity/ritueel/issues/10) sets the build tag).

## Roads not taken

- **ritueel prepares the card (new PIN, PUK and management key).** One tool from box to root, but it would generate and show secrets it may not keep, hide a step the holder should understand, and duplicate the maker's tool.
- **A typed management key.** Nothing stored on the card, but a second secret per card to keep and type, for a protection that a thief with the card and PIN does not need to beat.
- **A default management key left in place.** Nothing to prepare, but anyone with the card could replace a root key in its slot; refused outright.
- **ritueel creates the account and the roles.** One command for a cloud root, but it would need account-creating rights, differ for every organisation and become an infrastructure tool; a policy it cannot trust is worse than a role it did not make.
- **Verify the roles' permissions as well as the key policy.** A tighter check, but IAM policies, boundaries and organisation policies make it a guess; the key policy is what the service enforces for this key.
- **One key policy copied to the replica by the service.** Less to check, but a multi-Region set shares no policy, so the replica would carry the default one.
- **Generate the keys before the plan, so that every byte is fixed.** An exact plan, but the key would exist, and a slot be overwritten, before the person confirmed anything.
- **Resume a half-finished birth.** Saves a reset, but needs state ritueel cannot verify on a card, and a resumed key was never seen by the person in a plan.
- **One `Sign` principal only, with the reminder automated.** No new path to the root keys, but the cloud root would still stop being renewed in month 13 when no person came, and a renewal whose every byte is fixed by the ledger and the clock gains nothing from a person.
- **KMS grants instead of a renewal role.** No change to the key policy, but a grant cannot limit what is signed any better and is less visible than a statement the checks read; root keys refuse grants.
- **The renewal role with multi-factor authentication.** One more barrier, but a scheduler cannot answer it, so it would be the ceremony role again.
- **A second confirmation after each birth.** More caution, but the fingerprint before each touch already gives the person the chance to stop, and a second prompt is the key press habit that [0004](/decisions/0004-ceremonies-plan-confirm-reserve-sign-verify-record/) refuses.

## Follow-ups

- Build the `piv` store, the registry, the checks, the bundle and its test, and measure that the factory-value report spends no PIN try ([issue #11](https://github.com/truvity/ritueel/issues/11)).
- Build the `aws-kms` store, the `aws_kms` block, the key policy and the checks, against a test account ([issue #12](https://github.com/truvity/ritueel/issues/12)).
- The commands, the births, the birth journal and the card and KMS reason codes ([issue #30](https://github.com/truvity/ritueel/issues/30)).
- The build tag for the stores that need cgo ([issue #10](https://github.com/truvity/ritueel/issues/10)).
- `ritueel renew`, the renewal policy and its checks ([issue #12](https://github.com/truvity/ritueel/issues/12), [issue #30](https://github.com/truvity/ritueel/issues/30)).
