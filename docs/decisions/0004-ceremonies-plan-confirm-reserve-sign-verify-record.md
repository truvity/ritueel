# 0004 — Ceremonies: plan, confirm, reserve, sign, verify, record

**Status:** Accepted
**Date:** 2026-11-11

## Context

[0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/) fixes who holds the roots; this record fixes how a person uses them. The proposal was [issue #27](https://github.com/truvity/ritueel/issues/27). Four facts shape it.

- **A root is used rarely, with a person present.** A mistake costs a year or a trust update, so the tool has to show what it will sign in a form the person can compare, and must not be confirmable by habit.
- **The machine is not trusted.** A card root and a real software root are used only in the offline system ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#where-a-plan-runs)) and a cloud root from the holder's workstation; a test root may run on the workstation or on a rehearsal card (below); neither machine can copy a key that never leaves its store, but either can lie about what is being signed.
- **A card forgives little.** Three wrong PINs block it. A missed touch comes back about 15 seconds later as a generic security status, not as a touch timeout (measured 2026-10-31, YubiKey 5, firmware 5.8.0).
- **The first consumer has no hardware.** It and its test harness need a software root that a script can drive, through the same commands.

## Decision

### Six steps, every ceremony

1. **Plan.** Read the bundle and the pending requests, and write a plan with every byte that will be signed fixed in advance: the root, each key's fingerprint and store, every serial number, validity and signature time, and the number of touches. Serials and times are drawn here, once. The plan holds public information only and needs no card.
2. **Confirm.** Show the plan in words and print its digest. The person types the first eight characters of the digest; a key press is not accepted. A script passes `--confirm DIGEST`, so it cannot confirm a plan it has not computed. A confirmation never replaces a touch.
3. **Reserve.** Before the first signature, write an *attempt* (plan digest, root, time). If the run stops after a signature, the attempt shows that signatures may exist and that its serials are used; `status` lists it until a person closes it.
4. **Sign.** Use the root, showing each fingerprint before its touch.
5. **Verify.** Check every artifact against its request and the plan, with code that did not sign it, before it is written out.
6. **Record.** Write the ceremony record and the transcript, then the trust products.

A command runs all six; `--plan-only` stops after the plan, and `ritueel run PLAN --confirm DIGEST` executes a saved plan after checking it still matches the bundle. `ritueel due` writes the plans for what is due. There is no `yearly` command: each renewal is a separate action in a plan. So a ceremony is one command, or two or three when someone reviews the plan first. The commands, flags and exit codes are in [the command reference](/reference/cli/).

### Refused before anything is written

A card whose serial is not registered or is the wrong one for the role; a fingerprint that differs from the plan or from the one the requester printed; a key that cannot be attested where the policy asks for attestation; a slot collision or a purpose with no slot; a card with fewer than three PIN tries left; a card that is not adopted, or that still has a default PIN, at `init` (the holder sets the PIN, and adoption replaces the PUK and the management key: [0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)); a request that fails a check of the [hand-off contract](/reference/hand-off-contract/). ritueel never retries a PIN, and reads one only from the terminal, without echo.

### The roots at `init`

`init` creates the bundle, the roots (two by default, both cards present), the revocation signature of each primary, and the first trust products. **It obtains, verifies and stores the attestation of each root key** (the slot certificates for a card, the description and policy for a KMS key) in the bundle and the record, and refuses a root that cannot be attested. It prints the accepted limit of [0002](/decisions/0002-key-custody-every-key-is-born-in-its-store-two-root-cards-or-one-kms-root-and-a-replica/#the-accepted-limit), and the record says it was shown.

### The bundle and the records

- **One bundle of plain files.** A bundle is the directory with a fixed structure that holds everything ritueel knows about one trust domain: configuration, the inventory of cards ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#the-inventory)), the roots' certificates and public keys with their attestations, digests of the revocation signatures, the trust products, the secrets of cards sealed to the holder's recipients ([0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#card-secrets)) and the wrapped backup of a person's encryption subkey ([0017](/decisions/0017-a-persons-openpgp-key-in-two-stages-an-adopted-primary-first-then-card-born-primaries/#day-to-day-cards)); everything else is public material. Never a private key in clear, a PIN the holder types, a passphrase or a revocation signature itself. The **ledger** is the write-once part of it: one sub-folder per ceremony, holding its plan, attempt, record, transcript and birth journal, each sub-folder naming the one before. ritueel needs no git; the holder is still advised to keep the bundle in version control and to back it up ([0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/#an-opinionated-bundle)). A sealed single-file form of the ledger is later.
- **One bundle is one trust domain.** A bundle has its own ledger and hash chain, trust sequence, root list and roots, labelled A and B and then the next letter. A holder with a personal key and a company keeps two bundles, and nothing of the person is in the company's files. A root across bundles is written with the bundle's name, `acme/A`; inside a bundle it is `A`. The bundle's name is the name of its directory (for example `personal/`, `acme/`); no file stores it, and `name` in `ritueel.yaml` stays the name in the roots' subjects. Two bundles may share a pair of root cards ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/)); the mechanics are in [the bundle reference](/reference/bundle/).
- **The trust file is always "the CA bundle" in full,** and the command is `ca-bundle build`. Every other bare use of "bundle" means the directory. This is the accepted cost of the word.
- **A record is a JSON file in the ceremony's sub-folder of the ledger,** with the time in UTC, the command, the plan digest, the keys and stores, the evidence checked, the policy applied, the artifacts with digests, the slot map version and the confirmation. No secret.
- **Records form a hash chain** that `records verify` checks, each sub-folder naming the one before it; they are not signed by a root. The digest of the last record goes into the next signed root list, which anchors the chain without another use of the root.
- **The transcript is what ritueel printed,** written by ritueel, never a capture of the terminal.

### Who signs, and when

- **The root of the year** signs: by default the root that did not sign the previous yearly ceremony, found in the records. `--root` overrides it, with a reason recorded.
- **The yearly ceremony is in month 12** of the intermediates' 13 months. `status` warns about an intermediate at 60, 30 and 14 days, and about a root at 6 months, 3 months and 30 days, with exit codes 10, 11 and 12 for notice, alert and critical. A healthy root always has about a year left, so a root warning means a missed extension, with time left to act.
- **The plan for the yearly renewals needs one request for every registered intermediate** and stops when one is missing, unless `--allow-missing NAME` is given to `due` and recorded.
- **Each ceremony that uses a card extends that card's root,** as one more planned, recorded signature.

### A missed touch

When the PIN was accepted in the same session and the card refused after 10 seconds or more, ritueel reports "the card refused after N seconds: no touch was given in time, or the PIN state was lost". A sooner refusal is reported as a refusal. It claims no more than it knows, and does not retry.

### Software roots and tests

Software mode runs the same commands and steps. Its root is a key file opened as [0015](/decisions/0015-key-files-open-with-a-passkey-on-each-root-card-and-card-secrets-are-sealed-in-the-bundle/#the-key-file) says, and `init`, every confirmation and every record say that a software root can be copied. A test root or a script uses a passphrase through `--passphrase-fd N`, and `--confirm DIGEST`. `--test-root` makes a root without a passphrase, marked `TEST ONLY` in its certificate name and in every record, and `ca-bundle build` and `keyring build` refuse to put a test root and a real root in one product. A test root may run its ceremonies on the workstation or on a rehearsal card; a real root never becomes a test root (`test` is set at birth); and the program checks nothing about the machine it runs on ([0016](/decisions/0016-several-bundles-share-one-pair-of-root-cards-and-the-bundle-keeps-a-card-inventory/#where-a-plan-runs)). A software root serves tests, drills, development and the first consumer's harness. A real software root is one that is not a test root, for example a person's own primary ([0012](/decisions/0012-personal-openpgp-the-primary-offline-in-a-file-the-daily-subkey-on-a-card/)); no software root ever anchors a signed release ([0006](/decisions/0006-release-keys-and-the-keyring-package/)). A test that needs hardware is tagged, skipped by default, and selects its card by serial.

### KMS roots and wizards

A KMS root follows the same steps; the confirmation is the typed digest plus a session of the ceremony role ([0013](/decisions/0013-the-kms-ceremony-role-is-the-only-signer-and-ritueel-asks-nothing-of-its-sign-in/)), through the caller's standard credential chain. The record holds the key ARN, the digest of the key policy and the role session. The guided mode ([#16](https://github.com/truvity/ritueel/issues/16)) only fills in flags and shows the plan, and the local page ([#17](https://github.com/truvity/ritueel/issues/17)) is a read-only view. The command line and the page call one API of one ritueel process, started on demand: the command line through a Unix socket, where the digest typed in the terminal arrives, and the page only through a listener on `127.0.0.1`, on a random port, with a per-session token, while the page is in use ([0011](/decisions/0011-the-wizards-one-engine-three-faces-and-a-web-page-that-cannot-confirm-anything/)).

## Consequences

- A ceremony is reviewable: the plan can be read, hashed and checked on another machine before a card is touched, and the same plan gives the same bytes.
- A crash after the first signature leaves a trace; closing it is a step a person must take.
- Plan and record are code that exists only for the ceremony, in return for one shape to test, teach and check.
- Typing a digest prefix costs a few seconds a year; the touches grow with the number of intermediates, and the plan prints the count.
- Losing the bundle loses the card inventory, the attestations and the creation times; the published trust products still hold the public keys.
- The pages say "bundle" for this directory and "the CA bundle" for the trust file, in full every time.
- A holder with two trust domains keeps and backs up two bundles.

## Roads not taken

- **One command with no plan step.** Simpler, but nothing to review before the touch and no trace of what a crash may have signed.
- **Confirm by pressing a key.** Fast, but pressed without reading, and a script could confirm a plan it never read.
- **Sign each record with the root.** A third party could check a record, but it is a third use of the root and one more touch.
- **Capture the terminal as the transcript.** Complete and free, but it can hold what was typed.
- **`init` creates one root at a time.** The second card can stay away, but the revocation material and the two-root list are made together, and a one-root state is the unsafe one.
- **A ceremony service.** Several people could share a web interface, but it is a network service that holds ceremony state and acts on roots.
- **Accept a root without attestation at `init`.** Faster adoption, but nothing would then show that the root was born on its card.
- **Keep the word directory.** No rename, but the key directory, the revocation directory and the working directory are directories too, and a sentence cannot tell them apart.
- **Another word (dossier, vault, home, realm).** No clash with the CA bundle, but the maintainer chose bundle and accepted the cost of writing "the CA bundle" in full.
- **Several trust domains in one directory.** Cards stay in one inventory, but it needs a second layer between the directory and the root, renames A and B, and mixes a person's files with a company's.
- **The bundle name is the root name.** Shorter, but A and B are two keys that a host pins one by one, so `acme/A` names the root exactly.

## Follow-ups

None.
