# 0005 — A ceremony has six steps; a key that cannot be copied may be used on the workstation

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. A ceremony is interactive, with a person present, and is one to three commands. Routine work is automated.
2. Every ceremony leaves a record: what was done, with which keys, on which store, what outsiders see, and where it ran (workstation or offline system). The format is the [ceremony record](/reference/ceremony-record/) page.
3. Every ceremony has six steps in this order: plan, confirm, reserve, sign, verify, record. The steps, the checks and the records are the same for every store.
4. Plan: ritueel reads the bundle and the pending requests and writes a plan with every byte to be signed fixed in advance: the root, each key's fingerprint and store, every serial, the validity and signature times, the numbers of signatures and touches. Serials and times are drawn once, here. The plan holds public information only, needs no card, can be made anywhere, and can be carried to the offline system as a saved plan file.
5. A key born in a ceremony is not in the plan; the plan fixes everything else. A signature that covers a new key is listed without `tbs_sha256`, marked derived, and verify checks it against the profile and the born key with code that did not sign it. So the plan is not byte-exact for new keys, software roots of the second milestone included.
6. Confirm: ritueel shows the plan in words with its digest, and the person types the first eight characters of it. A key press is not accepted. A script confirms with `--confirm DIGEST`, so it cannot confirm a plan it has not computed. A confirmation never replaces a touch.
7. Reserve: before the first key is born, not only before the first signature, ritueel writes an attempt (plan digest, root, time), and appends each key to a birth journal as soon as it exists. If a run stops, `status` shows the attempt as critical until a person closes it, and `records close` prints the journal. ritueel does not resume a birth and does not undo one.
8. Sign: the root is used and each fingerprint is shown before its touch, so a new key is seen before any root signs for it.
9. Verify: every artifact is checked against its request and the plan, with code that did not sign it, before it is written out. Record: the ceremony record and the transcript are written, then the trust files.
10. One command runs all six steps; `--plan-only` stops after the plan; `ritueel run PLAN --confirm DIGEST` executes a saved plan after checking that it still matches the bundle.
11. Renewals are separate actions (`root extend`, `subkey extend`, `intermediate renew`, `crl renew`, `root-list sign`); there is no "yearly" command. `ritueel due` writes the plans for what is due, all of it into one ceremony. A plan is like the confirmation step of a bank transfer: the fixed order ritueel executes, not a script.
12. Nothing happens without the user's confirmation, and the PIN and the touch stay on the card.
13. ritueel verifies where an intermediate key lives, signs an intermediate's PKCS#10 request into an intermediate CA certificate, and binds an OpenPGP subkey after checking the back-signatures.
14. ritueel refuses, before anything is written: a card whose serial is not registered or is wrong for the role; a fingerprint that differs from the plan or from the one the requester printed; a key that cannot be attested where policy asks for it; a slot collision or a purpose with no slot; a card with fewer than three PIN tries left; a request that fails a check of the hand-off contract; and, at init, a card that this bundle has no sealed copy of the secrets for (not adopted here, not received by request and answer) or that still has a default PIN (the holder sets the PIN; adoption replaces the PUK and the management key). `init` and `root add` also refuse a hardware or cloud root that cannot be attested or read.
15. `init` creates the bundle, the roots, the revocation signature of each primary and the first trust files. It makes two roots by default, both cards present, each with this bundle's sealed copy of its secrets; a cloud root or a personal bundle has one. It obtains, verifies and stores the attestation of each root key, and prints the accepted limit of the store; the record says it was shown.
16. The machine is not trusted: the key never leaves its store, and every byte the root will sign is fixed, shown and confirmed before the store signs it. The program checks nothing about the machine, for any root.
17. A key that can be copied (a software key in a file) is used only in the offline system, a machine booted from a read-only system made for the purpose, never in the everyday system; a test root is the exception. The rule is the holder's and is taught. It costs a boot for every such ceremony. A drive for software keys is required, but the holder may override it; urgent cases such as a revocation get a fast path or an explicit risk acceptance.
18. A key that cannot be copied (a root on cards, a cloud root) may be used on the holder's workstation under four conditions: (1) a touch for every signature, set when the key is born and unchangeable later; (2) the number of signatures stated in the plan; (3) no retry of a failed touch, so a failed touch ends the ceremony; (4) the result checked against the plan on a second device before it is handed over or published. A cloud root is signed from the workstation through the ceremony role, with no stick. A cloud root and a test root are not affected by rule 17. The offline system stays available for whoever wants a clean machine, for any kind of root.
19. The limit is stated plainly. The card has no screen and signs whatever bytes it is sent; a compromised workstation can show the right digest and still ask for one more signature, and no hash on that machine stops that. A touch for every signature, a stated count and no retry bound the rest. If one extra touch is given by a trick, one unknown signature exists and a card keeps no log of it; a cloud key does better, because its audit trail records every signature.
20. The offline system is vanilla AirgapOS, unchanged, started from the ceremony USB stick, which carries one extra partition that ritueel lays out. ritueel builds no operating system of its own.
21. The extra partition holds ritueel binaries (several versions and architectures), several bundles, and the encrypted key files beside the bundles, never inside one: a bundle is made to be copied and shared, and a key file is the root itself. The saved plan travels inside the bundle. The stick step is shown only for the offline system.
22. Whenever a plan is prepared online and the stick is present, ritueel refreshes the partition itself, without a separate step, before the reboot into the offline system. The plan records the digest of the ritueel binary.
23. Plans and requests are detachable. An operation that needs another holder's bundle or cards is a request or a plan that can travel by any channel, be run elsewhere, and have its answer return. The same steps run at one desk or in two places; with the bundles and cards at hand, ritueel chains the steps in one run.
24. Software mode runs the same commands and steps. Its root is a key file opened as the key-file rule says, and `init`, every confirmation and every record say that a software root can be copied. A script root that is not a test root uses a passphrase through `--passphrase-fd N`; any script confirms with `--confirm DIGEST`.
25. A test root is made with `--test-root`, has no passphrase, and is a key file or lives on a rehearsal card, which serves only a test root. It is born with the normal `init --test-root` on a registered rehearsal card; no flag is added. It is marked TEST ONLY in its certificate name and every record, and `ca-bundle build` and `keyring build` refuse to put a test root and a real root in one trust file. A real root never becomes a test root, because test is set at birth. A test root may run its ceremonies on the workstation or on a rehearsal card. The relaxed mode for tests is wording only; no flag turns the offline rule off.

## Why

A root signs for everything below it, so the person must see what will be signed before it is signed. The machine is not trusted, so the rules rest on what stays in the store and on what the person confirmed. A copyable key is the root itself and needs a clean machine; rule 18 bounds the rest.

## What it costs

- Every ceremony with a copyable key needs a boot into the offline system.
- On the workstation, one tricked touch gives one unknown signature. The second-device check proves afterwards what was signed; it cannot prevent an extra one.
- A stopped run leaves a critical attempt until a person closes it.
- The reference pages (record, plan file, partition layout, commands) must follow this record.

## Roads not taken

- **One command with no plan step.** Simpler, but nothing to review before the touch and no trace of what a crash may have signed.
- **A different ceremony for each store.** Each keeps its own shape, but plan, confirmation, records and refusals would be written and taught four times.
- **Generate the keys before the plan.** Every byte is fixed, but the key would exist, and a slot be overwritten, before the person confirmed anything.
- **Confirm by pressing a key.** Fast, but pressed without reading, and a script could confirm a plan it never read.
- **Resume a half-finished birth.** Saves a slot deletion, but needs state ritueel cannot verify on a card, and the person never saw the resumed key in a plan.
- **A second confirmation after each birth.** More caution, but the fingerprint before the touch already allows a stop, and a second prompt is the key-press habit refused above.
- **Accept a root without attestation at init.** Faster adoption, but nothing would show the root was born on its card.
- **`init` creates one root at a time.** The second card can stay away, but the revocation material and the two-root list are made together, and a one-root state is the unsafe one.
- **An air-gapped machine kept for the purpose.** Little gain for the friction, since the key never leaves the card; the read-only system is the middle course.
- **The everyday workstation for a copyable key.** Nothing to boot, but the key is exposed to everything that machine runs for the whole sitting. Allowed for a key that cannot be copied, with four conditions; refused for a copyable key.
- **Every root, card and cloud, only in the offline system.** Removes the risk of one tricked touch, but costs a reboot for every ceremony.
- **Trust a hash shown on the workstation.** The card has no screen and the same machine shows the hash and talks to the card, so it can show the right digest and still ask for one more signature.
- **ritueel's own ceremony image.** Not chosen; ritueel builds no operating system.
- **Knoppix or other purpose-built distributions.** Researched; Debian Live is kept as the fallback.
- **A read-only boot partition made by ritueel (two partitions of its own design).** The maintainer chose vanilla AirgapOS; ritueel only defines the layout of the extra partition.
- **Key files inside the bundle.** A bundle is made to be copied and shared, and a copy would carry the root.
- **One way at one desk and another for two places.** Two procedures to build, test and teach; the same steps under the hood in both are wanted.
- **A flag that turns the offline rule off.** Faster tests, but the program checks nothing about the machine, so a flag would relax a rule nothing enforces, and `--test-root` already marks everything TEST ONLY.

## Not yet proven or only proposed

- **Not yet proven.** That AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it; a first-milestone test ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Not yet proven.** That the offline system, with no network stack, is vanilla AirgapOS and the local page runs only on the planning machine; this holds on condition that the passkey test passes ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Not yet proven.** Which card checks run for a test root on a rehearsal card; fixed with the card proofs of the first milestone ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Proposed.** A cloud key has no touch, so condition (1) of rule 18 is for cards; the stated count, no retry and the second-device check apply to both kinds of key; for a cloud root the typed digest and the role session stand, with no hardware-key gate as a rule. The maintainer is to confirm ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** The program enforces: (1) set in the card at birth; (2) the count and (3) no retry, kept by the program; (4) the second-device check is taught and recorded, because the program checks nothing about the machine. Whether the record carries a field that a second-device check was declared, and what is compared, is open ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** When a plan is prepared online and no stick is present, the plan is still made, nothing is refreshed, and the person is told the stick is not current ([#30](https://github.com/truvity/ritueel/issues/30)).

## Replaces

Old records 0001, 0002, 0003, 0004, 0007, 0008 and 0016, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
