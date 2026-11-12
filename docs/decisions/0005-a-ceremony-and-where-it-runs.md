# 0005 — A ceremony applies what is wanted and not applied yet, in six steps; a key that cannot be copied may be used on the workstation

**Status:** Accepted
**Date:** 2026-11-12

## Decision

1. A ceremony is interactive, with a person present, and is one or two commands. Routine work is automated.
2. Every ceremony leaves a ceremony record: what was done, with which keys, on which store, what outsiders see, and where it ran (workstation or offline system). The format is the [ceremony record](/reference/ceremony-record/) page.
3. Every ceremony has six steps in this order: plan, confirm, reserve, sign, verify, record. The steps, the checks and the ceremony records are the same for every store.
4. Plan: ritueel reads the wanted files, the history, the date and the requests, and writes a plan of what is not applied yet, with every byte to be signed fixed in advance (the root keys, each key's fingerprint and store, serials, times, the numbers of signatures and touches). It lists what it applies, what it leaves out with the reason, and the wanted files it used, by digest. Serials and times are drawn once, here. The plan holds public information only, needs no card, can be made anywhere, and can be carried to the offline system as a saved plan file.
5. A key born in a ceremony is not in the plan; the plan fixes everything else (store, serial and slot or Region, algorithm, OpenPGP creation time, serials, validity, touches). A signature that covers a new key is listed without `tbs_sha256`, marked derived, and verify checks it against the profile and the born key with code that did not sign it. So the plan is not byte-exact for new keys, software roots of the second milestone included.
6. Confirm: ritueel shows the plan in words with its digest, and the person types the first eight characters of it. A key press is not accepted. A script confirms with `--confirm DIGEST`, so it cannot confirm a plan it has not computed. A confirmation never replaces a touch.
7. Reserve: before the first key is born, not only before the first signature, ritueel writes an attempt, and appends each key to a birth journal as soon as it exists and each signature to a journal of signatures beside it. If a run stops, `status` shows the attempt as critical until a person closes it, and `close` prints the journals. ritueel does not resume a birth and does not undo one.
8. Sign: the root key is used and each fingerprint is shown before its touch, so a new key is seen before any root key signs for it.
9. Verify: every artifact is checked against its request and the plan, with code that did not sign it, before it is written out. Record: the transcript, then the artifacts under names of their own, and last the ceremony record, which lists them by digest.
10. `apply` runs all six steps and can stop after the plan; a saved plan is executed after checking that it still matches the bundle (at least the end of the history and the trust sequence), and asks for the first eight characters of its digest.
11. Renewals are separate actions of one ceremony, not commands, and there is no "yearly" command. `apply` renews what is due: a delegation, the root list or the SSH CA key list, 60 days before its end date (0007 rule 16, 0006 rules 18, 22); a CRL follows 0006 rule 26. A plan is like the confirmation step of a bank transfer: the fixed order ritueel executes, not a script.
12. Nothing happens without the user's confirmation, and the PIN and the touch stay on the card.
13. ritueel verifies where an intermediate key lives, signs an intermediate's PKCS#10 request into an intermediate CA certificate, and binds an OpenPGP subkey after checking the back-signatures.
14. ritueel refuses, before anything is written: a card whose serial is not registered or is wrong for the role; a wanted file that fails its check; a fingerprint that differs from the plan or from the one the requester printed; a key that cannot be attested where policy asks for it; a slot collision or a purpose with no slot; a card with fewer than three PIN tries left; a request that fails a check of the hand-off contract or is under no declared delegation (reason code `policy`); an adoption in a plan that runs in the offline system; and, when a root key is to be born, a card that is not adopted here or has a default PIN. The first `apply` and each added root key also refuse a hardware or cloud root key that cannot be attested or read.
15. `new` makes the folder and the starter wanted files and touches no card. The first `apply` makes the root keys, the revocation signature of each primary and the first trust set: two keys of each root by default, both cards present; a cloud root or a personal bundle has one key. It obtains, verifies and stores the attestation of each root key, and prints the accepted limit of the store; the ceremony record says it was shown.
16. The machine is not trusted: the key never leaves its store, and every byte the root will sign is fixed, shown and confirmed before the store signs it. The program checks nothing about the machine, for any root.
17. A key that can be copied (a software key in a file) is used only in the offline system, a machine booted from a read-only system made for the purpose, never in the everyday system; a test root is the exception. The rule is the holder's and is taught. It costs a boot for every such ceremony. A drive for software keys is required, but the holder may override it; urgent cases such as a revocation get a fast path or an explicit risk acceptance.
18. A key that cannot be copied (a root on cards, a cloud root) may be used on the holder's workstation under four conditions: (1) a touch for every signature, set when the key is born and unchangeable later; (2) the number of signatures stated in the plan; (3) no retry of a failed touch, so a failed touch ends the ceremony; (4) the result checked against the plan on a second device before it is handed over or published. Condition (1) is for a root on cards only: a cloud key has no touch, and for a cloud root the typed digest and the role session stand, and its audit trail records every signature. Conditions (2), (3) and (4) apply to both kinds of key. A cloud root always runs on the workstation, signed through the ceremony role with no stick, because the offline system has no network (rule 20). A cloud root and a test root are not affected by rule 17. The offline system is an option for a root on cards, for whoever wants a clean machine.
19. The limit is stated plainly. The card has no screen and signs whatever bytes it is sent; a compromised workstation can show the right digest and still ask for one more signature, and no hash on that machine stops that. A touch for every signature, a stated count and no retry bound the rest. If one extra touch is given by a trick, one unknown signature exists and a card keeps no log of it; a cloud key does better, because its audit trail records every signature.
20. The offline system is vanilla AirgapOS, unchanged, started from the ceremony USB stick, which carries one extra partition that ritueel lays out. ritueel builds no operating system of its own. It has no network stack, so the local page runs only on the planning machine.
21. The extra partition holds the ritueel binaries (several versions and architectures), several bundles, and the encrypted key files beside the bundles, never inside one. The stick's copy of a bundle carries no wanted files of its own; the saved plan travels inside the bundle with the exact copies of the wanted files it used. The stick step is shown only for the offline system.
22. Whenever a plan is prepared online and the stick is present, ritueel refreshes the partition itself, without a separate step, before the reboot into the offline system; the refresh only adds files and skips the wanted files. The plan records the digest of the ritueel binary.
23. The partitions of AirgapOS on the stick are not touched: ritueel does not fork AirgapOS or build an image of it, and the holder trusts AirgapOS as published.
24. The program, the bundles and the key files travel on the one stick that carries AirgapOS; there is no second stick for ritueel.
25. The run uses the version of the program that made the plan, the copy refreshed on the stick; the offline system fetches nothing.
26. Plans and requests are detachable. An operation that needs another holder's bundle or cards is a request or a plan that can travel by any channel, be run elsewhere, and have its answer return, added by `join` (0006 rule 30). The same steps run at one desk or in two places; with the bundles and cards at hand, ritueel chains the steps in one run.
27. Software mode runs the same commands and steps. Its root is a key file opened as the key-file rule says, and the first `apply`, every confirmation and every ceremony record say that a software root key can be copied. A script root that is not a test root uses a passphrase through `--passphrase-fd N`; any script confirms with `--confirm DIGEST`.
28. A test root is marked at birth, has no passphrase, and is a key file or lives on a rehearsal card. The normal first `apply` makes it. It is marked TEST ONLY in its certificate name and every ceremony record, and `apply` refuses to put it in one trust set with a real root. A real root never becomes a test root, because test is set at birth. A test root may run its ceremonies on the workstation or on a rehearsal card. The relaxed mode for tests is wording only; no flag turns the offline rule off.
29. What is not applied yet is found each time from the wanted files, the history, the date and the requests, and never stored. Each item is called a change.
30. A wanted line or file that is deleted retires, revokes and removes nothing. The history wins over a wanted file.

## Why

A root signs for everything below it, so the person must see what will be signed before it is signed. The machine is not trusted, so the rules rest on what stays in the store and on what the person confirmed. A copyable key is the root itself and needs a clean machine; rule 18 bounds the rest.

## What it costs

- Every ceremony with a copyable key needs a boot into the offline system.
- On the workstation, one tricked touch gives one unknown signature. The second-device check proves afterwards what was signed; it cannot prevent an extra one.
- A stopped run leaves a critical attempt until a person closes it.
- The reference pages (record, plan file, partition layout, commands) must follow this record.
- The stick is kept with the same care as a root: a key file is the root itself, even though it is encrypted.

## Roads not taken

- **One command with no plan step.** Simpler, but nothing to review before the touch and no trace of what a crash may have signed.
- **A different ceremony for each store.** Each keeps its own shape, but plan, confirmation, records and refusals would be written and taught four times.
- **Generate the keys before the plan.** Every byte is fixed, but the key would exist, and a slot be overwritten, before the person confirmed anything.
- **Confirm by pressing a key.** Fast, but pressed without reading, and a script could confirm a plan it never read.
- **Four characters to confirm instead of eight.** Rare ceremonies cost little to type, but four can be matched by a swapped plan at once, even from a browser tab, and the typed characters link the plan the page shows to the run in the terminal; neither length is the real protection.
- **Resume a half-finished birth.** Saves a slot deletion, but needs state ritueel cannot verify on a card, and the person never saw the resumed key in a plan.
- **A second confirmation after each birth.** More caution, but the fingerprint before the touch already allows a stop, and a second prompt is the key-press habit refused above.
- **Accept a root without attestation at the first `apply`.** Faster adoption, but nothing would show the root was born on its card.
- **The first `apply` makes one root key at a time.** The second card can stay away, but the revocation material and the two-root list are made together, and a one-root state is the unsafe one.
- **An air-gapped machine kept for the purpose.** Little gain for the friction; the read-only system is the middle course.
- **The everyday workstation for a copyable key.** Nothing to boot, but the key is exposed to everything that machine runs for the whole sitting. Allowed for a key that cannot be copied, with four conditions; refused for a copyable key.
- **Every root, card and cloud, only in the offline system.** Removes the risk of one tricked touch, but costs a reboot for every ceremony.
- **Trust a hash shown on the workstation.** The card has no screen and the same machine shows the hash and talks to the card, so it can show the right digest and still ask for one more signature.
- **ritueel's own ceremony image.** Not chosen; ritueel builds no operating system.
- **Knoppix or other purpose-built distributions.** Researched; Debian Live is kept as the fallback.
- **A read-only boot partition made by ritueel (two partitions of its own design).** The maintainer chose vanilla AirgapOS; ritueel only defines the layout of the extra partition.
- **Key files inside the bundle.** A bundle is made to be copied and shared, and a copy would carry the root.
- **One way at one desk and another for two places.** Two procedures to build, test and teach; the same steps under the hood in both are wanted.
- **A flag that turns the offline rule off.** Faster tests, but the program checks nothing about the machine, so a flag would relax a rule nothing enforces, and `--test-root` already marks everything TEST ONLY.
- **An AirgapOS fork or an image built by ritueel.** The stick would hold one system of ritueel's own, but ritueel would maintain an operating system, and the holder would trust that build instead of AirgapOS as published.
- **A second stick for ritueel.** The boot stick stays untouched, but there are two sticks to carry and lose, and the plan, the program and the key files no longer travel together.
- **Fetching the program at the offline system.** Nothing to keep on the stick, but it would need a network, which is the point of not having one.
- **One open plan that collects changes.** It ends two saved plans that disagree, but a change would live only in a plan, a plan made in the page could take the one place, and a plan older than its changes would hide them; what is wanted lives in the wanted files and a plan is made from them each time.
- **Saved plans as the place where a change waits.** Nothing new to build, but two saved plans can disagree and one goes out of date; a change waits in the wanted files, and a saved plan only carries one ceremony to another place.
- **Changes stored on each object.** Close to how people speak, but a change would have three homes (the object, a plan, the history); a change is found every time and never stored (rule 29).
- **A separate command for each renewal, and a command for what is due.** Explicit, but six commands for what an end date already says (rule 11).
- **A deleted line retires the object.** Short, but a slip in an editor would retire a key; a deleted line retires, revokes and removes nothing (rule 30).
- **A plan made on the stick.** One trip fewer, but the stick would need the wanted files and could bring old ones back; the stick runs only a saved plan (rule 21).
- **A count typed at `apply` as well as the eight characters.** A person would see the numbers, but it is a second prompt of the key-press habit refused above, and the plan in words already shows the counts; the eight characters are the one confirmation (rule 6).

## Not yet proven or only proposed

- **Not yet proven.** That AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it; a first-milestone test ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Not yet proven.** That the offline system, with no network stack, is vanilla AirgapOS and the local page runs only on the planning machine; this holds on condition that the passkey test passes ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Proposed.** Where a test root is marked, for example in its wanted root file, and how a test bundle starts; rule 28 says only that it is marked at birth ([#136](https://github.com/truvity/ritueel/issues/136)).
- **Not yet proven.** Which card checks run for a test root on a rehearsal card; fixed with the card proofs of the first milestone ([#11](https://github.com/truvity/ritueel/issues/11)).
- **Proposed.** The program enforces: (1) set in the card at birth; (2) the count and (3) no retry, kept by the program; (4) the second-device check is taught and recorded, because the program checks nothing about the machine. Whether the ceremony record carries a field that a second-device check was declared, and what is compared, is open ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** When a plan is prepared online and no stick is present, the plan is still made, nothing is refreshed, and the person is told the stick is not current ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** The names of the directories on the extra partition of the stick, and its file system; the layout is decided, the names and the file system are not ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** An age limit of a plan, and a flag `--only` that a script must pass to confirm: both guard a scheduled run, and neither is decided; no number and no spelling is fixed here ([#142](https://github.com/truvity/ritueel/issues/142), [#143](https://github.com/truvity/ritueel/issues/143)).
- **Proposed.** That `status` shows a deleted wanted line as a finding, the name of that finding, and what it shows when a deleted key line lowers the target (0007 rule 5) ([#133](https://github.com/truvity/ritueel/issues/133)).
- **Proposed.** Whether `apply` refuses to make a new plan while an attempt is open, or only refuses to run the plan that has the attempt (the ceremony record page says the second) ([#140](https://github.com/truvity/ritueel/issues/140)).

## Replaces

Old records 0001, 0002, 0003, 0004, 0007, 0008 and 0016, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
