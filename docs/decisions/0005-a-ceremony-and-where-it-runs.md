# 0005 — A ceremony applies what is wanted and not applied yet, in one act; a key that cannot be copied may be used on the workstation

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. A ceremony is interactive, with a person present, and is one or two commands. Routine work is automated.
2. A ceremony is one act, `apply`. The order inside it, the checks and the ceremony records are the same for every key store. The rules below say where the order matters.
3. Every ceremony leaves a ceremony record: what was done and where it ran (workstation or offline system). The format is the [ceremony record](/reference/ceremony-record/) page.

4. What is not applied yet is found each time from the wanted files, the history, the date and the requests, and never stored. Each item is called a change.
5. A wanted line or file that is deleted retires, revokes and removes nothing, and it is shown as a finding. The history wins over a wanted file.
6. The digest of a wanted file is the SHA-256 of the bytes as stored, so `sha256sum` gives the same value. Two files with one meaning have two digests, which is accepted.

7. `apply` first finds what is not applied yet (rule 4) and writes a plan of it, with every byte to be signed fixed in advance ([its members](/reference/ceremony-record/#the-plan)). The plan lists what it applies, what it leaves out with the reason, and the wanted files it used, by digest. Serials and times are drawn once, when the plan is made. The plan holds public information only, needs no card, can be made anywhere, and can be carried to the offline system as a saved plan file.
8. A key born in a ceremony is not in the plan; the plan fixes everything else ([its members](/reference/ceremony-record/#the-plan)). A signature that covers a new key is listed as derived, and the check of rule 12 tests it against the profile and the born key. So the plan is not byte-exact for new keys, software roots included.
9. A person confirms `apply`: ritueel shows the plan in words with its digest, and the person types the first eight characters of it. A key press is not accepted. A script confirms with `--confirm DIGEST`, so it cannot confirm a plan it has not computed. A wrong or missing confirmation writes nothing. A confirmation never replaces a touch.
10. Before the first key is born, not only before the first signature, ritueel writes an attempt, and appends each key to a birth journal as soon as it exists and each signature to a journal of signatures beside it. If a run stops, `status` shows the attempt as critical until a person closes it, and `close` prints the journals. ritueel does not resume a birth and does not undo one.
11. When the root key signs, each fingerprint is shown before its touch, so a new key is seen before any root key signs for it.
12. Every artifact is checked against its request and the plan, with code that did not sign it, before it is written out. Then ritueel writes the transcript, then the artifacts, and last the ceremony record ([record 0006](0006-bundle-history-and-trust-files.md), rules 8 and 31).
13. `apply` does the whole ceremony and can write the plan and stop; a saved plan is executed after checking that it still matches the bundle (at least the end of the history and the trust sequence), and asks for the first eight characters of its digest.
14. `close` asks the person to type the first eight characters of the digest of the plan, as `apply` does (rule 9); a script gives `--confirm DIGEST`.
15. `close` writes a closing record. It names the attempt it closes and the reason the holder gave.
16. Renewals are separate actions of one ceremony, not commands, and there is no "yearly" command. `apply` renews what is due, 60 days before its end date ([record 0007](0007-changing-and-losing-a-root.md), rule 18, [record 0006](0006-bundle-history-and-trust-files.md), rules 20, 26); a CRL follows [record 0006](0006-bundle-history-and-trust-files.md), rule 24. A plan is like the confirmation page of a bank transfer: the fixed order ritueel executes, not a script.
17. Nothing happens without the user's confirmation, and the PIN and the touch stay on the card.
18. ritueel verifies where an intermediate key lives, signs an intermediate's PKCS#10 request into an intermediate CA certificate, and binds an OpenPGP subkey after checking the back-signatures.

19. ritueel refuses, before anything is written: a card whose serial is not registered or is wrong for the role; a wanted file that fails its check; a fingerprint that differs from the plan or from the one the requester printed; a key that cannot be attested where policy asks for it; a slot collision or a purpose with no slot; a card with fewer than three PIN tries left; a request that fails a check of the hand-off contract or is under no declared delegation; an adoption in a plan that runs in the offline system; and, when a root key is to be born, a card that is not adopted here or has a default PIN. The first `apply` and each added root key also refuse a hardware or cloud root key that cannot be attested or read.
20. `new` makes the folder and the starter wanted files and touches no card. The first `apply` makes the root keys, the revocation signature of each primary and the first trust set: two keys of each root by default, both cards present; a cloud root has one key for each kind of root, and a personal bundle has one key. It obtains, verifies and stores the attestation of each root key, and prints the accepted limit of the key store; the ceremony record says it was shown.
21. The machine is not trusted: the key never leaves its key store, and every byte the root will sign is fixed, shown and confirmed before the key store signs it. The program checks nothing about the machine, for any root.

22. A key that can be copied (a software key in a file) is used only in the offline system, a machine booted from a read-only system made for the purpose, never in the everyday system; a test root is the exception. The rule is the holder's and is taught. A drive for software keys is required, but the holder may override it.
23. A key that cannot be copied (a root on cards, a cloud root) may be used on the holder's workstation under four conditions: (1) a touch for every signature, set when the key is born and unchangeable later; (2) the number of signatures stated in the plan; (3) no retry of a failed touch, so a failed touch ends the ceremony; (4) the result checked against the plan on a second device before it is handed over or published. Condition (1) is for a root on cards only: a cloud key has no touch, and for a cloud root the typed digest and the role session stand. Conditions (2), (3) and (4) apply to both kinds of key.
24. A cloud root always runs on the workstation, signed through the ceremony role with no stick, because the offline system has no network (rule 29). A cloud root and a test root are not affected by rule 22. The offline system is an option for a root on cards, for whoever wants a clean machine.
25. The limit is stated plainly. The card has no screen and signs whatever bytes it is sent; a compromised workstation can show the right digest and still ask for one more signature, and no hash on that machine stops that. Conditions (1) to (3) of rule 23 bound the rest. If one extra touch is given by a trick, one unknown signature exists and a card keeps no log of it; a cloud key does better, because its audit trail records every signature.
26. A test root is marked at birth, has no passphrase, and is a key file or lives on a rehearsal card. The normal first `apply` makes it. It is marked TEST ONLY in its certificate name and every ceremony record, and `apply` refuses to put it in one trust set with a real root. A real root never becomes a test root, because test is set at birth. A test root may run its ceremonies on the workstation or on a rehearsal card. The relaxed mode for tests is wording only; no flag turns the offline rule off.
27. Software mode runs the same commands and the same ceremony. Its root is a key file opened as the key-file rule says, and the first `apply`, every confirmation and every ceremony record say that a software root key can be copied. A script root that is not a test root uses a passphrase through a file descriptor.
28. Plans and requests are detachable. An operation that needs another holder's bundle or cards is a request or a plan that can travel by any channel, be run elsewhere, and have its answer return; coming back from the stick is a join ([record 0006](0006-bundle-history-and-trust-files.md), rule 35). The same ceremony runs at one desk or in two places; with the bundles and cards at hand, ritueel does it all in one run.

29. The offline system is vanilla AirgapOS, unchanged, started from the ceremony USB stick, which carries one extra partition ritueel lays out. ritueel builds no operating system of its own. It has no network stack, so the local page runs only on the planning machine.
30. The extra partition holds the ritueel binaries (several versions and architectures), several bundles, and the encrypted key files beside the bundles, never inside one. The stick's copy of a bundle carries no wanted files of its own; the saved plan travels inside the bundle with the exact copies of the wanted files it used. The stick step is shown only for the offline system.
31. The extra partition of the stick is exFAT, so that every operating system can read it.
32. Whenever a plan is prepared online and the stick is present, ritueel refreshes the partition itself, without a separate step, before the reboot into the offline system; the refresh only adds files and skips the wanted files. The plan records the digest of the ritueel binary.
33. The partitions of AirgapOS on the stick are not touched, and the holder trusts AirgapOS as published.
34. There is no second stick for ritueel.
35. The run uses the version of the program that made the plan, the copy refreshed on the stick.

## Why

A root signs for everything below it, so the person must see what will be signed before it is signed. The machine is not trusted, so the rules rest on what stays in the key store and on what the person confirmed. A copyable key is the root itself and needs a clean machine; rule 23 bounds the rest. Windows and macOS read exFAT as well as Linux, so a holder can read the stick on any workstation (rule 31).

## What it costs

- Every ceremony with a copyable key needs a boot into the offline system.
- On the workstation, the second-device check proves afterwards what was signed; it cannot prevent an extra signature (rule 25).
- A stopped run leaves a critical attempt until a person closes it.
- The stick is kept with the same care as a root: a key file is the root itself, even though it is encrypted.
- exFAT has no journal. A bundle on the stick stays whole by the write steps of [record 0006](0006-bundle-history-and-trust-files.md), rule 31, not by the file system (rule 31); the lines on a real stick below say what this does not cover.

## Roads not taken

- **One command with no plan to read first.** Simpler, but nothing to review before the touch and no trace of what a crash may have signed.
- **A different ceremony for each key store.** Each keeps its own shape, but plan, confirmation, records and refusals would be written and taught four times.
- **Generate the keys before the plan.** Every byte is fixed, but the key would exist, and a slot be overwritten, before the person confirmed anything.
- **Confirm by pressing a key.** Fast, but pressed without reading, and a script could confirm a plan it never read.
- **Four characters to confirm instead of eight.** Rare ceremonies cost little to type, but four can be matched by a swapped plan at once, even from a browser tab, and the typed characters link the plan the page shows to the run in the terminal; neither length is the real protection.
- **A count typed at `apply` as well as the eight characters.** A person would see the numbers, but it is a second prompt of the key-press habit refused above, and the plan in words already shows the counts; the eight characters are the one confirmation (rule 9).
- **Resume a half-finished birth.** Saves a slot deletion, but needs state ritueel cannot verify on a card, and the person never saw the resumed key in a plan.
- **A second confirmation after each birth.** More caution, but the fingerprint before the touch already allows a stop, and a second prompt is the key-press habit refused above.
- **Accept a root without attestation at the first `apply`.** Faster adoption, but nothing would show the root was born on its card.
- **The first `apply` makes one root key at a time.** The second card can stay away, but the revocation material and the two-root list are made together, and a one-root state is the unsafe one.
- **A separate command for each renewal, and a command for what is due.** Explicit, but six commands for what an end date already says (rule 16).
- **A deleted line retires the object.** Short, but a slip in an editor would retire a key; a deleted line retires, revokes and removes nothing (rule 5).
- **The first eight characters of the digest of the attempt for `close`.** It names what is closed, but it is a second kind of eight characters that the person does not see in the folder name, and the digest of the plan is the habit of `apply` (rule 14).
- **Nothing to type for `close`, only the reason.** Nothing to learn, but rule 17 asks for a confirmation, a key press is not accepted for a plan (rule 9), and closing an attempt ends a critical finding of `status` (rule 10).
- **A digest of a canonical form of the parsed YAML.** One meaning would give one digest, but a canonical form must be specified and tested, the digest would depend on the parser, and no standard tool gives the value (rule 6).
- **A fixed normalisation of line ends before the digest.** The most common differences between machines and editors would go, but ritueel would digest bytes that are not in the file, and a copy in `wanted/` would no longer be an exact copy (rule 6).
- **An air-gapped machine kept for the purpose.** Little gain for the friction; the read-only system is the middle course.
- **The everyday workstation for a copyable key.** Nothing to boot, but the key is exposed to everything that machine runs for the whole sitting.
- **Every root, card and cloud, only in the offline system.** Removes the risk of one tricked touch, but costs a reboot for every ceremony.
- **Trust a hash shown on the workstation.** The card has no screen and the same machine shows the hash and talks to the card, so it can show the right digest and still ask for one more signature.
- **A flag that turns the offline rule off.** Faster tests, but the program checks nothing about the machine, so a flag would relax a rule nothing enforces, and `--test-root` already marks everything TEST ONLY.
- **One way at one desk and another for two places.** Two procedures to build, test and teach; the same ceremony in both is wanted.
- **A plan made on the stick.** One trip fewer, but the stick would need the wanted files and could bring old ones back; the stick runs only a saved plan (rule 30).
- **A plan as the place where a change waits.** One open plan that collects changes would end two saved plans that disagree, but a change would live only in a plan, a plan made in the page could take the one place, and a plan older than its changes would hide them; saved plans as that place need nothing more to build, but one goes out of date; what is wanted lives in the wanted files and a plan is made from them each time, a change waits in the wanted files, and a saved plan only carries one ceremony to another place.
- **Changes stored on each object.** Close to how people speak, but a change would have three homes (the object, a plan, the history); a change is found every time and never stored (rule 4).
- **Knoppix or other purpose-built distributions.** Debian Live is kept as the fallback.
- **An operating system or boot partition of ritueel's own.** A ceremony image, a read-only boot partition (two partitions of its own design) or an AirgapOS fork, built by ritueel: the stick would hold one system of ritueel's own, but ritueel would maintain an operating system, and the holder would trust that build instead of AirgapOS as published; ritueel builds no operating system and only defines the layout of the extra partition.
- **Key files inside the bundle.** A bundle is made to be copied and shared, and a copy would carry the root.
- **A second stick for ritueel.** The boot stick stays untouched, but there are two sticks to carry and lose, and the plan, the program and the key files no longer travel together.
- **Fetching the program at the offline system.** Nothing to keep on the stick, but it would need a network, which is the point of not having one.
- **ext4 for the stick's partition.** It has a journal and the trial found no fault in it, but Windows and macOS do not read it, so only a Linux workstation could read the stick (rule 31).
- **Both file systems, the holder chooses.** Each holder gets the file system wanted, but there are two paths to test and to keep working (rule 31).
- **Six named steps for every ceremony: plan, confirm, reserve, sign, verify, record.** They gave a short list to teach and a name for each rule, but they made one act look like six and had to be repeated on every page and picture; a ceremony is one act, `apply`, and an order is written only where a rule needs it (rules 9 to 12).

## Not yet proven or only proposed

- **Not yet proven.** That AirgapOS boots from a stick with a second partition, mounts it and runs a static binary from it; a first-milestone test ([#200](https://github.com/truvity/ritueel/issues/200)).
- **Not yet proven.** That the offline system, with no network stack, is vanilla AirgapOS and the local page runs only on the planning machine; this holds on condition that the passkey test passes ([#200](https://github.com/truvity/ritueel/issues/200)).
- **Proposed.** Where a test root is marked, for example in its wanted root file, and how a test bundle starts; rule 26 says only that it is marked at birth ([#136](https://github.com/truvity/ritueel/issues/136)).
- **Not yet proven.** Which card checks run for a test root on a rehearsal card; fixed with the card proofs of the first milestone ([#200](https://github.com/truvity/ritueel/issues/200)).
- **Proposed.** The program enforces: (1) set in the card at birth; (2) the count and (3) no retry, kept by the program; (4) the second-device check is taught and recorded, because the program checks nothing about the machine. Whether the ceremony record carries a field that a second-device check was declared, and what is compared, is open ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** For an urgent case such as a revocation, a fast path or an explicit risk acceptance when the drive for software keys is not at hand; which of the two is not decided ([#180](https://github.com/truvity/ritueel/issues/180)).
- **Proposed.** When a plan is prepared online and no stick is present, the plan is still made, nothing is refreshed, and the person is told the stick is not current ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Not yet proven.** That a real stick with an exFAT partition keeps a bundle whole after a power cut; the trial in a virtual machine is in [the research note](../research/exfat-power-cut-2026-11-12.md) ([#181](https://github.com/truvity/ritueel/issues/181)).
- **Not yet proven.** On one real stick with an exFAT partition, cutting the stick's data connection during a write left a bundle broken in 4 of 30 cut moments: three times a folder's list of names was destroyed, once two flushed journal lines were lost; the stick kept its power, so a real power loss and a file system with a journal on a real stick are not tested ([the measurement](../research/usb-stick-cut-during-a-write-2026-11-13.md), [#181](https://github.com/truvity/ritueel/issues/181)).
- **Proposed.** ritueel refuses a stick's copy of a bundle that fails its check, says which files are lost or unexpected, and tells the holder to refresh the stick from the repository ([the measurement](../research/usb-stick-cut-during-a-write-2026-11-13.md), [#181](https://github.com/truvity/ritueel/issues/181)).
- **Proposed.** The names of the directories on the extra partition of the stick; the layout and the file system (rule 31) are decided, the names are not ([#30](https://github.com/truvity/ritueel/issues/30)).
- **Proposed.** An age limit of a plan; it guards a scheduled run, and no number is fixed ([#142](https://github.com/truvity/ritueel/issues/142)).
- **Proposed.** A flag `--only` that a script must pass to confirm; it guards a scheduled run, and no spelling is fixed ([#143](https://github.com/truvity/ritueel/issues/143)).
- **Proposed.** Whether `apply` refuses to make a new plan while an attempt is open, or only refuses to run the plan that has the attempt (the ceremony record page says the second) ([#140](https://github.com/truvity/ritueel/issues/140)).
