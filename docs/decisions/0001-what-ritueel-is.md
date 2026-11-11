# 0001 — ritueel keeps roots and teaches how; systems that issue every day keep intermediates

**Status:** Accepted
**Date:** 2026-11-11

## Decision

1. Roots and root changes are a separate product, ritueel, kept apart from systems that issue certificates every day (such as sluis) and hold intermediates.
2. The purpose is to help one person or a small team keep a private root and an OpenPGP primary key for years without losing, leaking, misusing or letting it expire. ritueel teaches the model first, then runs each ceremony with the person deciding.
3. Five core ideas. One set of ceremonies over three stores (a key file, a pair of root cards, a cloud key service); the guarantees differ by store, and ritueel says so. Prefer a key that cannot be copied (root cards, a cloud key); it also avoids the reboot into the offline system. One bundle keeps the roots of a PKI and of OpenPGP together, with what is known about the cards. Requests in, answers out: other systems connect through files, and plans can travel. An opinionated, automated workflow: what is due, then plan, confirm, reserve, sign, verify, record.
4. Scope is X.509 CA roots and OpenPGP primary keys, in one model, across key stores.
5. ritueel and sluis depend on neither each other nor shared code. They exchange only standard formats (PKCS#10, X.509, OpenPGP packets, attestation certificates) through a versioned hand-off contract, so either side can be replaced.
6. The floor of the contract is PKCS#10 in, X.509 out, in a stated profile that any certificate authority can issue. On the floor the requester's anchors are the CA certificates the operator installed, with no trust sequence and no rollback protection.
7. ritueel's own contract adds the proof of where the key lives, the result file, the reason codes, and the signed root list with its trust sequence.
8. The contract is specified and tested from both sides, with versioning and test vectors; it is the first backlog item. The software-root mode is built first, because the full contract can only be tested with it.
9. Out of scope: online signing, leaf certificates, secret storage.
10. ritueel changes only your bundle. The one thing it may send out is your public OpenPGP key, to the keyservers you list. For everything else it prints what to do ([0011](0011-publishing-and-what-to-do-after-a-ceremony.md)). Its work otherwise ends at files: roots, certifications and bindings, trust files, records and a keyring file. Packaging (deb, rpm), publishing anything else and using keys belong to other tools; the release pipeline packages the keyring.
11. Staff keys are out of scope. Every employee uses OpenPGP as a person's own key. There is no delegation by a company root to an online certifier, no card helper and no staff proof format. What another system may automate later (signing releases, syncing a person's key to a hosting account) is outside ritueel. Printing the key file, the link and the host's command is a next step that ritueel prints (0011); calling the host's tool is outside ritueel until the maintainer says otherwise.
12. The operator prepares the holder (account, roles, PIN). ritueel creates the keys, attests and verifies them; it creates no account and no role, and keeps no PIN that the holder types.
13. A feature that makes a ceremony faster but takes the decision from the person is refused.
14. An earlier private tool is only a source of ideas, use cases and history, not a base for ritueel.
15. The scope cut is: plain folders only, trim the existing design, extras not built. The SSH CA stays.
16. ritueel is a teaching product first: the purpose is a smooth and safe experience of managing a root, not the tools. The site is part of the product; it teaches the logic of roots and intermediates, with one guide per procedure and drills on test keys.
17. Opinionated help covers the whole life of a root: where the bundle lives, backup and restore, re-signing and rotating, revocation, card loss and replacement. Each procedure gets a Learn page (why and when), a guide (steps) and a drill.
18. The site publishes only the home page, the Learn path, the demo, the glossary, where it stands (status and roadmap), one page that states the design in brief, and the hand-off contract that the requester system reads. Records, guides, tool, reference, principles, research and contributor pages are not published; they are written under docs/ and read in the repository.
19. The allowlist site/published.txt says which pages are published; a page comes back by one line, and nothing is deleted. Old addresses of unpublished pages redirect (302) to their file on GitHub, and links from published pages to unpublished files open that file.
20. The teaching target is four things from the ground up (how a YubiKey holds keys, passkeys, a KMS key, choosing where a root lives), a glossary, a reference generated from the program, and a "how to verify a release" page that comes with the release candidate, not before.
21. The site compares key stores by what each protects against and costs (software and its backends, YubiKey PIV and OpenPGP card, AWS KMS today), recommends devices to buy for testing, and dates each claim.
22. Pages say what is built: guided mode, local page, 1Password backend and keyring backend are marked planned until their issues are done. Pages do not call the second card a spare, the custody two-person control, or a replica a second root, and state the accepted limit.
23. The site shows, not only tells: a comic-style "How it works?" sketch of the major use cases (binding subkeys from a YubiKey, signing a PKI intermediate); illustrations of the YubiKey, slots and passkeys; the layout of a root card, a day-to-day card and a server card; the layout of a bundle and of the extra partition on the stick.
24. The site also publishes "How it works": an overview of the use cases and two layout pages, in pictures. Each such page says that the pictures show the design, because the program does not exist yet.
25. The pictures are inline SVG that follows the theme of the site, drawn by a figure kit under `site/figures/`.
26. The site is judged at two bars: the design phase now, the first signed release later; a newcomer's reading test does not block the design phase. Learn is done when someone new to PKI has read every Learn page end to end, their questions are answered on the page, and the comparison page exists. The comparison page exists; the reading does not yet.
27. On 2026-11-11 the site was cut to the target. No new teaching page is written for now; three wait (user IDs, checking your cards, renewing a delegated key).
28. The glossary fixes twelve words: root, delegated key, holder (page word: operator), requester (sluis is one; ritueel is the certifier), store, ceremony, bundle, history, record, renew, replace and trust files. A root is the key others trust without further proof (an X.509 root CA key or an OpenPGP primary); a delegated key is an intermediate certificate key, an OpenPGP subkey or an SSH CA key. A ceremony has six steps, confirmed by a person; "yearly ceremony" is a practice, not a command. To renew is to extend the same key; to replace is to make a new key on an event, including the three-year limit on a copyable key.
29. "Bundle" always means the directory that holds everything ritueel knows about one trust domain; the trust file is "the CA bundle" in full; across bundles it is "acme/A". Trust files live in trust/<number>/, and the older page word "trust products" goes. Card, row and inventory are defined on the bundle and cards pages.
30. The milestones are: Learn (now); M0 Records; M1 Proofs on a rehearsal card; M2 Release candidate; M3 A person's key, stage one; M4 A company's cloud root; M5 First signed release; M6 A company's card roots, then a person's card-born primaries; M7 Afterwards. Dates are not promised, the order is; what each milestone delivers is on the roadmap page. A change to the plan is a pull request to the roadmap page. Milestones are GitHub milestones with area and type labels.
31. M0 (the written design) is the small clean set of records, the page that states the design in brief, the reference pages, the glossary and the teaching pages saying the same thing. M1 comes first of the builds: the passkey proof, the card proofs and the stick test, before the stores.
32. The decision records are rewritten from a clean state as a small set, written only from the checked list of decisions; the old eighteen stay in the repository.

## Why

Root custody is rare and costly to get wrong; daily issuing is busy, so the two are kept apart. A reader who does not know why a root is kept apart and guarded makes the expensive mistake faster, so teaching comes first. The 77-feature analysis proposed 22 core, 16 rules, 19 later, 8 merged and 12 dropped; these counts are a proposal, not accepted as such.

## What it costs

- The contract needs work on both sides, and the software-root mode comes first.
- Most pages are read on GitHub, not on the site.
- The requester system loses its staff-key counterpart.

## Roads not taken

- **Root ceremonies inside the system that holds intermediates.** One system, but root custody sits beside the busiest code and the line between rare and daily keys disappears.
- **A hosted service that holds the roots.** Easy to use, but the roots become online and someone must be trusted with every root.
- **Two tools, one for X.509 and one for OpenPGP.** Each is simpler, but create, vouch, overlap, supersede and revoke are one model, and teaching and records would be written twice.
- **A shared library or a private protocol.** Less to specify, but neither side works without the other and other issuing systems are locked out.
- **No floor, the full contract or nothing.** One trust mode everywhere, but ritueel's formats would be required of every CA and a system with intermediates could not be tested without ritueel.
- **ritueel also sets the PIN.** One tool from box to root, but the holder must type the PIN and ritueel would have to hold it.
- **ritueel creates the account and the roles.** One command for a cloud root, but it needs account-creating rights, differs for every organisation and becomes an infrastructure tool.
- **Tools first, teaching as an appendix.** Faster to build, but a reader who does not know why a root is kept apart and guarded makes the expensive mistake faster.
- **Staff keys for a company: a delegation to an online certifier, a card helper and a staff proof bundle.** It would cover staff, but the maintainer dropped it; what the requester system automates later is its own work.
- **Publish every page and put the working material behind a Design entry.** Nothing lost, but the overload stays and 32 not-built-yet pages keep contradicting the target.
- **Hold back only the unbuilt pages.** A smaller cut, but 53 pages remain to drift apart.
- **Keep rewriting the 18 records in place.** No new work, but 33,646 words, each rewritten many times, contradicting each other in places.
- **Mermaid or image files for the pictures.** Simple to write, but an image file cannot follow the light and the dark theme, and Mermaid needs a script that the Content-Security-Policy would have to list.

## Not yet proven or only proposed

None.

## Replaces

Records 0001, 0002, 0006, 0007, 0008 and 0014, read at commit d0ae12da2432d5ae95cf95d68fb85ba3dda6cfee.
