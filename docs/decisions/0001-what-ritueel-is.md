# 0001 — ritueel keeps roots and teaches how; systems that issue every day keep intermediates

**Status:** Accepted
**Date:** 2026-11-13

## Decision

1. Roots and root changes are a separate product, ritueel, kept apart from systems that issue certificates every day (such as sluis) and hold intermediates.
2. The purpose is to help one person or a small team keep a private root and an OpenPGP primary key for years without losing, leaking, misusing or letting it expire. ritueel teaches the model first, then runs each ceremony with the person deciding.

3. One set of ceremonies over three key stores (a key file, a pair of root cards, a cloud key service); the guarantees differ by key store, and ritueel says so.
4. Prefer a key that cannot be copied (root cards, a cloud key); it also avoids the reboot into the offline system.
5. One bundle keeps the roots of a PKI and of OpenPGP together, with what is known about the cards.
6. Requests in, answers out: other systems connect through files, and plans can travel.
7. An opinionated, automated workflow: say what is wanted, read the plan of what is not applied yet, and apply it.

8. Scope is roots of three kinds (X.509 trust anchor, OpenPGP identity, SSH CA), in one model, across key stores.
9. Out of scope: online signing, leaf certificates, secret storage.
10. Staff keys are out of scope. There is no staff-key flow where a company root hands signing to an online certifier, no card helper and no staff proof format. What another system may automate later (signing releases, syncing a person's key to a hosting account) is outside ritueel.
11. A feature that makes a ceremony faster but takes the decision from the person is refused.
12. The holder prepares their own account, roles and PIN. ritueel creates the keys, attests and verifies them; it creates no account and no role, and keeps no PIN that the holder types.
13. What ritueel changes, sends out and prints is decided in [record 0011](0011-publishing-and-what-to-do-after-a-ceremony.md), rule 1. Its work otherwise ends at files: roots, certifications and bindings, trust files, records and a keyring file. Packaging (deb, rpm), publishing anything else and using keys belong to other tools.

14. ritueel and sluis depend on neither each other nor shared code. They exchange only standard formats through a versioned [hand-off contract](/reference/hand-off-contract/), so either side can be replaced.
15. The floor of the contract is PKCS#10 in, X.509 out, in a stated profile that any certificate authority can issue. On the floor the requester's anchors are the CA certificates the operator installed, with no trust sequence and no rollback protection.
16. ritueel's own contract adds the proof of where the key lives, the result file, the reason codes, and the signed root list with its trust sequence.
17. The contract is specified and tested from both sides, with versioning and test vectors; it is the first backlog item. The software-root mode is built first, because the full contract can only be tested with it.

18. ritueel is a teaching product first: the purpose is a smooth and safe experience of managing a root, not the tools. The site is part of the product; it teaches the logic of roots and intermediates, with one guide per procedure and drills on test keys.
19. Opinionated help covers the whole life of a root: where the bundle lives, backup and restore, re-signing and rotating, revocation, card loss and replacement. Each procedure gets a Learn page (why and when), a guide (steps) and a drill.
20. The teaching target is four things from the ground up (how a YubiKey holds keys, passkeys, a KMS key, choosing where a root lives), a glossary, a reference generated from the program, and a "how to verify a release" page that comes with the release candidate, not before.
21. The site compares key stores by what each protects against and costs (software and its backends, YubiKey PIV and OpenPGP card, AWS KMS), recommends devices to buy for testing, and dates each claim.
22. The site publishes only the home page, the Learn path, the demo, the glossary, where it stands (status and roadmap), one page that states the design in brief, "How it works" (an overview of the use cases and two layout pages, in pictures), and the hand-off contract that the requester system reads. Each "How it works" page says that the pictures show the design. Records, guides, tool, reference, principles, research and contributor pages are not published; they are written under docs/ and read in the repository.
23. The allowlist site/published.txt says which pages are published; a page comes back by one line, and nothing is deleted. Old addresses of unpublished pages redirect (302) to their file on GitHub, and links from published pages to unpublished files open that file.
24. The site shows, not only tells: a comic-style "How it works?" sketch of the major use cases (binding subkeys from a YubiKey, signing a PKI intermediate); illustrations of the YubiKey, slots and passkeys; the layout of a root card, a day-to-day card and a server card; the layout of a bundle and of the extra partition on the stick.
25. The pictures are inline SVG that follows the theme of the site, drawn by a figure kit under `site/figures/`.
26. Pages say what is built and mark what is not built as planned. Pages do not call the second card a spare, the custody two-person control, or a replica a second root, and state the accepted limit.
27. The site is judged at two bars: the design phase and the first signed release; in the design phase a newcomer's reading test does not block. Learn is done when someone new to PKI has read every Learn page end to end, their questions are answered on the page, and the comparison page exists.

28. The glossary fixes fifteen words: root, delegated key, holder, requester, key store, ceremony, bundle, history, record, renew, replace, trust files, wanted, not applied yet and apply.
29. A root is what outsiders trust without further proof, of one kind, built from keys in any place; a delegated key is an intermediate certificate key, an OpenPGP subkey or an SSH CA key, and a delegation is a declared name under a root for a key that does daily work.
30. A ceremony is one act, `apply`, confirmed by a person; "yearly ceremony" is a practice, not a command.
31. To renew is to extend the same key; to replace is to make a new key on an event, including the three-year limit.
32. The words card, row and card file are defined on the bundle and cards pages.

33. The milestones are: Learn; M0 Records; M1 Proofs on a rehearsal card; M2 Release candidate; M3 A person's key, stage one; M4 A company's cloud root; M5 First signed release; M6 A company's card roots, then a person's card-born primaries; M7 Afterwards. Dates are not promised, the order is; what each milestone delivers is on the roadmap page. A change to the plan is a pull request to the roadmap page. Milestones are GitHub milestones with area and type labels.
34. M0 (the written design) is the small clean set of records, the page that states the design in brief, the reference pages, the glossary and the teaching pages saying the same thing. M1 comes first of the builds: the passkey proof, the card proofs and the stick test, before the key stores.

## Why

Root custody is rare and costly to get wrong; daily issuing is busy, so the two are kept apart. A reader who does not know why a root is kept apart and guarded makes the expensive mistake faster, so teaching comes first.

## What it costs

- The contract needs work on both sides, and the software-root mode comes first.
- Most pages are read on GitHub, not on the site.

## Roads not taken

- **Root ceremonies inside the system that holds intermediates.** One system, but root custody sits beside the busiest code and the line between rare and daily keys disappears.
- **A hosted service that holds the roots.** Easy to use, but the roots become online and someone must be trusted with every root.
- **Two tools, one for X.509 and one for OpenPGP.** Each is simpler, but create, vouch, overlap, supersede and revoke are one model, and teaching and records would be written twice.
- **A shared library or a private protocol.** Less to specify, but neither side works without the other and other issuing systems are locked out.
- **No floor, the full contract or nothing.** One trust mode everywhere, but ritueel's formats would be required of every CA and a system with intermediates could not be tested without ritueel.
- **ritueel also sets the PIN.** One tool from box to root, but the holder must type the PIN and ritueel would have to hold it.
- **ritueel creates the account and the roles.** One command for a cloud root, but it needs account-creating rights, differs for every organisation and becomes an infrastructure tool.
- **Tools first, teaching as an appendix.** Faster to build, but a reader who does not know why a root is kept apart and guarded makes the expensive mistake faster.
- **Staff keys for a company: a handing over of signing to an online certifier, a card helper and a staff proof format.** It would cover staff, but staff keys are out of scope (rule 10); what the requester system automates later is its own work.
- **Publish every page and put the working material behind a Design entry.** Nothing lost, but the overload stays and pages for what is not built keep contradicting the target.
- **Hold back only the unbuilt pages.** A smaller cut, but many pages remain to drift apart.
- **Mermaid or image files for the pictures.** Simple to write, but an image file cannot follow the light and the dark theme, and Mermaid needs a script that the Content-Security-Policy would have to list.
- **A root as one card's row of three keys.** Fewer rules to change, but outsiders see one trust anchor with two keys and not "two roots"; a root is built from keys (rule 29).
- **One root for each organisation or person, with three faces.** One name, but it brings A and B back as a grid and cannot say a root of one kind with a key on a card and a key in the cloud; one root of each kind was chosen.
- **Place and slot as words of their own.** Complete, but a place is one fact about a key; one sentence in the glossary row "key store" does the work.
- **A glossary of sixteen words.** "Place" and "certification" would have entries and "delegation" would rename "delegated key", but the list grows by a third and one sentence in a row that exists does the same; the list has fifteen words (rule 28).

## Not yet proven or only proposed

None.
