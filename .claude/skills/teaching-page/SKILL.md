---
name: teaching-page
description: Use when writing or rewriting a Learn or Guides page of the ritueel site, or any page that teaches how to run a root, a ceremony or a transition. Covers the reader, sourcing, dating and links.
---

Read "Teaching pages" and "Dated and checkable" in `docs/contributing/pages.md` and follow them. Judge the page against the mission in `docs/contributing/design.md` first: it teaches before any tool, and the person stays in charge. For any name, address or id, also read `docs/contributing/public-content.md`.

Checklist:

- [ ] The reader is new to PKI and OpenPGP but technically capable. Explain the root, not the hash.
- [ ] It starts from the reader's question or pain, in the first paragraph, before the rule.
- [ ] The reason comes before the steps. A guide links the Learn page that holds the reason.
- [ ] Every external fact has a source and an "as of" date. Each claim is labelled READ, MEASURED or UNVERIFIED in the pull request, with its source. Exact quotations and numbers were checked in the source, not in a fetch summary.
- [ ] No UNVERIFIED fact is on the page: it is confirmed, or left out with an issue.
- [ ] It says where it sits in `docs/learn/custody-chain.md` and links the ceremony or guide that carries out what it teaches.
- [ ] A tool or a store that is not built is marked planned, in the first paragraph; a guide never describes a missing command as if it existed.
- [ ] Hardware and price facts give the model, the revision, the price with its currency, the source and the day.
- [ ] A drill says what the learner starts with, what they do and how they know it worked, on test keys.
- [ ] If the page moved or was renamed, `site/public/_redirects` has a 301 line for the old address, and links are updated.
- [ ] Front matter has a `title` and a `description` of 40 to 160 characters; links use site paths with a trailing slash.
- [ ] `devbox run -- just check-rules`, `site-lint` and `site-build` pass; then follow `docs/contributing/workflow.md`.
