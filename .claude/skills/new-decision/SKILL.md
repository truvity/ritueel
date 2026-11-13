---
name: new-decision
description: Use when creating, rewriting or changing the status of an architecture decision record (ADR) in docs/decisions/, or turning a decision proposal issue into a record.
---

Read `docs/contributing/decisions.md` and follow it. It points to `docs/decisions/README.md` for the format and to `docs/contributing/pages.md` for the prose; read both. Settle what the principles settle (`docs/contributing/design.md`) and ask the maintainer only a real conflict.

Checklist, each step as the pages describe it:

- [ ] The proposal issue exists and is linked.
- [ ] The record is a copy of `docs/decisions/0000-template.md` with the next free number.
- [ ] Every section is filled: *Decision* as numbered sentences (formats only named and linked), *Why*, *What it costs*, the roads not taken each with the reason it lost (git does not keep that part), and *Not yet proven or only proposed*. The aim is 900 words for the first three together.
- [ ] It passes the mission test of `docs/contributing/design.md`: it teaches first, and the person stays in charge.
- [ ] Each rule is stated once, here or in a reference page it links. A rule that another record or page already states is linked, not repeated.
- [ ] Before the first release the record may be rewritten, merged or renumbered; records have no site address, so there is no redirect line; the design page (`docs/design.md`) and the glossary links are kept in step in the same pull request. After the first release it is append-only: supersede, never edit the decision.
- [ ] The status is right for what is decided; a point that is not decided, or decided but not yet proven, sits in *Not yet proven or only proposed* with its label and its issue.
- [ ] The index in `docs/decisions/README.md` has the row.
- [ ] The pages that follow are added or named.
- [ ] The pull request holds no more records than the page allows.
- [ ] `devbox run -- just check-decisions`, then `devbox run -- just check`, pass; then follow `docs/contributing/workflow.md`.
