---
name: new-decision
description: Use when creating, rewriting or changing the status of an architecture decision record (ADR) in docs/decisions/, or turning a decision proposal issue into a record.
---

Read `docs/contributing/decisions.md` and follow it. It points to `docs/decisions/README.md` for the format and to `docs/contributing/pages.md` for the prose; read both. Settle what the principles settle (`docs/contributing/design.md`) and ask the maintainer only a real conflict.

Checklist, each step as the pages describe it:

- [ ] The proposal issue exists and is linked.
- [ ] The record is a copy of `docs/decisions/0000-template.md` with the next free number.
- [ ] Every section is filled, including the roads not taken, each with the reason it lost. Git does not keep that part.
- [ ] It passes the mission test of `docs/contributing/design.md`: it teaches first, and the person stays in charge.
- [ ] Each rule is stated once, here or in a reference page it links. A rule that another record or page already states is linked, not repeated.
- [ ] Before the first release the record may be rewritten, merged or renumbered; a moved address has a 301 line in `site/public/_redirects` and updated links. After the first release it is append-only: supersede, never edit the decision.
- [ ] The status is right for what is decided; open parts keep it `Proposed`, follow-ups are listed with their issue.
- [ ] The index in `docs/decisions/README.md` has the row.
- [ ] The pages that follow are added or named.
- [ ] The pull request holds no more records than the page allows.
- [ ] `devbox run -- just check-decisions`, then `devbox run -- just check`, pass; then follow `docs/contributing/workflow.md`.
