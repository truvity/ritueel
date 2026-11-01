---
name: new-decision
description: Use when creating, rewriting or changing the status of an architecture decision record (ADR) in docs/decisions/, or turning a decision proposal issue into a record.
---

Read `docs/contributing/decisions.md` and follow it. It points to `docs/decisions/README.md` for the format and to `docs/contributing/pages.md` for the prose; read both.

Checklist, each step as the pages describe it:

- [ ] The proposal issue exists and is linked.
- [ ] The record is a copy of `docs/decisions/0000-template.md` with the next free number.
- [ ] Every section is filled, including the roads not taken.
- [ ] The status is right for what is decided; open parts keep it `Proposed`, follow-ups are listed with their issue.
- [ ] The index in `docs/decisions/README.md` has the row.
- [ ] The pages that follow are added or named.
- [ ] The pull request holds no more records than the page allows.
- [ ] `devbox run -- just check-decisions`, then `devbox run -- just check`, pass; then follow `docs/contributing/workflow.md`.
