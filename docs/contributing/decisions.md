---
title: Decision records
description: How a ritueel decision goes from a proposal issue to an accepted record, who decides, and what every record must keep.
sidebar:
  order: 3
---

A decision record (ADR) says why ritueel is shaped the way it is, what else was weighed, and what follows. The format, the numbering and the status values are in [docs/decisions/README.md](https://github.com/truvity/ritueel/blob/main/docs/decisions/README.md); the process is in [GOVERNANCE.md](https://github.com/truvity/ritueel/blob/main/GOVERNANCE.md). This page is the order of work.

## The maintainer decides

A contributor or an agent presents the options, each with its pros and cons, and a recommendation. It does not pick. The maintainer decides: merging a record with status `Accepted` is the decision.

## From proposal to record

1. **Proposal.** Open an issue with the *Decision proposal* form: the question, the context, the options with pros and cons, and the options you would not take. The form labels it `type:decision`.
2. **Record.** When the direction is clear, copy [the template](https://github.com/truvity/ritueel/blob/main/docs/decisions/0000-template.md) to `docs/decisions/NNNN-short-title-in-kebab-case.md`, with the next free number. Link the proposal issue in the context.
3. **Index.** Add the record to the index table in `docs/decisions/README.md`, with its status. Every record has a row, and every row has a record.
4. **Pages.** The pages that the decision changes follow in the same pull request, or in the next one ([Pages](/contributing/pages/)).
5. **Pull request.** At most five records per pull request. A larger batch is split.

## Accepted means decided

A record is `Accepted` when every part of it is decided. Two kinds of unfinished work differ:

- A **follow-up** verifies or implements the decision and cannot change it: a test at a card, a format page, a matrix of older tool versions. It goes under `## Follow-ups`, one line with its issue, and the record can still be `Accepted`.
- An **open part** is a question whose answer could change the decision. While one exists, the record stays `Proposed`, and the open part is tracked in an issue the record links.

When in doubt, ask whether any result of the task would make you rewrite the Decision section. If it could, the part is open.

## Keep it short

A record holds the choice, the reasons and the roads not taken. Measurements are cited from a dated page under `docs/research/` ([Spikes and research](/contributing/research/)); formats, file layouts and command tables live under `docs/reference/`. A record of about one screen of decision is the aim.

## Roads not taken

Every record keeps the options it did not take: one line each, saying what the option would have given, what it costs, and why it lost. Git keeps the text that was merged, not the reasoning that was dropped, so this part is required and is never cut to make a record shorter.

## Changing a record

- **Until the first release (design phase),** a record is rewritten in place, merged with another, renumbered or removed, so that the set stays small and current. The earlier text stays in git history. When a record's address changes, add a line to `site/public/_redirects` from the old address to the new one, and update every link to it.
- **From the first release on,** records are append-only. A changed mind gets a new record that supersedes the old one, and the old status line says so (`Superseded by NNNN`, or `Accepted; amended by NNNN`). Typos and links may be fixed in place.

## What CI checks

CI checks the file name, the required sections, the status value, the one-line roads not taken, that every follow-up links its issue, that an `Accepted` record has no open part, and the index rows; run `just check-decisions`, then `just check`, before you push. Passing it is necessary, not sufficient: the maintainer reviews the reasoning.
