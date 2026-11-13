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
2. **Record.** When the direction is clear, copy [the template](https://github.com/truvity/ritueel/blob/main/docs/decisions/0000-template.md) to `docs/decisions/NNNN-short-title-in-kebab-case.md`, with the next free number. Link the proposal issue in the *Why* section.
3. **Index.** Add the record to the index table in `docs/decisions/README.md`, with its status. Every record has a row, and every row has a record.
4. **Pages.** The pages that the decision changes follow in the same pull request, or in the next one ([Pages](/contributing/pages/)).
5. **Pull request.** At most five records per pull request. A larger batch is split.

## Accepted means decided

The numbered sentences of an `Accepted` record are decided. Two kinds of unfinished work sit outside them, in the section `## Not yet proven or only proposed`, one line each with its issue:

- **Not yet proven.** The sentence is decided and waits for a test on a card or an account, a format page, or a matrix of older tool versions. The line starts `**Not yet proven.**`, and the record can still be `Accepted`.
- **Proposed.** The point is not decided. The line starts `**Proposed.**`, and the record links the issue that tracks it.

When in doubt, ask whether any result of the task would make you rewrite a numbered sentence. If it could, move that sentence into this section: a numbered sentence is never a guess.

## Keep it short

A record has the shape of [the template](https://github.com/truvity/ritueel/blob/main/docs/decisions/0000-template.md): numbered sentences in *Decision*, then *Why*, *What it costs*, *Roads not taken* and *Not yet proven or only proposed*. The aim is 900 words for *Decision*, *Why* and *What it costs* together. *Decision* has no sub-headings, tables or code blocks: an exact format (a slot table, file members, a byte layout, a flag list) is only named and linked to its page under `docs/reference/`. Measurements are cited from a dated page under `docs/research/` ([Spikes and research](/contributing/research/)).

## State each rule once

A rule lives in one place: in the record that decides it, or in a reference page with test vectors that the record links. Do not restate it in a second record or a page; link to it. Two statements of one rule drift apart, and the reader cannot tell which is true. When a record needs a rule from another, name the record and the section.

Judge a proposal against the mission first ([How we design](/contributing/design/#the-mission-is-the-test)): a record that makes a tool decide for the person, or skips the teaching, is reworked before it is written.

## Roads not taken

Every record keeps the options it did not take: one line each, saying what the option would have given, what it costs, and why it lost. Git keeps the text that was merged, not the reasoning that was dropped, so this part is required and is never cut to make a record shorter. The same goes for a research page and a reference page that settles a choice.

## Changing a record

- **Until the first release (design phase),** a record is rewritten in place, merged with another, renumbered or removed, so that the set stays small and current. The earlier text stays in git history. A rule keeps its number: a later change adds a rule at the end of the list or marks a rule as removed, and does not renumber the others, so that a citation by number stays true. A record that changes an earlier decision says so in its own rule, and the earlier record is edited to the current state; a record never carries a history section. Records have no page on the site, so a moved record needs no redirect line. In the same pull request, keep [the design in brief](/design/) and the glossary in step with the records they link, and update every link to the record. Do not amend a record with a note that the design phase would rather absorb.
- **From the first release on,** records are append-only. A changed mind gets a new record that supersedes the old one, and the old status line says so (`Superseded by NNNN`, or `Accepted; amended by NNNN`). The decision is never edited; typos and links may be fixed in place. A number is never reused.

The first release is the line between the two. Which side a record is on is the maintainer's to say when it is not clear.

## What CI checks

CI checks the file name, the required sections in order, the status value, that *Decision* is a numbered list with no heading, table or code block, the one-line roads not taken, that every line of *Not yet proven or only proposed* carries its label and links its issue, that there is no *Replaces* section (a record states the design as it is, with no history), that an `Accepted` record has no open part, the size (a warning above 1,100 words for the three core sections or 1,800 for the whole record), and the index rows; run `just check-decisions`, then `just check`, before you push. Passing it is necessary, not sufficient: the maintainer reviews the reasoning.
