---
title: How we design
description: The order of work for a ritueel design question, when to ask the maintainer, and the mission that every new page and feature is judged against.
sidebar:
  order: 4
---

This page is the design paradigm: how a question is answered before it becomes a decision record, a page or code. The format of a record is in [Decision records](/contributing/decisions/); the principles it applies are on [Design principles](/principles/).

## The mission is the test

[ADR 0007](/decisions/0007-ritueel-teaches-and-its-tools-simplify-the-ceremonies/) sets the mission: ritueel teaches people to run a PKI root and an OpenPGP master key safely. The tools only simplify the rituals, and the person stays in charge. Judge every new page, tool or option against it:

1. **Does it teach first?** The reader meets the reason before the command, and a Learn page exists before a guide or a tool depends on it.
2. **Does the tool only simplify a ritual** a careful person could do by hand? A tool that decides for the person, or hides a step they should understand, fails.
3. **Does the person stay in charge?** Every irreversible step is confirmed by the person, in the terminal or by touch, never by a click alone.

A change that fails one of the three is reworked or dropped, or it goes to the maintainer as a conflict ([below](#ask-only-real-conflicts)).

## Principles first

Check each question against the [principles](/principles/) and the accepted records before anything else. If they settle it, write the answer and cite the principle or the record; do not ask. The custody vocabulary comes from them and is not restated here: a key is born in its store and never leaves it (principle 1), redundancy answers loss and not compromise (2), and a claim is verified and never trusted (4). Roots are ritueel's; a system like [sluis](https://sluis.id) holds intermediates only.

## Ask only real conflicts

Ask the maintainer when:

- two principles pull apart;
- a principle does not reach the question;
- a product, legal or money fact is needed that nobody in the repository can know.

Each question comes with the options, the pros and cons of each, and a recommendation. A question that a principle already answers is not a question.

## Generalise before detail

For a milestone or a large topic, first list the high-level questions: topology, trust and custody, data ownership, failure, operations, compatibility. Mark each **settled**, **partly** or **open**. Only then map records, issues and pages under them. A question that several milestones share is answered once, in one place.

## Nothing without a consumer

A store, a backend, a command or an option arrives with its first real installation or caller (principle 8). Until then it is a line marked "planned" and an issue, not code, and not a page that promises it ([What is built](/contributing/pages/#what-is-built)).

## Milestones are an order

The [roadmap](/roadmap/) is an order, not a wish list: finish the design of a milestone before the code for it starts, and build in the order the roadmap gives. A record or page that depends on a later milestone says so.

## Records and issues stay in step

- Every requirement a record or page states names an open issue in the right milestone.
- Every issue a page or record names exists.
- The roadmap matches the board.

`just check-decisions` holds what it can. The rest is a bookkeeping pass at the end of each design batch: read the records you changed, and open or fix the issue behind each.

## Where the rest lives

One rule lives in one place; these are the owners.

| Rule | Owner |
|---|---|
| Roads not taken; a rule stated once; records during design and after the first release | [Decision records](/contributing/decisions/) |
| Measure, date and label a claim READ, MEASURED or UNVERIFIED | [Dated and checkable](/contributing/pages/#dated-and-checkable) |
| What a spike or research page holds | [Spikes and research](/contributing/research/) |
| How a Learn or Guides page is written | [Teaching pages](/contributing/pages/#teaching-pages) |
