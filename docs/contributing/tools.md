---
title: Tools, checks and verification
description: Where the ritueel tools come from, which recipe runs a check, how to run commands from an agent shell, and when a result counts as verified.
sidebar:
  order: 2
---

## Tools come from devbox

Every tool the repository uses is pinned in `devbox.json`, at an exact version, and locked in `devbox.lock`. Run commands inside the devbox environment: `devbox shell`, or one command at a time with `devbox run -- <command>`. When `devbox.json` changes, `devbox.lock` changes in the same pull request.

- Pin exact versions, of tools and of the standards they implement. A range is not a pin.
- Prefer a pinned release binary over a container for a tool.
- Do not use testcontainers.

## Standards first

Follow specifications and standards. Where a standard exists for a protocol, a format or an algorithm, do not invent one; a deliberate deviation from a standard needs a [decision record](/contributing/decisions/). Pin the version of the standard you follow, as you pin the version of a tool. The formats ritueel works with are X.509 (RFC 5280) and PKCS#10 (RFC 2986) for certificates and requests, OpenPGP (RFC 9580) for keys and signatures, and the attestation certificates that key stores issue.

## Run the recipe, not the tool

The `Justfile` holds the recipes, and CI runs the same recipes. Run the recipe, not the bare tool underneath it: the recipe carries the flags, the order and the extra checks that CI applies.

| Recipe | What it checks |
|---|---|
| `just check` | Everything a pull request must pass: `check-rules` and, once the site is in, `site-check` |
| `just check-rules` | The repository rules, below, after a self-test of the checks |
| `just check-decisions` | The decision records: file names, the template's sections, the status, the index rows |
| `just check-public` | Content that must not be public, in every tracked text file |
| `just check-yaml-ext` | YAML files use `.yaml` |
| `just check-agent-links` | `AGENTS.md` exists, `CLAUDE.md` imports it, and every path that they and the skills point to exists |

Read the recipe, and the workflow in `.github/workflows/` that calls it, to know what CI really runs. Build and test recipes for the code arrive with the code, and this table grows with them.

## Commands from an agent shell

An AI agent's shell may reset its working directory between calls, so a `cd` in one call is gone in the next. Use absolute paths:

- `git -C /abs/path/to/worktree status`, `go -C /abs/path ...`;
- or `cd /abs/path && devbox run -- just check` as one command.

Never run `go mod init` or `go get` outside the repository: in the wrong directory they create or change a module that is not this one.

## Hardware tokens and cloud keys

Tests that use a hardware token, a smart card, a security key or a cloud key use dedicated test devices and test keys only, never a device or a key someone uses for real work. Select the test device by its serial number, never by "the first one found", and reset it to its factory state when the test is done. Cloud tests use a dedicated test account and keys that are deleted afterwards. A serial number, an account id or a key id is not written into the repository.

## When a result counts

- Measure before you fix. Find the cause in numbers or in a log line before you change anything.
- Read what a tool printed, not only its exit code. A tool can exit 0 and say it did nothing.
- A green check that tests nothing is not green. A check that finds nothing to check, an empty list of files or an empty sweep, fails rather than passes.
- Say what you ran, with the command and its result. Plausible output that nobody ran is not a contribution.
