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
| `just check` | Everything a pull request must pass: `check-rules`, `site-check` and `site-workers` |
| `just check-rules` | The repository rules, below, after a self-test of the checks |
| `just check-decisions` | The decision records: file names, the template's sections, the status, the index rows |
| `just check-public` | Content that must not be public, in every tracked text file |
| `just check-yaml-ext` | YAML files use `.yaml` |
| `just check-vectors` | The test vectors in `testdata/`: the manifest names every tracked file, every file it names is tracked, and the digests match |
| `just check-agent-links` | `AGENTS.md` exists, `CLAUDE.md` imports it, and every path that they and the skills point to exists |
| `just site-check` | The site: `site-lint`, `site-build` and `site-links` |
| `just site-lint` | Page descriptions of 40 to 160 characters |
| `just site-build` | A strict site build: no warning and no broken internal link, and the built output has what it must |
| `just site-links` | Every link in the built site, internal and external |
| `just site-workers` | `wrangler deploy --dry-run` on the build: uploads nothing, needs no Cloudflare credential |

Read the recipe, and the workflow in `.github/workflows/` that calls it, to know what CI really runs. Build and test recipes for the code arrive with the code, and this table grows with them.

## The site

The site is built from `docs/` and `site/` with Astro Starlight, and every page is prerendered into static files in `site/dist`. `docs/` is linked into the site at `site/src/content/docs`, so a page reads the same on GitHub as on ritueel.id. The decision records are indexed by the site, not rendered as ordinary pages.

- `just site-dev` serves it on `http://localhost:4321` with live reload.
- `just site-build` makes the strict build, the same build CI checks.
- `site/public/_headers` holds the Content-Security-Policy and the other security headers. Inline scripts are listed by hash, and `site/scripts/check-csp.mjs` (run by `check-built.sh`) fails when a page runs one that is not listed, or a listed one is gone, and prints the hashes to paste.
- **Where it is served.** `site/wrangler.jsonc` names the Worker `ritueel-site` and serves `site/dist` as static assets. It declares no routes, no KV and no account, and `workers_dev` and `preview_urls` are off for good: Wrangler turns both on by default, and each publishes a hostname that contains the operator's account subdomain. There is no preview per pull request for that reason; a pull request is judged by `just site-check` and `just site-workers` in CI, and you can serve the same build with `yarn wrangler dev` in `site/`.
- **The deploy** is the `deploy` job of `.github/workflows/site.yaml`. It runs on a push to `main` and on a manual run from `main`, after the `build` job has passed, and never on a pull request. It rebuilds the site, then runs `just site-deploy`, which is `yarn wrangler deploy` in `site/`. No build artifact is uploaded to GitHub. The job runs in the GitHub environment `cloudflare`, which allows deployments from `main` only and has no required reviewers. It holds two secrets: `CLOUDFLARE_API_TOKEN`, a token limited to deploying this one Worker, and `CLOUDFLARE_ACCOUNT_ID`. The job gives each secret to the one step that needs it. While the token is not set, the job says so in a notice and skips, and `main` stays green. The maintainer creates and rotates the token; a deploy that fails with an authentication error is the sign that it has expired.
- The Worker, its routes and the domain are declared in the operator's own infrastructure code, outside this repository. The deploy uploads a new version of the Worker and changes none of them.

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
