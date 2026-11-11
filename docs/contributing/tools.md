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
| `just check` | Everything a pull request must pass: `check-rules`, `site-check`, `site-workers` and `site-render` |
| `just check-rules` | The repository rules, below, after a self-test of the checks |
| `just check-decisions` | The decision records: file names, the template's sections, the status, the index rows |
| `just check-public` | Content that must not be public, in every tracked text file |
| `just check-yaml-ext` | YAML files use `.yaml` |
| `just check-vectors` | The test vectors in `testdata/`: the manifest names every tracked file, every file it names is tracked, and the digests match |
| `just check-mdx-pages` | Markdown everywhere: an `.mdx` file under `docs/` imports a component and places it ([Page format](/contributing/pages/#page-format)) |
| `just check-agent-links` | `AGENTS.md` exists, `CLAUDE.md` imports it, and every path that they and the skills point to exists |
| `just site-check` | The site: `site-lint`, `site-build` and `site-links` |
| `just site-lint` | Page descriptions of 40 to 160 characters |
| `just site-build` | A strict site build: no warning and no broken internal link, and the built output has what it must |
| `just site-links` | Every link in the built site, internal and external |
| `just site-test-worker` | The Worker's tests (`site/scripts/check-worker.mjs`): the GitHub App's token request, the KV write rules, a refresh and every route, with GitHub and KV faked |
| `just site-workers` | `just site-test-worker`, then `wrangler deploy --dry-run` on the build: bundles the Worker, uploads nothing, needs no Cloudflare credential |
| `just site-render` | The status page in headless Chrome (`site/scripts/check-render.mjs`): the live script against a stand-in for the Worker, light and dark, at 1440, 390 and 375 px. Needs `just site-build` |

Read the recipe, and the workflow in `.github/workflows/` that calls it, to know what CI really runs. Build and test recipes for the code arrive with the code, and this table grows with them.

## The site

The site is built from `docs/` and `site/` with Astro Starlight, and every page is prerendered into static files in `site/dist`. `docs/` is linked into the site at `site/src/content/docs`, so a page reads the same on GitHub as on ritueel.id. The decision records are indexed by the site, not rendered as ordinary pages.

- `just site-dev` serves it on `http://localhost:4321` with live reload.
- `just site-build` makes the strict build, the same build CI checks.
- `site/public/_headers` holds the Content-Security-Policy and the other security headers. Inline scripts are listed by hash, and `site/scripts/check-csp.mjs` (run by `check-built.sh`) fails when a page runs one that is not listed, or a listed one is gone, and prints the hashes to paste. The site loads nothing from outside except Cloudflare Web Analytics, which the CDN injects at the edge (privacy-first, no cookies, pinned by an integrity hash): `script-src` names `https://static.cloudflareinsights.com` and `connect-src` names `https://cloudflareinsights.com`, and the check fails on any other external origin.
- **The project status page** (`/status/`, `site/src/pages/status.astro`) is static HTML with a live part. The decision records by status, the reference pages and the lines of code are counted from the repository by `site/src/lib-status.ts` at build time, which the home page's status line uses too; they never change after the build. The milestones are the rows of the table in `docs/roadmap.md`, joined with the issues by `site/src/lib-milestones.ts`. The issues per milestone and the latest run of each workflow on `main` are the live parts, drawn by one renderer (`site/src/lib-status-html.ts`) in two places: the build writes a snapshot of them into the page (the issues come from the GitHub REST API, `site/src/lib-github-rest.ts`, read with the token in `GITHUB_TOKEN`; CI passes the workflow's read-only token), and the Worker draws the live version. Without a token, or when GitHub does not answer, the build still passes and the snapshot says the issue figures are unavailable.
- **The live status API** is the Worker's code in `site/src/worker/`, a plain module that `wrangler deploy` bundles; it has no Astro server in it. `site/wrangler.jsonc` runs it first for `/api/*` only, so a static page never invokes it, and gives it a cron every 15 minutes. The cron is the only writer: it mints an installation token of a read-only GitHub App (issues, Actions and metadata, each read), reads the issues and milestones over REST and the workflow runs on `main` with a conditional request, and writes one KV document, `board`, only when the content changed or the stored copy is more than an hour old (at most 100 writes a day). There is no webhook, so the page is as live as the cron is frequent; a webhook is a later addition if 15 minutes proves too slow. Two routes, both read-only: `GET /api/status` is the data as JSON (a minute of cache; 503 until the first refresh), and `GET /api/status/live/` is the live parts as an HTML fragment. The page's script, `site/src/scripts/status-live.ts`, is bundled into a file of this site, so the Content-Security-Policy needs no new entry: it fetches the fragment and swaps each part in, and on any failure the snapshot stays and a note above it says so. The Worker joins the document with `/data/status.json`, the roadmap as the build read it, from its own static assets. `just site-test-worker` (part of `just site-workers`) runs `site/scripts/check-worker.mjs`: the App's token request, the KV write rules, a refresh and every route against fakes, with no network and no credential.
- **Where it is served.** `site/wrangler.jsonc` names the Worker `ritueel-site`, serves `site/dist` as static assets and names the Worker's code, its cron and one KV binding, `STATUS`, with a placeholder id. It declares no routes and no account, and `workers_dev` and `preview_urls` are off for good: Wrangler turns both on by default, and each publishes a hostname that contains the operator's account subdomain. There is no preview per pull request for that reason; a pull request is judged by `just site-check` and `just site-workers` in CI, and you can serve the same build with `yarn wrangler dev` in `site/`. Never widen `assets.run_worker_first` beyond `/api/*`, and never turn on Workers Cache: either would put the whole site under the Free plan's daily request limit.
- **The deploy** is the `deploy` job of `.github/workflows/site.yaml`. It runs on a push to `main` and on a manual run from `main`, after the `build` job has passed, and never on a pull request. It rebuilds the site, then runs `just site-deploy`, which writes `site/wrangler.deploy.json` (`site/scripts/deploy-config.mjs`: `wrangler.jsonc` with the KV id from `RITUEEL_STATUS_KV_ID`, so that the id is never in the repository) and runs `yarn wrangler deploy` on it, with the Worker's secrets in a file that only that step can read (`--secrets-file`). No build artifact is uploaded to GitHub. The job runs in the GitHub environment `cloudflare`, which allows deployments from `main` only and has no required reviewers. It holds `CLOUDFLARE_API_TOKEN` (a token limited to deploying this one Worker), `CLOUDFLARE_ACCOUNT_ID`, `RITUEEL_STATUS_KV_ID`, `RITUEEL_STATUS_APP_KEY` (the private key of the GitHub App) and the variable `RITUEEL_STATUS_APP_CLIENT_ID`. The job gives each to the one step that needs it. While the token is not set, the job says so in a notice and skips, and `main` stays green; once it is set, a missing one of the others fails the job in seconds, naming it. The maintainer creates and rotates the token; a deploy that fails with an authentication error is the sign that it has expired. Nobody runs `wrangler secret put`: rotating an App key is changing the secret in GitHub and running the workflow.
- The Worker, its KV namespace, its routes, the domain and the GitHub App are declared in the operator's own infrastructure code and settings, outside this repository. The deploy uploads a new version of the Worker and its two secrets, and changes none of them.

## How a consumer gets ritueel

The first consumer is the test harness of a system that holds intermediates, such as [sluis](https://sluis.id), which runs ritueel's software-root mode in its CI ([principle 8](/principles/#the-principles)). It needs a build it can pin. Not built yet: the release workflow comes with the Go module ([issue #10](https://github.com/truvity/ritueel/issues/10)).

- **What a release is.** A tag `vX.Y.Z` on `main`. GoReleaser (version 2) builds the binary for Linux and macOS, on amd64 and arm64, into one `.tar.gz` for each platform, and writes `SHA256SUMS` with the digest of each. The files go on the repository's GitHub Releases page.
- **Checksums only, before the gate.** No release is signed until the project's root is adopted and drilled ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#no-signed-release-before-the-gate)). Until the first signed release (M5) a consumer's trust in a build is the digest it pinned, not a signature. From M5 the proof is `SHA256SUMS` signed by a release subkey that the project's root binds, with a keyless signature beside it ([ADR 0006](/decisions/0006-release-keys-and-the-keyring-package/#ritueels-own-releases)).
- **How a consumer pins it.** It records the version and the SHA-256 of the archive for each platform it runs on in its own repository, downloads the archive from the release, compares the digest before it unpacks, and refuses a mismatch. A new version is a reviewed change of both. `ritueel version` prints the version and the commit, so a log shows which build ran.
- **No container image and no packages yet.** A `.deb` or `.rpm` of ritueel waits for a user beyond the test harness, and will be signed once the gate is passed.

## Commands from an agent shell

An AI agent's shell may reset its working directory between calls, so a `cd` in one call is gone in the next. Use absolute paths:

- `git -C /abs/path/to/worktree status`, `go -C /abs/path ...`;
- or `cd /abs/path && devbox run -- just check` as one command.

Never run `go mod init` or `go get` outside the repository: in the wrong directory they create or change a module that is not this one.

## Local work

- **Work in your own place.** Use a fresh clone or a worktree under your scratch area ([Branches and pull requests](/contributing/workflow/#one-change-one-worktree-one-branch)). Never work inside someone else's checkout, and do not `cd` into it.
- **Run the narrow recipes,** `just check-rules`, `just site-lint` and `just site-build`, and leave the rest to GitHub CI, which runs the full gate on every pull request. Say which you ran.
- **If `just` is not on `PATH`,** run `devbox run -c <dir> -- just <recipe>`, with `<dir>` the absolute path of the clone.
- **If `yarn` fails with `EXDEV`** in a scratch area, set `YARN_GLOBAL_FOLDER` to a folder on the same filesystem as the clone.
- **Do not print a token, a password or a secret.** Read a credential file when the command runs; do not echo it, and do not paste its value into a command line you show.
- **A deletion that a safety check refuses is left to the maintainer,** with the exact command in your report ([AI agents](/contributing/agents/#safety-tooling)).

## Hardware tokens and cloud keys

Tests that use a hardware token, a smart card, a security key or a cloud key use dedicated test devices and test keys only, never a device or a key someone uses for real work. Select the test device by its serial number, never by "the first one found", and reset it to its factory state when the test is done. Cloud tests use a dedicated test account and keys that are deleted afterwards. A serial number, an account id or a key id is not written into the repository.

## When a result counts

- Measure before you fix. Find the cause in numbers or in a log line before you change anything.
- Read what a tool printed, not only its exit code. A tool can exit 0 and say it did nothing.
- A green check that tests nothing is not green. A check that finds nothing to check, an empty list of files or an empty sweep, fails rather than passes.
- Say what you ran, with the command and its result. Plausible output that nobody ran is not a contribution.
