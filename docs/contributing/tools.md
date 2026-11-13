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
| `just check` | Everything a pull request must pass: `check-rules`, `site-check`, `site-workers`, `site-render`, `proto-check`, `ui-lint`, `ui-test`, `ui-e2e` and `go-check` |
| `just check-rules` | The repository rules, below, after a self-test of the checks |
| `just check-decisions` | The decision records: file names, the template's sections, the numbered decision, the size, the status, the index rows |
| `just check-record-refs` | Every `rule N` that cites a decision record names a record and a rule that exist; a bare number resolves only inside its own record or by a page's declared default |
| `just check-public` | Content that must not be public, in every tracked text file |
| `just check-yaml-ext` | YAML files use `.yaml` |
| `just check-vectors` | The test vectors in `testdata/`: the manifest names every tracked file, every file it names is tracked, and the digests match |
| `just check-mdx-pages` | Markdown everywhere: an `.mdx` file under `docs/` imports a component and places it ([Page format](/contributing/pages/#page-format)) |
| `just check-agent-links` | `AGENTS.md` exists, `CLAUDE.md` imports it, and every path that they and the skills point to exists |
| `just site-check` | The site: `site-lint`, `site-build` and `site-links` |
| `just site-lint` | Page descriptions of 40 to 160 characters, the redirect block, and the tests of the allowlist and the link rewrite |
| `just site-redirects` | Rewrite the generated redirect lines of `site/public/_redirects` from `site/published.txt` |
| `just site-build` | A strict site build, after `just ui-demo`: no warning and no broken internal link, and the built output has what it must, the demo included |
| `just site-links` | Every link in the built site, internal and external |
| `just site-test-worker` | The Worker's tests (`site/scripts/check-worker.mjs`): the GitHub App's token request, the KV write rules, a refresh and every route, with GitHub and KV faked |
| `just site-workers` | `just site-test-worker`, then `wrangler deploy --dry-run` on the build: bundles the Worker, uploads nothing, needs no Cloudflare credential |
| `just site-render` | The status page in headless Chrome (`site/scripts/check-render.mjs`): the live script against a stand-in for the Worker, light and dark, at 1440, 390 and 375 px. Needs `just site-build` |
| `just ui-install` | Installs the local page's dependencies from `ui/package-lock.json` |
| `just ui-lint` | The page's TypeScript (strict) and its safety scan: no `innerHTML`, `eval`, `fetch` or remote URL, no text under 12 px |
| `just ui-test` | The page's tests (vitest): the safety scan, the text rule, every screen with hostile text, the demo transport, the contract, the scenes, the routes, and that every site link in the demo is a page of the site, with its anchor a heading of that page (`ui/src/links.test.ts`) |
| `just ui-build` | Both builds of the page, the demo (base `/demo/`) and the real one, and what each JavaScript bundle must and must not hold |
| `just ui-demo` | The demo for the site: the page in demo mode, base path `/demo/`, built into `site/public/demo/` (a build product, not committed). `site-build` runs it first |
| `just ui-e2e` | The page in headless Chrome, served under the site's own Content-Security-Policy; fails on a console error or a policy violation. Needs Chrome or Chromium |
| `just proto-lint` | `buf lint` of `proto/`, the page's API |
| `just proto-gen` | Lints, then regenerates the TypeScript in `ui/src/gen/` |
| `just proto-check` | `proto-gen` must leave no difference: the committed `ui/src/gen/` is what the generator makes |
| `just go-check` | Everything a pull request must pass for the Go code: `go-fmt`, `go-tidy`, `go-verify`, `go-vet`, `go-lint`, `go-test` and `go-build`, the cheap checks first. It does not run `go-vuln` |
| `just go-fmt` | `gofmt -s` finds nothing to change in the Go files of `cmd/`, `internal/` and `tools/`. It fails when it finds no Go file |
| `just go-vet` | `go vet` on the Go packages, built without cgo |
| `just go-lint` | `golangci-lint config verify`, then `golangci-lint run`, with the rules of `.golangci.yaml` |
| `just go-tidy` | `go.mod` and `go.sum` are what `go mod tidy` would write |
| `just go-verify` | Downloads the modules, then `go mod verify` checks each one against `go.sum` |
| `just go-test` | The unit tests. No network, no device, no cloud key |
| `just go-build` | The release build into `bin/ritueel`, then three checks: the file is a static Linux executable (`tools/elfcheck`), `ritueel version` exits 0, and no arguments exit 2 |
| `just go-vuln` | `govulncheck`: known vulnerabilities in what the module imports. Run by `security.yaml`, not by `go-check` |

Read the recipe, and the workflow in `.github/workflows/` that calls it, to know what CI really runs. The release workflow is not built yet, and this table grows with it.

## The Go code

The Go code is the program `ritueel`. [The first version's commands](/reference/cli/#the-first-versions-commands) say what it must do. Run the recipes of the table above inside the devbox environment. Start with `just go-check`.

### Pins and the module

- `devbox.json` pins Go (`go`), the linter (`golangci-lint`) and the vulnerability scanner (`govulncheck`) at exact versions. It also sets `CGO_ENABLED=0`, so the program is a static executable.
- `go.mod` has a `go` line that is the pinned Go version, and it has no `toolchain` line. The build and the tests use only the Go that devbox pins: `devbox.json` sets `GOTOOLCHAIN=local`, so a newer `go` line in a `go.mod` makes the `go` command stop, and it does not download another Go. `devbox.json` also sets `GOFLAGS=-mod=readonly`, so a build never changes `go.mod`.
- The module path is `ritueel.id/ritueel`.
- There is no `vendor/` folder. `go.sum` is committed. `go-verify` checks the downloaded modules against it, and `go-tidy` fails when `go.mod` or `go.sum` is not what `go mod tidy` writes.

### The layout

| Folder | What it holds |
|---|---|
| `cmd/ritueel/` | The program. `main.go` builds the environment from the real streams, calls `cli.Run` and exits. It does nothing else |
| `internal/` | The packages: `cli` (the command line, the exit codes, the JSON output) and `buildinfo` (the version and the commit) |
| `tools/` | Small programs that run beside the build. `tools/elfcheck` checks that a file is a static Linux executable. They are not part of the release |

The recipes name the Go folders (`./cmd/... ./internal/... ./tools/...`) and do not use `./...`. A bare `./...` would also walk the Go files that npm packages ship inside `ui/node_modules` and `site/node_modules`.

### What the linter enforces

`.golangci.yaml` holds the rules, and `go-lint` runs them on every pull request. You meet these first:

- **Only `cmd/ritueel/main.go` exits and holds the real output streams.** `os.Exit`, `fmt.Print`, `fmt.Printf`, `fmt.Println`, `os.Stdout` and `os.Stderr` are refused in all other code. Write to the stdout or stderr writer you were given. Test files and the programs of `tools/` are exempt.
- **A command returns an error that carries its exit code.** The linter does not check this; the code follows it. A command returns an error of the types in `internal/cli/exit.go` (`UsageError`, `Refusal`, `BackendRefusal`, `NotConfirmed`) or any other error, which ends with code 1.
- **No `net/http` in code that is not a test.** Most commands run offline. A command that needs the network lives in its own package, and that package replaces this rule with one that is limited to its path, in the same pull request.
- **Some libraries are not used.** The linter refuses them and names what to use in their place (table below).
- **An exported name has a comment** (`revive`, rule `exported`).

| Instead of | Use |
|---|---|
| `github.com/spf13/cobra`, `github.com/urfave/cli/v2` | `github.com/urfave/cli/v3` |
| `github.com/spf13/viper`, `github.com/knadh/koanf` | Flags and named files, no configuration mapper |
| `github.com/samber/do`, `go.uber.org/fx`, `github.com/google/wire` | Build the parts in `main` and pass them as arguments |
| `gopkg.in/yaml.v2`, `gopkg.in/yaml.v3` | `go.yaml.in/yaml/v3` |
| `github.com/pkg/errors` | The standard library, with `%w` |

The other linters are the standard set (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`) with `depguard`, `errorlint`, `forbidigo`, `gocritic`, `misspell`, `revive` and `usetesting`. `gofmt` and `goimports` format the files.

### The command line

- The command line is built with `github.com/urfave/cli/v3`, at one exact version in `go.mod`.
- The exit codes and the JSON object are those of [the command reference](/reference/cli/#exit-codes). The code and the reference change together, in one pull request.
- A command is tested in process: call `cli.Run` with buffers for the streams and a fixed build, and read the exit code and both buffers. `cmd/ritueel/main_test.go` also builds the program and runs it as a process, to check the real executable.
- A new dependency is named in the pull request, with the reason for it.

### In CI

- The job `go` of `.github/workflows/checks.yaml` runs `just go-check`. It is one of the jobs that the single job `checks` waits for.
- The job installs the tools from this repository's own `devbox.json` and `devbox.lock`, with `jetify-com/devbox-install-action`. At run time the action fetches the devbox installer, and the job checks the devbox program it installs against a pinned checksum. The action also runs the Nix installer, which CI trusts. The other jobs use the shared setup action.
- A pull request only reads the Go caches (the build cache and the module cache). It never saves them. `.github/workflows/go-cache.yaml` is the only workflow that saves them. It runs on `main`, after a change to a Go file, `go.mod`, `go.sum`, `devbox.json`, `devbox.lock` or the `Justfile`, and on demand. The build cache is not checked when it is read, so code that is not reviewed must not write it.
- The vulnerability scan is its own workflow, `.github/workflows/security.yaml`, which runs `just go-vuln` on `main`, on pull requests, every day and on demand. It is not part of `checks` and does not block a merge: a new advisory is news about the world, not about your change.

### A new top-level Go folder

Add the folder in two places of the `Justfile`: the variable `go_packages`, and the file list of `go-fmt` (`git ls-files ... -- cmd internal tools`). Then check that `go-check` still sees the new files. If the folder holds a program that exits or prints by design, add a path exception for it to the `forbidigo` rule in `.golangci.yaml`, as `tools/` has.

## The site

The site is built from `docs/` and `site/` with Astro Starlight, and every page is prerendered into static files in `site/dist`. `docs/` is linked into the site at `site/src/content/docs`, so a page reads the same on GitHub as on ritueel.id. The decision records are counted by the site (status page) and not rendered.

- `just site-dev` serves it on `http://localhost:4321` with live reload.
- `just site-build` makes the strict build, the same build CI checks.
- **Published pages.** `site/published.txt` is the allowlist; the docs collection loads only those files. Links from them to other pages of `docs/` are rewritten at build to the file on GitHub (`site/lib/docs-links.mjs`).
- **Redirects.** The unpublished addresses are the generated block of `site/public/_redirects`; `check-built.sh` and `just site-lint` fail when it is out of date. `check-github-links.mjs` checks the rewritten links, which `lychee.toml` excludes.
- `site/public/_headers` holds the Content-Security-Policy and the other security headers. Inline scripts are listed by hash, and `site/scripts/check-csp.mjs` (run by `check-built.sh`) fails when a page runs one that is not listed, or a listed one is gone, and prints the hashes to paste. The site loads nothing from outside except Cloudflare Web Analytics, which the CDN injects at the edge (privacy-first, no cookies, pinned by an integrity hash): `script-src` names `https://static.cloudflareinsights.com` and `connect-src` names `https://cloudflareinsights.com`, and the check fails on any other external origin.
- **The project status page** (`/status/`, `site/src/pages/status.astro`) is static HTML with a live part. The decision records by status, the reference pages and the lines of code are counted from the repository by `site/src/lib-status.ts` at build time; they never change after the build. The milestones are the rows of the table in `docs/roadmap.md`, joined with the issues by `site/src/lib-milestones.ts`. The issues per milestone and the latest run of each workflow on `main` are the live parts, drawn by one renderer (`site/src/lib-status-html.ts`) in two places: the build writes a snapshot of them into the page (the issues come from the GitHub REST API, `site/src/lib-github-rest.ts`, read with the token in `GITHUB_TOKEN`; CI passes the workflow's read-only token), and the Worker draws the live version. Without a token, or when GitHub does not answer, the build still passes and the snapshot says the issue figures are unavailable.
- **The live status API** is the Worker's code in `site/src/worker/`, a plain module that `wrangler deploy` bundles; it has no Astro server in it. `site/wrangler.jsonc` runs it first for `/api/*` only, so a static page never invokes it, and gives it a cron every 15 minutes. The cron is the only writer: it mints an installation token of a read-only GitHub App (issues, Actions and metadata, each read), reads the issues and milestones over REST and the workflow runs on `main` with a conditional request, and writes one KV document, `board`, only when the content changed or the stored copy is more than an hour old (at most 100 writes a day). There is no webhook, so the page is as live as the cron is frequent; a webhook is a later addition if 15 minutes proves too slow. Two routes, both read-only: `GET /api/status` is the data as JSON (a minute of cache; 503 until the first refresh), and `GET /api/status/live/` is the live parts as an HTML fragment. The page's script, `site/src/scripts/status-live.ts`, is bundled into a file of this site, so the Content-Security-Policy needs no new entry: it fetches the fragment and swaps each part in, and on any failure the snapshot stays and a note above it says so. The Worker joins the document with `/data/status.json`, the roadmap as the build read it, from its own static assets. `just site-test-worker` (part of `just site-workers`) runs `site/scripts/check-worker.mjs`: the App's token request, the KV write rules, a refresh and every route against fakes, with no network and no credential.
- **Where it is served.** `site/wrangler.jsonc` names the Worker `ritueel-site`, serves `site/dist` as static assets and names the Worker's code, its cron and one KV binding, `STATUS`, with a placeholder id. It declares no routes and no account, and `workers_dev` and `preview_urls` are off for good: Wrangler turns both on by default, and each publishes a hostname that contains the operator's account subdomain. There is no preview per pull request for that reason; a pull request is judged by `just site-check` and `just site-workers` in CI, and you can serve the same build with `yarn wrangler dev` in `site/`. Never widen `assets.run_worker_first` beyond `/api/*`, and never turn on Workers Cache: either would put the whole site under the Free plan's daily request limit.
- **The deploy** is the `deploy` job of `.github/workflows/site.yaml`. It runs on a push to `main` and on a manual run from `main`, after the `build` job has passed, and never on a pull request. It rebuilds the site, then runs `just site-deploy`, which writes `site/wrangler.deploy.json` (`site/scripts/deploy-config.mjs`: `wrangler.jsonc` with the KV id from `RITUEEL_STATUS_KV_ID`, so that the id is never in the repository) and runs `yarn wrangler deploy` on it, with the Worker's secrets in a file that only that step can read (`--secrets-file`). No build artifact is uploaded to GitHub. The job runs in the GitHub environment `cloudflare`, which allows deployments from `main` only and has no required reviewers. It holds `CLOUDFLARE_API_TOKEN` (a token limited to deploying this one Worker), `CLOUDFLARE_ACCOUNT_ID`, `RITUEEL_STATUS_KV_ID`, `RITUEEL_STATUS_APP_KEY` (the private key of the GitHub App) and the variable `RITUEEL_STATUS_APP_CLIENT_ID`. The job gives each to the one step that needs it. While the token is not set, the job says so in a notice and skips, and `main` stays green; once it is set, a missing one of the others fails the job in seconds, naming it. The maintainer creates and rotates the token; a deploy that fails with an authentication error is the sign that it has expired. Nobody runs `wrangler secret put`: rotating an App key is changing the secret in GitHub and running the workflow.
- The Worker, its KV namespace, its routes, the domain and the GitHub App are declared in the operator's own infrastructure code and settings, outside this repository. The deploy uploads a new version of the Worker and its two secrets, and changes none of them.

## How a consumer gets ritueel

The first consumer is the test harness of a system that holds intermediates, such as [sluis](https://sluis.id), which runs ritueel's software-root mode in its CI ([principle 8](/principles/#the-principles)). It needs a build it can pin. Not built yet: the release workflow ([issue #10](https://github.com/truvity/ritueel/issues/10)).

- **What a release is.** A tag `vX.Y.Z` on `main`. GoReleaser (version 2) builds the binary for Linux and macOS, on amd64 and arm64, into one `.tar.gz` for each platform, and writes `SHA256SUMS` with the digest of each. The files go on the repository's GitHub Releases page.
- **Checksums only, before the gate.** No release is signed until the project's root is adopted and drilled ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)). Until the first signed release (M5) a consumer's trust in a build is the digest it pinned, not a signature. From M5 the proof is `SHA256SUMS` signed by a release subkey that the project's root binds, with a keyless signature beside it ([record 0009](../decisions/0009-release-keys-and-the-keyring.md)).
- **How a consumer pins it.** It records the version and the SHA-256 of the archive for each platform it runs on in its own repository, downloads the archive from the release, compares the digest before it unpacks, and refuses a mismatch. A new version is a reviewed change of both. `ritueel version` prints the version and the commit, so a log shows which build ran.
- **No container image and no packages yet.** A `.deb` or `.rpm` of ritueel waits for a user beyond the test harness, and will be signed once the gate is passed.

## Commands from an agent shell

An AI agent's shell may reset its working directory between calls, so a `cd` in one call is gone in the next. Use absolute paths:

- `git -C /abs/path/to/worktree status`, `go -C /abs/path ...`;
- or `cd /abs/path && devbox run -- just check` as one command.

Never run `go mod init` or `go get` outside the repository: in the wrong directory they create or change a module that is not this one.

## Local work

- **Work in your own place.** Use a fresh clone or a worktree under your scratch area ([Branches and pull requests](/contributing/workflow/#one-change-one-worktree-one-branch)). Never work inside someone else's checkout, and do not `cd` into it.
- **Run the narrow recipes,** `just check-rules`, `just site-lint` and `just site-build`, and `just go-check` for a change to Go code. Leave the rest to GitHub CI, which runs the full gate on every pull request. Say which you ran.
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
