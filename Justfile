# Recipes for ritueel. Run them inside the devbox shell (`devbox shell`, or
# `devbox run -- just <recipe>`). CI runs the same recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install the site's dependencies exactly as the lockfile says.
site-install:
    cd site && yarn install --immutable

# The site on http://localhost:4321 with live reload. The demo of the local page (/demo/) is the
# build `just ui-demo` made, not a live one.
site-dev: site-install ui-demo
    cd site && yarn dev

# A strict build into site/dist: no warnings, no broken internal link, and the built
# output has what it must (search index, headers, the pages, the demo, no page for a decision record).
# The demo of the local page is built first (`just ui-demo`) into site/public/demo, where Astro
# copies it into site/dist/demo/.
site-build: site-install ui-demo
    site/scripts/strict-build.sh
    site/scripts/check-built.sh site/dist

# Front-matter descriptions of 40 to 160 characters on every page in docs/, the redirect block
# of site/public/_redirects against site/published.txt, and the tests of the allowlist, the link
# plugin and the redirect script (node:test, no install, no build).
site-lint:
    site/scripts/check-descriptions.mjs
    site/scripts/gen-redirects.mjs --check
    node --test 'site/test/*.test.mjs'

# Write site/public/_redirects again after a change to site/published.txt or to a hand line in it:
# a 302 to its file on GitHub for the old address of every page the site does not publish.
site-redirects:
    site/scripts/gen-redirects.mjs

# Every link in the built site, internal and external (lychee.toml). Needs `just site-build`.
# Each try is bounded to 4 minutes (a normal run takes well under one), is verbose so that
# the log names the link it stopped at, and a try that hit the bound is repeated, twice. A run
# that ends in lychee's own failure (a dead link) is not repeated.
site-links:
    #!/usr/bin/env bash
    set -euo pipefail
    for attempt in 1 2 3; do
      rc=0
      timeout --foreground 240 lychee --config lychee.toml --root-dir "$PWD/site/dist" --no-progress -v 'site/dist/**/*.html' || rc=$?
      [ "$rc" -eq 124 ] || exit "$rc"
      echo "site-links: lychee did not finish in 240 s (try $attempt of 3)" >&2
    done
    echo "site-links: lychee did not finish in 3 tries" >&2
    exit 1

# What a pull request must pass for the site.
site-check: site-lint site-build site-links

# The tests of the site's Worker (site/src/worker/, the renderer it shares with the status page, the
# live script's decisions, the deploy configuration), in Node, with GitHub and KV faked. No network,
# no credential.
site-test-worker: site-install
    site/scripts/check-worker.mjs

# The status page in headless Chrome (site/scripts/check-render.mjs): the live script swaps the
# Worker's parts in, keeps the snapshot when the Worker has nothing, and nothing scrolls sideways at
# 375 px. A server in the script stands in for the Worker. Needs `just site-build` and Chrome or
# Chromium (CHROME, or on PATH). With a directory, it saves a screenshot of each render there.
site-render dir='':
    site/scripts/check-render.mjs site/dist {{ dir }}

# The Worker's dry-run deploy: `wrangler deploy --dry-run` on the built site in site/dist, which
# also bundles the Worker. It uploads nothing and needs no Cloudflare credential. Needs
# `just site-build`.
site-workers: site-test-worker
    cd site && WRANGLER_SEND_METRICS=false yarn wrangler deploy --dry-run

# Deploy the build in site/dist to Cloudflare. Only the deploy job of site.yaml runs this, on a
# strict build of `main`. Needs CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID and RITUEEL_STATUS_KV_ID.
# `secrets` is a JSON file of Worker secrets to upload with the version (absolute path); the deploy
# job writes it from GitHub secrets and deletes it afterwards.
site-deploy secrets='':
    site/scripts/deploy-config.mjs
    cd site && WRANGLER_SEND_METRICS=false yarn wrangler deploy --config wrangler.deploy.json {{ if secrets != '' { '--secrets-file ' + quote(secrets) } else { '' } }}

# Repository rules (tools/checks/). Each check fails when it finds nothing to check.

# Decision records in docs/decisions/: NNNN-kebab-case.md names, the template's
# fields and sections in order, a status the README allows, every road not taken
# with its pros, cons and reason, and a README index row per record with its status.
check-decisions:
    tools/checks/decisions.mjs

# Every citation of a rule of a decision record ("record 0004, rule 2", "rules 12 and 29") in the
# pages, the records, the comments of proto/ and ui/src and the site figures names a record that
# exists and a rule that it has. A bare "rule N" is resolved only inside its own record or by the
# page's one declared default; anything else is an error.
check-record-refs:
    tools/checks/record-refs.mjs

# Public content of every tracked text file: no account-id-shaped number other than
# a documented placeholder, no private key block, no well-known token prefix, and no
# term of the private deny-list (PUBLIC_CONTENT_DENYLIST, a repository secret; the
# check skips that part, saying so, when the variable is empty, and fails instead
# when REQUIRE_DENYLIST=true).
check-public:
    tools/checks/public-content.mjs

# The same scan over the commit messages of BASE..HEAD (BASE defaults to origin/main)
# and the pull request title and body in PR_TITLE and PR_BODY. Not part of
# check-rules: on `main` itself the range is empty, and an empty sweep fails.
check-messages:
    tools/checks/public-messages.mjs

# YAML files use .yaml, except the names a tool requires (.github/ISSUE_TEMPLATE/config.yml, .yarnrc.yml).
check-yaml-ext:
    tools/checks/yaml-ext.mjs

# Markdown everywhere; MDX only for a page that places components: every docs/**/*.mdx imports
# a component and places it ("Page format" in docs/contributing/pages.md).
check-mdx-pages:
    tools/checks/mdx-pages.mjs

# Every path that AGENTS.md, CLAUDE.md, .claude/skills/*/SKILL.md and .claude/agents/*.md
# point to exists. Fails when AGENTS.md is missing or CLAUDE.md does not import it.
check-agent-links:
    tools/checks/agent-links.mjs

# The checks above against scratch repositories that must pass or must fail.
check-selftest:
    tools/checks/selftest.mjs

# Test vectors in testdata/*/v*/: every file the manifest names is tracked, every tracked file is
# named, and the digests in the proofs and results match the files.
check-vectors:
    tools/checks/vectors.mjs

# The local page (ui/) and its API (proto/). Run the recipes inside the devbox shell like the rest.

# Install the page's dependencies exactly as ui/package-lock.json says.
ui-install:
    cd ui && npm ci

# TypeScript (strict) and the safety scan: no innerHTML, eval, fetch or remote URL in the source,
# no text under 12px (ui/src/safety.test.ts, the page's lint).
ui-lint: ui-install
    cd ui && npm run lint

# The page's tests (vitest): the safety scan, the text rule, every screen with hostile text, the
# demo transport and the routes.
ui-test: ui-install
    cd ui && npm test

# Both builds of the page, and what each bundle must and must not hold: the demo (base /demo/, in
# ui/dist) and the real one (relative base, in ui/dist-real). Neither is committed.
ui-build: ui-install
    cd ui && npm run build && npm run build:real && npm run check:dist

# The demo for the site: the page in demo mode, base path /demo/, built into site/public/demo.
# That directory is a build product and is not committed: Astro copies site/public into
# site/dist, so the demo is served at /demo/ by the same static assets as the pages, under the
# same headers. `just site-build` runs this first.
ui-demo: ui-install
    cd ui && OUT_DIR=../site/public/demo npm run build

# The page in headless Chrome (Chrome or Chromium on PATH, or CHROME): keyboard, focus, theme,
# the panel, the scenes, the four states, copy, the layout, the phone. The demo is served under the site's own
# Content-Security-Policy (site/public/_headers), and the run fails on a console error or a policy
# violation. Needs no other server.
ui-e2e: ui-build
    #!/usr/bin/env bash
    set -euo pipefail
    cd ui
    log=$(mktemp)
    node scripts/serve.mjs 0 --headers ../site/public/_headers > "$log" &
    server=$!
    trap 'kill "$server" 2>/dev/null || true; rm -f "$log"' EXIT
    for _ in $(seq 1 50); do [ -s "$log" ] && break; sleep 0.1; done
    url=$(head -1 "$log")
    [ -n "$url" ] || { echo "ui-e2e: the server printed no address" >&2; exit 1; }
    npm run e2e -- "$url"

# Lint proto/ (buf STANDARD). Needs nothing else.
proto-lint:
    buf lint

# Lint proto/ and regenerate the page's TypeScript, ui/src/gen/ (protoc-gen-es from ui/node_modules).
proto-gen: ui-install proto-lint
    buf generate

# proto-gen must leave no difference: the committed ui/src/gen/ is what the generator makes.
proto-check: proto-gen
    git diff --exit-code -- ui/src/gen proto
    @test -z "$(git ls-files --others --exclude-standard -- ui/src/gen proto)" || { echo "proto-check: untracked generated files" >&2; exit 1; }

# Every repository rule.
check-rules: check-selftest check-decisions check-record-refs check-public check-yaml-ext check-mdx-pages check-agent-links check-vectors

# The Go code (cmd/, internal/, tools/). Run the recipes inside the devbox shell like the rest.

# The packages the Go recipes look at. Spelled out, because `./...` would also walk Go files that npm
# packages ship inside ui/node_modules or site/node_modules. A new top-level Go directory is added here
# and to `go-fmt`.
go_packages := "./cmd/... ./internal/... ./tools/..."

# Everything a pull request must pass for the Go code. Needs the module download; no credential, no
# device. Cheap checks first. `go-vuln` is not part of it (security.yaml runs it).
go-check: go-fmt go-tidy go-verify go-vet go-lint go-test go-build

# gofmt -s finds nothing to change in the module's own Go files (tracked or new, never ignored ones,
# so not node_modules; testdata/ is skipped as the go tool skips it). The linter's gofmt and goimports
# formatters check the same again. Fails when there is no Go file: a check that finds nothing fails.
go-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    mapfile -t files < <(git ls-files --cached --others --exclude-standard -- cmd internal tools | grep -E '\.go$' | grep -v '/testdata/' || true)
    [ "${#files[@]}" -gt 0 ] || { echo "go-fmt: no Go file found" >&2; exit 1; }
    out=$(gofmt -l -s "${files[@]}")
    [ -z "$out" ] || { echo "go-fmt: run gofmt -s -w on:" >&2; echo "$out" >&2; exit 1; }

# go vet on every package, built the way the release is built (no cgo, from the environment).
go-vet:
    go vet {{ go_packages }}

# The one linter. `config verify` first: `run` accepts a settings block in the wrong place silently.
# GOTOOLCHAIN=local (set in devbox.json) keeps the linter and the code on the Go that devbox.json pins.
go-lint:
    golangci-lint config verify
    golangci-lint run {{ go_packages }}

# go.mod and go.sum are what `go mod tidy` would write.
go-tidy:
    go mod tidy -diff

# Download the modules, then check each one against go.sum. It downloads, which is why the Go job has network.
go-verify:
    go mod download
    go mod verify

# The unit tests. No network, no device, no cloud key.
go-test:
    go test {{ go_packages }}

# The release build, as the release makes it: static, no cgo, paths trimmed, the version and the commit
# stamped in (VERSION and COMMIT in the environment override git's answer). Both must be plain
# (letters, digits and . _ + -), because they go into one quoted -ldflags string. Then: the file is a
# static Linux executable (tools/elfcheck), `version` prints exactly what was stamped (so a renamed
# symbol or a broken -X fails here), and no arguments exit 2 (a usage error).
go-build:
    #!/usr/bin/env bash
    set -euo pipefail
    version="${VERSION:-$(git describe --tags --match 'v[0-9]*' --dirty --always 2>/dev/null || echo dev)}"
    commit="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
    for pair in "VERSION=${version}" "COMMIT=${commit}"; do
      [[ "${pair#*=}" =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "go-build: ${pair%%=*} must match [A-Za-z0-9._+-]+, got '${pair#*=}'" >&2; exit 1; }
    done
    pkg=ritueel.id/ritueel/internal/buildinfo
    mkdir -p bin
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X ${pkg}.version=${version} -X ${pkg}.commit=${commit}" \
      -o bin/ritueel ./cmd/ritueel
    go run ./tools/elfcheck bin/ritueel
    got=$(bin/ritueel version)
    want="ritueel ${version} (commit ${commit})"
    echo "$got"
    [ "$got" = "$want" ] || { echo "go-build: 'ritueel version' printed '$got', wanted '$want'" >&2; exit 1; }
    rc=0; bin/ritueel > /dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "go-build: no arguments should exit 2, got $rc" >&2; exit 1; }

# Known vulnerabilities in what this module imports. Its own workflow (security.yaml), never in `check`:
# a new advisory is news about the world, not about the change.
go-vuln:
    govulncheck {{ go_packages }}

# Everything a pull request must pass.
check: check-rules site-check site-workers site-render proto-check ui-lint ui-test ui-e2e go-check
