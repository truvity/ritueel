# Recipes for ritueel. Run them inside the devbox shell (`devbox shell`, or
# `devbox run -- just <recipe>`). CI runs the same recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install the site's dependencies exactly as the lockfile says.
site-install:
    cd site && yarn install --immutable

# The site on http://localhost:4321 with live reload.
site-dev: site-install
    cd site && yarn dev

# A strict build into site/dist: no warnings, no broken internal link, and the built
# output has what it must (search index, headers, the pages, a page per decision record).
site-build: site-install
    site/scripts/strict-build.sh
    site/scripts/check-built.sh site/dist

# Front-matter descriptions of 40 to 160 characters on every page in docs/.
site-lint:
    site/scripts/check-descriptions.mjs

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

# Every repository rule.
check-rules: check-selftest check-decisions check-public check-yaml-ext check-mdx-pages check-agent-links check-vectors

# Everything a pull request must pass.
check: check-rules site-check site-workers site-render
