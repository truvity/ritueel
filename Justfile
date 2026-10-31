# Recipes for ritueel. Run them inside the devbox shell (`devbox shell`, or
# `devbox run -- just <recipe>`). CI runs the same recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

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

# Every path that AGENTS.md, CLAUDE.md, .claude/skills/*/SKILL.md and .claude/agents/*.md
# point to exists. Fails when AGENTS.md is missing or CLAUDE.md does not import it.
check-agent-links:
    tools/checks/agent-links.mjs

# The checks above against scratch repositories that must pass or must fail.
check-selftest:
    tools/checks/selftest.mjs

# Every repository rule.
check-rules: check-selftest check-public check-yaml-ext check-agent-links

# Everything a pull request must pass.
check: check-rules
