---
name: maintainer-script
description: Use when issues or the board need more than a couple of writes (bulk create, edit, comment, label or close). The agent writes a dry-run-by-default script for the maintainer to run instead of writing itself.
---

Read "Issues and the board" in `docs/contributing/workflow.md` and follow it. An agent opens at most a couple of issues itself; everything else goes into a script that the maintainer runs. Keep the script and its body files in your scratch area, and hand them over in the pull request or the report; commit them only when the maintainer asks.

Checklist:

- [ ] Before creating anything, search open and closed issues by title in this repository **and in the sibling sluis repository** for a cross-repository item. A script once nearly duplicated an issue that already existed in the other repository.
- [ ] Dry run by default; `--apply` to write; idempotent (create only when no issue has the exact title, comment only when the text is absent, replace a body only while it equals the reviewed copy).
- [ ] Reads over REST (`gh api`), never GraphQL; a short pause after each write; an apply log; on a failed read, print the real `gh` stderr.
- [ ] Each API page goes to a temporary file and `jq` reads the file; no page is held in a shell variable.
- [ ] Bodies are files next to the script. The dry-run output is reviewed and scanned for private terms and for secrets before the maintainer runs it.
- [ ] Nothing in the script or its output prints a token.

Skeleton (adapt; `OWNER/REPO` is this repository, `SIBLING` the other):

```bash
#!/usr/bin/env bash
# usage: script.sh [--apply]
set -euo pipefail
apply=false; [ "${1:-}" = "--apply" ] && apply=true
repo="OWNER/REPO"; sibling="OWNER/SIBLING"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
log="apply-$(date -u +%Y%m%dT%H%M%SZ).log"

# Read every issue (open and closed) over REST into a file; pull requests are not issues.
fetch() { # repo outfile
  gh api "repos/$1/issues?state=all&per_page=100" --paginate 2>"$tmp/err" \
    | jq -s '[.[][] | select(.pull_request == null) | {number, title, state}]' >"$2" \
    || { cat "$tmp/err" >&2; exit 1; }
}
fetch "$repo" "$tmp/here.json"
fetch "$sibling" "$tmp/sibling.json"

create() { # title bodyfile
  local title=$1 body=$2
  if jq -e --arg t "$title" 'any(.[]; .title == $t)' "$tmp/here.json" >/dev/null; then
    echo "skip (exists here): $title"; return
  fi
  if jq -e --arg t "$title" 'any(.[]; .title == $t)' "$tmp/sibling.json" >/dev/null; then
    echo "skip (exists in the sibling repository): $title"; return
  fi
  if $apply; then
    gh issue create --repo "$repo" --title "$title" --body-file "$body" | tee -a "$log"
    sleep 2
  else
    echo "would create: $title"
  fi
}

create "Exact title of the issue" bodies/exact-title.md
```
