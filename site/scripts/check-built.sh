#!/usr/bin/env bash
# What the built site must contain, checked in site/dist (or the directory given, relative to
# the repository root). Each check fails closed: a missing file or an empty match is a failure.
#
# usage: site/scripts/check-built.sh [dist]
set -euo pipefail
cd "$(dirname "$0")/../.."
dist=${1:-site/dist}
fail=0
bad() { echo "check-built: $*" >&2; fail=1; }

for f in index.html 404.html sitemap-index.xml robots.txt \
         learn/index.html learn/what-is-a-root/index.html learn/custody-chain/index.html learn/key-stores/index.html \
         learn/life-of-a-root/index.html guides/index.html tools/index.html tools/wizard/index.html principles/index.html reference/index.html reference/cli/index.html research/index.html \
         roadmap/index.html contributing/index.html decisions/index.html status/index.html \
         demo/index.html demo/scheme.js demo/favicon.svg demo/THIRD-PARTY-LICENSES.md tools/local-page/index.html; do
  [ -s "$dist/$f" ] || bad "missing or empty: $f"
done

# Search: Pagefind's index and its entry point.
[ -s "$dist/pagefind/pagefind.js" ] || bad "no Pagefind entry point in $dist/pagefind"
[ -n "$(ls "$dist"/pagefind/index 2>/dev/null)" ] || bad "no Pagefind index shards in $dist/pagefind/index"

# Response headers (CSP and the rest): the Worker serves them from _headers.
[ -s "$dist/_headers" ] || bad "no _headers: site/public/_headers did not reach the output"
site/scripts/check-csp.mjs "$dist" || bad "the Content-Security-Policy does not match the pages (above)"

# The demo of the local page (ui/, built by `just ui-demo` into site/public/demo): its page names its
# files under /demo/, loads no script that is inline, and no file of it names a host other than the few
# that are text, not requests: XML namespaces, the pages React and MUI name in an error message, the
# link back to this site, the in-memory transport's placeholder and Tailwind's licence banner.
# (`ui/scripts/check-dist.mjs` checks the bundles themselves; this is the same check on what is served.)
if [ -s "$dist/demo/index.html" ]; then
  grep -q 'src="/demo/assets/' "$dist/demo/index.html" || bad "demo/index.html does not load its bundle from /demo/assets/ (is the base path /demo/?)"
  [ -n "$(ls "$dist"/demo/assets/*.js 2>/dev/null)" ] || bad "no script under demo/assets/"
  if grep -rEoh 'https?://[A-Za-z0-9.-]+' "$dist"/demo/assets "$dist/demo/index.html" | sort -u | grep -Evx 'https?://(www\.w3\.org|mui\.com|react\.dev|ritueel\.id|in-memory|tailwindcss\.com)'; then
    bad "the demo's files name a host other than those of its allow-list (above)"
  fi
fi

# Fingerprinted assets (/_astro/*, content-hashed file names) are cached for a year and nothing
# else is: the immutable Cache-Control must sit under /_astro/* and under no other path.
awk '
  /^[^ \t#]/ { path = $0; next }
  /^[ \t]+[Cc]ache-[Cc]ontrol:/ {
    v = $0; sub(/^[ \t]+[Cc]ache-[Cc]ontrol:[ \t]*/, "", v); sub(/[ \t\r]+$/, "", v)
    if (v ~ /immutable/) {
      if (path == "/_astro/*" && v == "public, max-age=31536000, immutable") ok = 1
      else stray = 1
    }
  }
  END { exit (ok && !stray) ? 0 : 1 }
' "$dist/_headers" || bad "$dist/_headers must give /_astro/* (and only it) 'Cache-Control: public, max-age=31536000, immutable'"

# The Worker configuration: neither workers.dev nor preview URLs; no routes, account or zone (those
# live outside this repository); the Worker runs first for /api/* and nothing else; one cron; and
# exactly one KV binding, STATUS, with the placeholder id (the real one is put in at the deploy by
# site/scripts/deploy-config.mjs, from a secret).
cfg=site/wrangler.jsonc
grep -q '"workers_dev": false' "$cfg" || bad "$cfg does not set workers_dev false"
grep -q '"preview_urls": false' "$cfg" || bad "$cfg does not set preview_urls false"
if grep -Eq '^\s*"(routes?|account_id|zone_id)"' "$cfg"; then
  bad "$cfg declares routes or an account; those live outside this repository"
fi
grep -Eq '^\s*"run_worker_first": \["/api/\*"\]' "$cfg" || bad "$cfg must run the Worker first for /api/* only (assets.run_worker_first)"
if grep -Eq '"run_worker_first": *(true|\[[^]]*"/\*")' "$cfg"; then bad "$cfg runs the Worker first for more than /api/*: static traffic would count against the Worker request limit"; fi
grep -Eq '^\s*"main": "src/worker/index.ts"' "$cfg" || bad "$cfg does not name the Worker's code as main"
[ "$(grep -cE '^\s*\{ "binding": "STATUS", "id": "0{32}" \}' "$cfg")" -eq 1 ] || bad "$cfg must declare exactly one KV namespace, STATUS, with the placeholder id"
if grep -E '"id": "[0-9a-f]{32}"' "$cfg" | grep -Evq '"id": "0{32}"'; then bad "$cfg holds a KV namespace id; the id is a secret of the deploy environment"; fi
grep -Eq '"crons": \["[^"]+"\]' "$cfg" || bad "$cfg has no cron trigger"

# The roadmap as the Worker reads it (/data/status.json) and the live status page: a container for
# every part the Worker's fragment has, the note, and the script as a file of this site, not inline.
if [ -s "$dist/data/status.json" ]; then
  want=$(grep -cE '^\| \*\*M[0-9]+:' docs/roadmap.md || true)
  have=$(grep -c '"key": "M[0-9]*"' "$dist/data/status.json" || true)
  { [ "$want" -gt 0 ] && [ "$want" -eq "$have" ]; } || bad "data/status.json has $have milestones; docs/roadmap.md has $want milestone rows"
else
  bad "missing or empty: data/status.json"
fi
if [ -s "$dist/status/index.html" ]; then
  for part in cards issues checks; do
    grep -q "data-live-part=\"$part\"" "$dist/status/index.html" || bad "status/index.html has no live part $part"
  done
  grep -q 'data-live-src="/api/status/live/"' "$dist/status/index.html" || bad "status/index.html has no live source"
  grep -q 'data-live-note' "$dist/status/index.html" || bad "status/index.html has no live note"
  grep -Eq '<script[^>]* src="/_astro/[^"]*"' "$dist/status/index.html" || bad "status/index.html loads no script from /_astro/ (the live script must be a file of this site)"
fi

# "Edit page" links: each one is a file in this checkout (and the page's own source).
site/scripts/check-edit-links.mjs "$dist" || bad "an edit link does not point at its file in the repository (above)"

# A decision record page exists for every record, and the template is not one.
if [ -s "$dist/decisions/index.html" ]; then
  if grep -q '0000-template' "$dist/decisions/index.html"; then bad "decisions/index.html lists the template"; fi
  [ ! -e "$dist/decisions/0000-template" ] || bad "the template is built as a decision page"
  for rec in docs/decisions/[0-9][0-9][0-9][0-9]-*.md; do
    name=$(basename "$rec" .md)
    [ "$name" = "0000-template" ] && continue
    [ -s "$dist/decisions/$name/index.html" ] || bad "no page for the decision record $name"
  done
fi

# Links in the decision pages, which the build's link validator cannot see: every in-site
# link leads to a built page, and every #anchor to an id on it.
site/scripts/check-anchors.mjs "$dist" || bad "a decision page links a missing page or anchor (above)"

# The redirects file reached the output, and each target is a built page.
if [ -s "$dist/_redirects" ]; then
  while read -r from to code; do
    case "$from" in ''|'#'*) continue ;; esac
    [ -s "$dist${to%/}/index.html" ] || bad "_redirects: $from points to $to, which is not a built page"
  done < "$dist/_redirects"
else
  bad "no _redirects: site/public/_redirects did not reach the output"
fi

# The project status page: a card for every milestone row of the roadmap, and the design line
# the home page shows, word for word (both are counted by site/src/lib-status.ts).
if [ -s "$dist/status/index.html" ]; then
  want=$(grep -cE '^\| \*\*M[0-9]+:' docs/roadmap.md || true)
  have=$(grep -o 'data-milestone="M[0-9]*"' "$dist/status/index.html" | sort -u | wc -l)
  { [ "$want" -gt 0 ] && [ "$want" -eq "$have" ]; } || bad "status/index.html has $have milestone cards; docs/roadmap.md has $want milestone rows"
  grep -q 'data-github="\(available\|unavailable\)"' "$dist/status/index.html" || bad "status/index.html does not say whether the issues were read"
  design() { grep -o 'Design: [0-9]* decision records, [0-9]* reference pages\. Code: [0-9]* lines\.' "$1" | head -1; }
  home=$(design "$dist/index.html")
  [ -n "$home" ] || bad "index.html has no design line"
  [ "$home" = "$(design "$dist/status/index.html")" ] || bad "status/index.html and index.html disagree on the design line"
fi

# The landing page says what ritueel is and that it is in the design phase.
grep -q 'design phase' "$dist/index.html" || bad "the landing page lacks the status paragraph"

[ "$fail" -eq 0 ] || exit 1
echo "check-built: ok ($(find "$dist" -name '*.html' | wc -l) HTML files)"
