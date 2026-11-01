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
         concepts/index.html concepts/roots-and-transitions/index.html concepts/key-stores/index.html \
         guides/index.html reference/index.html reference/cli/index.html research/index.html \
         roadmap/index.html contributing/index.html decisions/index.html; do
  [ -s "$dist/$f" ] || bad "missing or empty: $f"
done

# Search: Pagefind's index and its entry point.
[ -s "$dist/pagefind/pagefind.js" ] || bad "no Pagefind entry point in $dist/pagefind"
[ -n "$(ls "$dist"/pagefind/index 2>/dev/null)" ] || bad "no Pagefind index shards in $dist/pagefind/index"

# Response headers (CSP and the rest): the Worker serves them from _headers.
[ -s "$dist/_headers" ] || bad "no _headers: site/public/_headers did not reach the output"
site/scripts/check-csp.mjs "$dist" || bad "the Content-Security-Policy does not match the pages (above)"

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

# The Worker configuration: neither workers.dev nor preview URLs, no routes, no KV, no secrets.
cfg=site/wrangler.jsonc
grep -q '"workers_dev": false' "$cfg" || bad "$cfg does not set workers_dev false"
grep -q '"preview_urls": false' "$cfg" || bad "$cfg does not set preview_urls false"
if grep -Eq '^\s*"(routes?|kv_namespaces|account_id|zone_id)"' "$cfg"; then
  bad "$cfg declares routes, KV or an account; those live outside this repository"
fi

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

# The landing page says what ritueel is and that it is in the design phase.
grep -q 'design phase' "$dist/index.html" || bad "the landing page lacks the status paragraph"

[ "$fail" -eq 0 ] || exit 1
echo "check-built: ok ($(find "$dist" -name '*.html' | wc -l) HTML files)"
