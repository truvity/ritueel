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

# The pages of site/published.txt (the eleven Learn pages, the three How it works pages, the glossary, the roadmap, the hand-off contract),
# the pages made in src/pages, and the demo.
for f in index.html 404.html sitemap-index.xml robots.txt \
         learn/index.html learn/what-is-a-root/index.html learn/where-a-root-is-used/index.html \
         learn/how-a-yubikey-holds-keys/index.html learn/how-passkeys-work/index.html learn/how-a-kms-key-works/index.html \
         learn/choosing-where-a-root-lives/index.html learn/life-of-a-root/index.html learn/revoke/index.html \
         learn/custody-chain/index.html learn/chain-openpgp/index.html \
         how-it-works/index.html how-it-works/cards/index.html how-it-works/bundle-and-stick/index.html \
         glossary/index.html roadmap/index.html reference/hand-off-contract/index.html \
         design/index.html status/index.html \
         demo/index.html demo/scheme.js demo/favicon.svg demo/THIRD-PARTY-LICENSES.md; do
  [ -s "$dist/$f" ] || bad "missing or empty: $f"
done

# Nothing else of docs/ is built: a page of an address that gen-redirects.mjs --list names (a file of
# docs/ that site/published.txt does not list) has no HTML page and no sitemap entry.
unpublished=$(site/scripts/gen-redirects.mjs --list) || bad "site/scripts/gen-redirects.mjs --list failed"
[ -n "$unpublished" ] || bad "gen-redirects.mjs --list names no unpublished page, so the check of unpublished pages proves nothing"
ls "$dist"/sitemap-*.xml >/dev/null 2>&1 || bad "no sitemap file in $dist"
grep -qF '<loc>https://ritueel.id/learn/</loc>' "$dist"/sitemap-*.xml 2>/dev/null || bad "the sitemap lacks https://ritueel.id/learn/"
while read -r addr; do
  [ -n "$addr" ] || continue
  [ ! -e "$dist${addr%/}/index.html" ] || bad "an unpublished page is built: $addr"
  if grep -qF "<loc>https://ritueel.id$addr</loc>" "$dist"/sitemap-*.xml 2>/dev/null; then bad "the sitemap lists an unpublished page: $addr"; fi
done <<< "$unpublished"

# The figures (site/figures, placed by <Figure>) reached the output: a figure page holds its <figure>
# and drawings that are images with a label, and none of the drawings keeps its text in the search.
# (Starlight's own icons are <svg> too, so the check names the drawings by role="img".)
for f in index.html how-it-works/index.html how-it-works/cards/index.html how-it-works/bundle-and-stick/index.html \
         learn/how-a-yubikey-holds-keys/index.html learn/how-passkeys-work/index.html; do
  [ -s "$dist/$f" ] || continue
  grep -q '<figure class="fig ' "$dist/$f" || bad "$f has no figure"
  [ "$(grep -o '<svg[^>]* role="img"[^>]* data-pagefind-ignore' "$dist/$f" | wc -l)" -ge 1 ] || bad "$f has no drawing with role=img and data-pagefind-ignore (did a sanitizer drop them?)"
  if grep -Eo '<svg[^>]* (class="fig-[a-z]+" )?viewBox="[^"]*"[^>]*>' "$dist/$f" | grep -v 'role="img"' | grep -q 'viewBox="0 0 \(280 224\|760\|360\)'; then bad "$f has a drawing without role=img"; fi
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

# The decision records have no page: nothing is built under decisions/ (the old addresses are
# redirects, and the design page says what the records decide).
[ ! -e "$dist/decisions" ] || bad "decisions/ is built: the records have no pages"

# The redirects file reached the output. A rule that leads to a page of docs/ which is not published
# is a 302 to that file on GitHub, and the file exists in this checkout; a rule that leads to an old
# decision record is a 301 to that file at a fixed commit, and the file is named in site/old-records.txt;
# any other rule is a 301 to a built page. A source is never a built page (a redirect is followed even where a page exists) and
# no source appears twice.
if [ -s "$dist/_redirects" ]; then
  seen=$'\n'
  gh=https://github.com/truvity/ritueel/blob/main/docs/
  pinned='^https://github\.com/truvity/ritueel/blob/[0-9a-f]{40}/docs/decisions/(.+)$'
  while read -r from to code; do
    case "$from" in ''|'#'*) continue ;; esac
    case "$seen" in *$'\n'"$from"$'\n'*) bad "_redirects: $from is the source of two rules" ;; esac
    seen+="$from"$'\n'
    [ ! -e "$dist${from%/}/index.html" ] || bad "_redirects: $from is a built page, which a redirect would hide"
    if [[ "$to" =~ $pinned ]]; then
      [ "$code" = 301 ] || bad "_redirects: $from points to an old record at a commit and must be a 301, not a $code"
      grep -qE "^[0-9]{4}-[a-z0-9-]+ ${BASH_REMATCH[1]//./\\.}\$" site/old-records.txt || bad "_redirects: $from points to ${BASH_REMATCH[1]}, which site/old-records.txt does not name"
      continue
    fi
    case "$to" in
      "$gh"*)
        [ "$code" = 302 ] || bad "_redirects: $from points to a file on GitHub and must be a 302, not a $code"
        file=${to#"$gh"}; file=${file%%#*}
        [ -f "docs/$file" ] || bad "_redirects: $from points to docs/$file, which is not a file of this checkout"
        ;;
      *)
        [ "$code" = 301 ] || bad "_redirects: $from points to a built page and must be a 301, not a $code"
        target=${to%%#*}
        [ -s "$dist${target%/}/index.html" ] || bad "_redirects: $from points to $to, which is not a built page"
        ;;
    esac
  done < "$dist/_redirects"
else
  bad "no _redirects: site/public/_redirects did not reach the output"
fi

# The links of the built pages into the repository (the files the pages link on GitHub, the rewritten
# ones among them): each file exists, and each #anchor of a Markdown file is one of its headings.
site/scripts/check-github-links.mjs "$dist" || bad "a link into the repository on GitHub names a missing file or heading (above)"

# The project status page: a card for every milestone row of the roadmap.
if [ -s "$dist/status/index.html" ]; then
  want=$(grep -cE '^\| \*\*M[0-9]+:' docs/roadmap.md || true)
  have=$(grep -o 'data-milestone="M[0-9]*"' "$dist/status/index.html" | sort -u | wc -l)
  { [ "$want" -gt 0 ] && [ "$want" -eq "$have" ]; } || bad "status/index.html has $have milestone cards; docs/roadmap.md has $want milestone rows"
  grep -q 'data-github="\(available\|unavailable\)"' "$dist/status/index.html" || bad "status/index.html does not say whether the issues were read"
fi

# The landing page says what ritueel is and that it is in the design phase.
grep -q 'design phase' "$dist/index.html" || bad "the landing page lacks the status paragraph"

[ "$fail" -eq 0 ] || exit 1
echo "check-built: ok ($(find "$dist" -name '*.html' | wc -l) HTML files)"
