#!/usr/bin/env node
// The Go module path of the project resolves: go.mod names the module `ritueel.id/ritueel`, and the
// Go tool (and the module proxy) fetch https://ritueel.id/ritueel?go-get=1 and read a
// <meta name="go-import" content="<module path> git <repository URL>"> tag in the <head> of the
// answer. The page is site/public/ritueel/index.html, copied into the build as it is. A module that
// is renamed, or a page that is lost or edited, would make `go install` and pkg.go.dev fail
// without any other check noticing; this is the guard.
//
// The module path is read from go.mod and mapped to the built file (site/dist/<path after the
// host>/index.html). The check fails unless
//   - the host of the module path is the site's own host (ritueel.id);
//   - the file exists and its <head> holds exactly one go-import tag, whose content is exactly
//     `<module path> git https://github.com/truvity/ritueel`.
// A local check against the checkout and the build, no network. Needs `just site-build`.
//
// usage: site/scripts/check-go-import.mjs [dist] [repo-root]
//   dist       the built site, relative to the repository root (default site/dist)
//   repo-root  the directory that holds go.mod (default: this repository; the tests point it at a scratch tree)
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE_HOST = 'ritueel.id';
const REPO_URL = 'https://github.com/truvity/ritueel';

const root = resolve(process.argv[3] ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..'));
const dist = resolve(root, process.argv[2] ?? 'site/dist');
const errors = [];
const E = (m) => errors.push(m);

if (!existsSync(dist)) {
  console.error(`check-go-import: no ${dist}; run the build first`);
  process.exit(1);
}

// The module path: the argument of the `module` directive (a quoted path is allowed).
let modulePath = null;
try {
  const gomod = readFileSync(join(root, 'go.mod'), 'utf8');
  const m = /^module[ \t]+(?:"([^"]+)"|`([^`]+)`|(\S+))[ \t]*(?:\/\/.*)?$/m.exec(gomod);
  modulePath = m ? (m[1] ?? m[2] ?? m[3]) : null;
} catch (e) {
  E(`cannot read go.mod: ${e.message}`);
}
if (modulePath === null && errors.length === 0) E('go.mod has no module directive');

if (modulePath !== null) {
  const slash = modulePath.indexOf('/');
  const host = slash < 0 ? modulePath : modulePath.slice(0, slash);
  const rest = slash < 0 ? '' : modulePath.slice(slash + 1);
  if (host !== SITE_HOST) {
    E(`the module path ${modulePath} is not under this site's host ${SITE_HOST}, so no page of this site can answer the Go tool for it`);
  } else if (rest === '') {
    E(`the module path ${modulePath} has no path after the host; this check maps ${SITE_HOST}/<path> to <path>/index.html`);
  } else if (rest.split('/').some((s) => s === '' || s === '.' || s === '..')) {
    E(`the module path ${modulePath} has an empty or relative path element`);
  } else {
    const file = join(dist, ...rest.split('/'), 'index.html');
    const label = `${rest}/index.html`;
    if (!existsSync(file) || !statSync(file).isFile()) {
      E(`${label} is not in the built site, so https://${modulePath}?go-get=1 would answer 404`);
    } else {
      const html = readFileSync(file, 'utf8');
      const head = /<head\b[^>]*>([\s\S]*?)<\/head\s*>/i.exec(html)?.[1];
      if (head === undefined) {
        E(`${label} has no <head>`);
      } else {
        const tags = [...head.matchAll(/<meta\b[^>]*>/gi)]
          .map((m) => m[0])
          .filter((t) => /\bname\s*=\s*["']?go-import["'\s>/]/i.test(t));
        if (tags.length !== 1) {
          E(`${label} must hold exactly one go-import tag in its <head>, and has ${tags.length}`);
        } else {
          const content = /\bcontent\s*=\s*"([^"]*)"/i.exec(tags[0])?.[1] ?? /\bcontent\s*=\s*'([^']*)'/i.exec(tags[0])?.[1];
          const want = `${modulePath} git ${REPO_URL}`;
          if (content !== want) E(`${label}: the go-import content is ${JSON.stringify(content ?? null)}, want ${JSON.stringify(want)}`);
        }
      }
    }
  }
}

if (errors.length) {
  for (const m of errors) console.error(`check-go-import: ${m}`);
  process.exit(1);
}
console.log(`check-go-import: ${modulePath} resolves to ${REPO_URL} through ${modulePath.slice(SITE_HOST.length + 1)}/index.html`);
