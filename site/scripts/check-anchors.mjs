#!/usr/bin/env node
// Links in the built decision pages (dist/decisions/**), which starlight-links-validator does
// not see because the pages are generated in src/pages. Every in-site link must lead to a built
// page, and every #anchor to an element with that id on the target page. External links are
// lychee's job (`just site-links`).
//
// usage: site/scripts/check-anchors.mjs [dist]
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const dist = process.argv[2] ?? 'site/dist';
const root = join(dist, 'decisions');
const errors = [];
const ids = new Map();
const idsOf = (file) => {
  if (!ids.has(file)) ids.set(file, new Set([...readFileSync(file, 'utf8').matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  return ids.get(file);
};
const pages = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (name.endsWith('.html')) pages.push(p);
  }
};
if (existsSync(root)) walk(root);

let links = 0;
for (const page of pages) {
  const html = readFileSync(page, 'utf8');
  for (const m of html.matchAll(/\shref="([^"]+)"/g)) {
    const href = m[1].replaceAll('&amp;', '&');
    if (/^[a-z][a-z0-9+.-]*:|^\/\//i.test(href)) continue; // external or another scheme
    const [path, frag] = href.split('#');
    if (path && !path.startsWith('/')) continue; // relative asset paths, none expected
    if (/^\/(_astro|pagefind)\//.test(path) || /\.[a-z0-9]+$/i.test(path)) continue; // assets
    links++;
    const target = path ? join(dist, path, path.endsWith('/') ? 'index.html' : '') : page;
    if (!existsSync(target) || statSync(target).isDirectory()) { errors.push(`${page}: ${href}: no built page at ${path}`); continue; }
    if (frag && frag !== '_top' && !idsOf(target).has(decodeURIComponent(frag))) errors.push(`${page}: ${href}: no element with id "${frag}"`);
  }
}
for (const e of errors) console.error(`check-anchors: ${e}`);
if (errors.length) process.exit(1);
if (!links) { console.error('check-anchors: no in-site link found in the decision pages; an empty sweep proves nothing'); process.exit(1); }
console.log(`check-anchors: ${links} in-site links in ${pages.length} decision pages, all resolve`);
