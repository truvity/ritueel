#!/usr/bin/env node
// The links of the built pages into this repository on GitHub, checked against this checkout:
// https://github.com/truvity/ritueel/(blob|tree)/main/<path>[#fragment].
//
// lychee.toml leaves them out (a page that a pull request adds has no address on `main` yet), and
// the link plugin (site/lib/docs-links.mjs) writes a link to a file on GitHub for every link to a
// page that the site does not publish, so this check stands in for lychee on exactly those links:
//
// - <path> is a file of the checkout (a directory, for `tree`);
// - the #fragment of a link to a Markdown file is one of the ids GitHub gives its headings; a
//   fragment like L12 (a line) is allowed on any other file.
//
// It fails closed: a sweep that finds few links proves nothing, so it needs at least 100 links in
// all and 15 on the design page. Edit links (/edit/main/) stay with check-edit-links.mjs.
//
// usage: check-github-links.mjs [dist]   (default site/dist, relative to the repository root)
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { githubHeadingIds } from '../lib/headings.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const dist = join(root, process.argv[2] ?? 'site/dist');
const MIN_ALL = 100;
const MIN_DESIGN = 15;
const LINK = /\bhref="(https:\/\/github\.com\/truvity\/ritueel\/(blob|tree)\/main\/[^"]*)"/g;

function* pages(dir) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* pages(path);
    else if (name.endsWith('.html')) yield path;
  }
}

const decode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

const ids = new Map();
const headingIds = (file) => {
  if (!ids.has(file)) ids.set(file, githubHeadingIds(readFileSync(join(root, file), 'utf8')));
  return ids.get(file);
};

const problems = [];
let all = 0;
let onDesign = 0;
const seen = new Set();

for (const page of pages(dist)) {
  const where = relative(dist, page);
  const html = readFileSync(page, 'utf8');
  for (const m of html.matchAll(LINK)) {
    all++;
    if (where === 'design/index.html') onDesign++;
    const url = m[1].replaceAll('&amp;', '&');
    const key = `${where} ${url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const rest = url.slice(url.indexOf('/main/') + '/main/'.length);
    const hash = rest.indexOf('#');
    const path = trimSlashes(decode(hash === -1 ? rest : rest.slice(0, hash)));
    const fragment = hash === -1 ? '' : decode(rest.slice(hash + 1));
    const full = join(root, path);
    if (path === '' || path.split('/').includes('..') || !existsSync(full)) {
      problems.push(`${where}: ${url} names ${path || '(the root)'}, which is not in this checkout`);
      continue;
    }
    if (m[2] === 'blob' && statSync(full).isDirectory()) {
      problems.push(`${where}: ${url} is a blob link to a directory`);
      continue;
    }
    if (fragment === '') continue;
    if (/\.mdx?$/.test(path)) {
      if (!headingIds(path).has(fragment)) problems.push(`${where}: ${url} has no heading "${fragment}" in ${path}`);
    } else if (!/^L\d+(-L\d+)?$/.test(fragment)) {
      problems.push(`${where}: ${url} has a fragment that is not a line (${fragment}) on a file that is not Markdown`);
    }
  }
}

if (all < MIN_ALL || onDesign < MIN_DESIGN) {
  problems.push(
    `found ${all} links into the repository (${onDesign} on the design page); an empty sweep proves nothing, and at least ${MIN_ALL} (${MIN_DESIGN}) are expected`,
  );
}
if (problems.length) {
  for (const p of problems) console.error(`check-github-links: ${p}`);
  process.exit(1);
}
console.log(`check-github-links: ok (${all} links, ${onDesign} on the design page)`);

/** The text without the slashes at its end. */
function trimSlashes(text) {
  let end = text.length;
  while (end > 0 && text[end - 1] === '/') end--;
  return text.slice(0, end);
}
