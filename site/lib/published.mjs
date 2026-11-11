// Which files of docs/ the site publishes, and where each one lives. Plain Node, no dependency:
// astro.config.mjs, src/content.config.ts, the scripts and the tests all import it.
//
// The list is site/published.txt. The decision records are published by the `decisions`
// collection and src/pages/decisions, not by the list.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const GITHUB_DOCS = 'https://github.com/truvity/ritueel/blob/main/docs/';

// Addresses of the site that are not a file of docs/ and are served as they are: the decisions
// index, the live status page, the demo and the Worker's data. Nothing may redirect from them.
export const OTHER_ADDRESSES = ['/decisions/', '/status/', '/demo/'];

/**
 * The repository root: the first directory above this file that has docs/decisions. A build may
 * run this code from a bundled chunk, which is still inside the checkout; the working directory
 * is the second place to look.
 */
export function repoRoot() {
  for (const start of [dirname(fileURLToPath(import.meta.url)), process.cwd()]) {
    for (let dir = start; ; dir = dirname(dir)) {
      if (existsSync(join(dir, 'docs', 'decisions'))) return dir;
      if (dirname(dir) === dir) break;
    }
  }
  throw new Error('published.mjs: no docs/decisions above ' + import.meta.url + ' or the working directory');
}

/** Every .md and .mdx file of docs/, as a sorted path relative to docs/ with forward slashes. */
export function docsFiles(root = repoRoot()) {
  const out = [];
  const walk = (dir, prefix) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix + entry.name;
      if (entry.isDirectory()) walk(join(dir, entry.name), rel + '/');
      else if (/\.mdx?$/.test(entry.name)) out.push(rel);
    }
  };
  walk(join(root, 'docs'), '');
  return out.sort();
}

/** A decision record: docs/decisions/NNNN-*.md, without the template (0000). */
export function isRecord(file) {
  return /^decisions\/\d{4}-.+\.md$/.test(file) && !file.startsWith('decisions/0000-');
}

/** The address a docs file has on the site (with the trailing slash the site uses). */
export function addressOf(file) {
  if (file === 'index.mdx' || file === 'index.md') return '/';
  const stem = file.replace(/\.mdx?$/, '').replace(/\/index$/, '');
  return `/${stem}/`;
}

/** The file on GitHub that a docs file is, on `main`. */
export function githubUrl(file) {
  return GITHUB_DOCS + file;
}

/**
 * The lines of site/published.txt, in order. Throws on a duplicate, on a path that is not a file
 * of docs/, on a decision record or the decisions folder, and on a name that starts with `_`:
 * a glob that matches nothing is silent, so a typo would unpublish a page without a word.
 */
export function publishedDocs(root = repoRoot()) {
  const text = readFileSync(join(root, 'site', 'published.txt'), 'utf8');
  const files = new Set(docsFiles(root));
  const list = [];
  const seen = new Set();
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    const at = `site/published.txt:${i + 1}`;
    if (seen.has(line)) throw new Error(`${at}: ${line} is listed twice`);
    seen.add(line);
    if (line.startsWith('decisions/')) {
      throw new Error(`${at}: ${line} is a decision record; the records are published without the list`);
    }
    if (line.split('/').some((part) => part.startsWith('_'))) {
      throw new Error(`${at}: ${line} starts with an underscore; such files are not pages`);
    }
    if (!files.has(line)) throw new Error(`${at}: ${line} is not a file of docs/`);
    list.push(line);
  });
  return list;
}

const cache = new Map();

/** Is this docs file a page of the site: on the list, or a decision record. */
export function isPublished(file, root = repoRoot()) {
  if (isRecord(file)) return true;
  let set = cache.get(root);
  if (!set) cache.set(root, (set = new Set(publishedDocs(root))));
  return set.has(file);
}

/**
 * The docs file behind a site path ("/learn/", "/contributing/tools", "learn/x.md"), looked up
 * under the folder `docs`, or undefined when there is none: the path is not a page of docs/ (the
 * status page, the demo, an asset, a stale address). An explicit .md or .mdx path is looked up
 * as it is written.
 */
export function fileOfPath(path, docs = join(repoRoot(), 'docs')) {
  const rel = path.replace(/^\/+/, '').replace(/\/+$/, '');
  if (/\.mdx?$/.test(rel)) return existsSync(join(docs, rel)) ? rel : undefined;
  const candidates = rel === '' ? ['index.mdx', 'index.md'] : [`${rel}.md`, `${rel}.mdx`, `${rel}/index.md`, `${rel}/index.mdx`];
  return candidates.find((c) => existsSync(join(docs, c)));
}
