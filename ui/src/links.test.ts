import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// The demo is public on the site it links to. A link to a page the site does not have is a
// dead end for the reader, and the page cannot tell: it only checks that a path is plain
// (learnPathOk). This test reads every made-up answer in fixtures/ and fails unless each
// site path in it is a page of the site (docs/, the repository's documentation, is the
// site's source) and each #anchor is a heading of that page.

const FIXTURES = new URL('./fixtures/', import.meta.url).pathname;
const DOCS = new URL('../../docs/', import.meta.url).pathname;

// The fields the page turns into a link to the site (LearnLink in ui/Page.tsx):
// Finding.learn_path and PlanStep.learn_path through FindingCard and Plan, and
// Ceremony.guide_path through History.
const SITE_LINK_FIELDS = new Set(['learnPath', 'guidePath']);
// Fields of a fixture that are a path on the person's own computer, not on the site.
// They are checked by their own test: never absolute, never a URL, never a way out of the folder.
const LOCAL_PATH_FIELDS = new Set(['savePath', 'folderPath', 'path']);

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

interface Found {
  file: string;
  at: string;
  field: string;
  value: string;
}

interface Sweep {
  links: Found[];
  unknownFields: Found[];
  localPaths: Found[];
  slashed: Found[];
}

function collect(file: string, v: Json, at: string, sweep: Sweep): void {
  if (Array.isArray(v)) v.forEach((x, i) => collect(file, x, `${at}[${i}]`, sweep));
  else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (typeof x === 'string') {
        const found = { file, at: `${at}.${k}`, field: k, value: x };
        if (SITE_LINK_FIELDS.has(k)) sweep.links.push(found);
        else {
          if (LOCAL_PATH_FIELDS.has(k)) sweep.localPaths.push(found);
          else if (/(path|url|href|link)$/i.test(k)) sweep.unknownFields.push(found);
          // A site path in a field with any other name (guide, page, docs ...) would go unchecked.
          if (x.startsWith('/')) sweep.slashed.push(found);
        }
      }
      collect(file, x, `${at}.${k}`, sweep);
    }
  }
}

const sweep: Sweep = { links: [], unknownFields: [], localPaths: [], slashed: [] };
for (const name of readdirSync(FIXTURES).filter((n) => n.endsWith('.json')).sort()) {
  collect(name, JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Json, '$', sweep);
}
const { links, unknownFields, localPaths, slashed } = sweep;

/** The file that is the page at a site path such as /a/b/, or undefined. */
function pageFile(path: string): string | undefined {
  const rel = path.replace(/^\/|\/$/g, '');
  // The site serves /a/b/, never /a/b/index/; and it has no empty, "." or ".." segment.
  if (rel !== '' && rel.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) return undefined;
  if (/(^|\/)index$/.test(rel)) return undefined;
  const candidates = rel === '' ? ['index.md', 'index.mdx'] : [`${rel}.md`, `${rel}.mdx`, `${rel}/index.md`, `${rel}/index.mdx`];
  const root = resolve(DOCS);
  const file = candidates.map((c) => resolve(DOCS, c)).find((c) => c.startsWith(root + '/') && existsSync(c));
  // A draft page is not published.
  if (file && /^---\n[\s\S]*?\ndraft:\s*true\s*\n[\s\S]*?\n---/.test(readFileSync(file, 'utf8'))) return undefined;
  return file;
}

/** The ids the site gives the headings of a page: GitHub's slugs, as Starlight makes them. */
function headingIds(file: string): Set<string> {
  const ids = new Set<string>();
  const seen = new Map<string, number>();
  let fence = '';
  let front = false;
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (i === 0 && line.trim() === '---') front = true;
    else if (front) {
      if (line.trim() === '---') front = false;
      return;
    }
    const f = /^\s{0,3}(```+|~~~+)/.exec(line);
    if (f) {
      if (!fence) fence = f[1][0];
      else if (f[1][0] === fence) fence = '';
      return;
    }
    if (fence) return;
    const m = /^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$/.exec(line);
    if (!m) return;
    const text = m[2]
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/`/g, '')
      .replace(/\*/g, '')
      .replace(/(^|\W)_(.+?)_(?=\W|$)/g, '$1$2')
      .replace(/<[^>]+>/g, '');
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\p{M}_ -]/gu, '')
      .replace(/ /g, '-');
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    ids.add(n === 0 ? base : `${base}-${n}`);
  });
  return ids;
}

describe('the demo links only to pages the site has', () => {
  it('finds the links (an empty sweep proves nothing)', () => {
    expect(links.length).toBeGreaterThan(20);
    expect(new Set(links.map((l) => l.field))).toEqual(SITE_LINK_FIELDS);
    expect(new Set(links.map((l) => l.value)).size).toBeGreaterThan(10);
  });

  it('knows every field of a fixture that looks like a link', () => {
    // A new link-like field must be added to SITE_LINK_FIELDS (and so checked) or to LOCAL_PATH_FIELDS.
    expect(unknownFields.map((f) => `${f.file} ${f.at}`)).toEqual([]);
  });

  it('puts no site path in a field that is not checked as a link', () => {
    expect(slashed.map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('keeps a path on the computer relative to its folder: no URL, no "..", no anchor', () => {
    expect(localPaths.length).toBeGreaterThan(20);
    const bad = localPaths.filter((f) => f.value.includes('://') || f.value.includes('..') || f.value.includes('#') || f.value.startsWith('/'));
    expect(bad.map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('finds the site pages and their headings', () => {
    expect(pageFile('/')).toBeDefined();
    expect(pageFile('/learn/')).toBeDefined();
    expect(pageFile('/reference/cli/')).toBeDefined();
    expect(pageFile('/learn/no-such-page/')).toBeUndefined();
    // The site serves /learn/, not /learn/index/, and no path that climbs out of docs/.
    expect(pageFile('/learn/index/')).toBeUndefined();
    expect(pageFile('/learn//ceremonies/')).toBeUndefined();
    expect(pageFile('/learn/../index/')).toBeUndefined();
    expect(pageFile('/x/../../README/')).toBeUndefined();
    const cards = pageFile('/reference/cards/');
    expect(cards).toBeDefined();
    const ids = headingIds(cards as string);
    expect(ids.has('every-six-months')).toBe(true);
    expect(ids.has('resultjson')).toBe(true);
    expect(ids.has('no-such-heading')).toBe(false);
  });

  it('every link is a path of the site, with the trailing slash the site uses', () => {
    // Each segment starts and ends with a letter or digit, so there is no "", "." or ".." segment.
    const bad = links.filter((l) => !/^(\/[a-z0-9]+(?:[a-z0-9_.-]*[a-z0-9])?)+\/(#[a-z0-9_-]+)?$/.test(l.value));
    expect(bad.map((l) => `${l.file} ${l.at}: ${l.value}`)).toEqual([]);
  });

  it('every link has a page in docs/', () => {
    const bad = links.filter((l) => !pageFile(l.value.split('#')[0]));
    expect(bad.map((l) => `${l.file} ${l.at}: ${l.value} has no page in docs/`)).toEqual([]);
  });

  it('every #anchor is a heading of its page', () => {
    const bad: string[] = [];
    for (const l of links) {
      const [path, anchor] = l.value.split('#');
      const file = pageFile(path);
      if (!file || anchor === undefined) continue;
      if (!headingIds(file).has(anchor)) bad.push(`${l.file} ${l.at}: ${l.value} (no heading "${anchor}")`);
    }
    expect(bad).toEqual([]);
  });
});
