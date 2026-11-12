import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { answerJson } from './testkit';

// The demo is public on the site it links to. A link to a page the site does not have is a
// dead end for the reader, and the page cannot tell: it only checks that a path is plain
// (learnPathOk). This test reads every made-up answer in fixtures/ and fails unless each
// site path in it is a PUBLISHED page of the site and each #anchor is a heading of that page.
// docs/ is the site's source, but the site publishes only the pages listed in
// site/published.txt; the rest of docs/ (the decision records among it) stays in the
// repository as working material and has no page. A link to such a page is a dead end too.

const FIXTURES = new URL('./fixtures/', import.meta.url).pathname;
const DOCS = new URL('../../docs/', import.meta.url).pathname;
const PUBLISHED_LIST = new URL('../../site/published.txt', import.meta.url).pathname;

// The allowlist of the site, read as a plain file (no import across packages): one path
// relative to docs/ for each line, `#` starts a comment. The decision records are not in it.
const PUBLISHED: string[] = readFileSync(PUBLISHED_LIST, 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line !== '' && !line.startsWith('#'));
const PUBLISHED_SET = new Set(PUBLISHED);

// The fields the page turns into a link to the site (LearnLink in ui/Page.tsx):
// Finding.learn_path through FindingCard, and Ceremony.guide_path through the
// panel of a ceremony.
const SITE_LINK_FIELDS = new Set(['learnPath', 'guidePath']);
// Fields of a fixture that are a path on the person's own computer, not on the site:
// Change.wanted_path, Root.wanted_path, Delegation.wanted_path, Request.answer_path
// and the path of a bundle, a place, a request and a trust file.
// They are checked by their own test: never absolute, never a URL, never a way out of the bundle.
const LOCAL_PATH_FIELDS = new Set(['wantedPath', 'path', 'answerPath']);

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
// The fixtures sit in one directory for each example bundle (acme, globex, personal), five
// call files each, and acme also holds scenes.json. Walk all of them: a link in a bundle the
// demo shows only after the switch is as public as one on the first screen. The answers of
// the five scenes (the base files with the patches put in) are walked too.
function fixtureFiles(dir = ''): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(FIXTURES, dir)).sort()) {
    const rel = dir ? `${dir}/${name}` : name;
    if (statSync(join(FIXTURES, rel)).isDirectory()) out.push(...fixtureFiles(rel));
    else if (name.endsWith('.json')) out.push(rel);
  }
  return out;
}
const FIXTURE_FILES = fixtureFiles();
for (const name of FIXTURE_FILES) {
  collect(name, JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Json, '$', sweep);
}
for (const scene of [1, 2, 3, 4, 5])
  for (const call of ['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles'] as const)
    collect(`acme scene ${scene} ${call}`, answerJson('acme', scene, call) as Json, '$', sweep);
const { links, unknownFields, localPaths, slashed } = sweep;

/** The file that is the PUBLISHED page at a site path such as /a/b/, or undefined (a file of docs/ that the site does not publish has no page). */
function pageFile(path: string): string | undefined {
  const rel = path.replace(/^\/|\/$/g, '');
  // The site serves /a/b/, never /a/b/index/; and it has no empty, "." or ".." segment.
  if (rel !== '' && rel.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) return undefined;
  if (/(^|\/)index$/.test(rel)) return undefined;
  const candidates = rel === '' ? ['index.md', 'index.mdx'] : [`${rel}.md`, `${rel}.mdx`, `${rel}/index.md`, `${rel}/index.mdx`];
  const root = resolve(DOCS);
  const file = candidates
    .filter((c) => PUBLISHED_SET.has(c))
    .map((c) => resolve(DOCS, c))
    .find((c) => c.startsWith(root + '/') && existsSync(c));
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
    let text = m[2]
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/`/g, '')
      .replace(/\*/g, '')
      .replace(/(^|\W)_(.+?)_(?=\W|$)/g, '$1$2');
    // Drop inline HTML tags until none is left, so a tag nested in another one cannot survive a single pass.
    for (let prev = ''; prev !== text; ) {
      prev = text;
      text = text.replace(/<[^>]+>/g, '');
    }
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

/** A link to a file of docs/ that exists but that the site does not publish. */
function isRepositoryOnly(value: string): boolean {
  const rel = value.split('#')[0].replace(/^\/|\/$/g, '');
  if (pageFile(value.split('#')[0])) return false;
  return [`${rel}.md`, `${rel}.mdx`, `${rel}/index.md`, `${rel}/index.mdx`].some((c) => existsSync(join(DOCS, c)));
}

describe('the demo links only to pages the site has', () => {
  it('walks every example bundle (an empty walk proves nothing)', () => {
    const dirs = new Set(FIXTURE_FILES.filter((f) => f.includes('/')).map((f) => f.split('/')[0]));
    expect(dirs).toEqual(new Set(['acme', 'globex', 'personal']));
    // A fixture directly in fixtures/ would be answered for no bundle: the demo reads only <bundle>/.
    expect(FIXTURE_FILES.filter((f) => !f.includes('/'))).toEqual([]);
    // Each bundle holds the five call files, and acme also its scenes.
    for (const call of ['get-summary', 'list-findings', 'get-inventory', 'list-ceremonies', 'list-trust-files'])
      for (const b of ['acme', 'globex', 'personal']) expect(FIXTURE_FILES, `${b}/${call}`).toContain(`${b}/inspect.${call}.json`);
    expect(FIXTURE_FILES).toContain('acme/scenes.json');
    expect(FIXTURE_FILES.filter((f) => f.endsWith('scenes.json'))).toEqual(['acme/scenes.json']);
  });

  it('finds the links (an empty sweep proves nothing)', () => {
    expect(links.length).toBeGreaterThan(20);
    expect(new Set(links.map((l) => l.field))).toEqual(SITE_LINK_FIELDS);
    expect(new Set(links.map((l) => l.value)).size).toBeGreaterThanOrEqual(2);
  });

  it('knows every field of a fixture that looks like a link', () => {
    // A new link-like field must be added to SITE_LINK_FIELDS (and so checked) or to LOCAL_PATH_FIELDS.
    expect(unknownFields.map((f) => `${f.file} ${f.at}`)).toEqual([]);
  });

  it('puts no site path in a field that is not checked as a link', () => {
    expect(slashed.map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('keeps a path on the computer relative to its bundle: no URL, no "..", no anchor', () => {
    expect(localPaths.length).toBeGreaterThan(20);
    const bad = localPaths.filter((f) => f.value.includes('://') || f.value.includes('..') || f.value.includes('#') || f.value.startsWith('/'));
    expect(bad.map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('names no path inside a ceremony folder and no pending area (the page lists no plan file)', () => {
    expect(localPaths.filter((f) => /^history\//.test(f.value) || /pending/.test(f.value) || f.value.endsWith('.plan')).map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
    // A path that starts with ~ is the place of a bundle, or the key file of a personal root, which is kept apart from the bundle.
    expect(localPaths.filter((f) => f.value.startsWith('~') && !/^~\/ritueel\/[a-z]+$/.test(f.value) && !/^~\/keys\/[a-z]+\/[A-Za-z0-9.]+\.age$/.test(f.value)).map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('finds the site pages and their headings', () => {
    expect(pageFile('/')).toBeDefined();
    expect(pageFile('/learn/')).toBeDefined();
    // A page of the repository that the site does not publish is no page of the site.
    expect(pageFile('/reference/cli/'), 'is a page of the repository, not of the site').toBeUndefined();
    expect(pageFile('/reference/cards/'), 'is a page of the repository, not of the site').toBeUndefined();
    expect(pageFile('/reference/hand-off-contract/')).toBeDefined();
    expect(pageFile('/design/')).toBeDefined();
    expect(pageFile('/learn/no-such-page/')).toBeUndefined();
    // The site serves /learn/, not /learn/index/, and no path that climbs out of docs/.
    expect(pageFile('/learn/index/')).toBeUndefined();
    expect(pageFile('/learn//ceremonies/')).toBeUndefined();
    expect(pageFile('/learn/../index/')).toBeUndefined();
    expect(pageFile('/x/../../README/')).toBeUndefined();
    expect(pageFile('/learn/how-a-yubikey-holds-keys/')).toBeDefined();
    expect(pageFile('/glossary/')).toBeDefined();
    // The headings of the design page that the page links to, as the site gives them ids.
    const design = headingIds(pageFile('/design/') as string);
    expect(design.has('where-a-root-is-used')).toBe(true);
    expect(design.has('cards')).toBe(true);
    expect(design.has('no-such-heading')).toBe(false);
  });

  it('every listed page is a file', () => {
    // A line of site/published.txt that names no file would publish nothing; an empty list proves nothing.
    expect(PUBLISHED.length).toBeGreaterThan(10);
    expect(new Set(PUBLISHED).size).toBe(PUBLISHED.length);
    const missing = PUBLISHED.filter((p) => !existsSync(join(DOCS, p)));
    expect(missing).toEqual([]);
  });

  it('every link is a path of the site, with the trailing slash the site uses', () => {
    // Each segment starts and ends with a letter or digit, so there is no "", "." or ".." segment.
    const bad = links.filter((l) => !/^(?:\/[a-z0-9]+(?:[_.-]+[a-z0-9]+)*)+\/(?:#[a-z0-9_-]+)?$/.test(l.value));
    expect(bad.map((l) => `${l.file} ${l.at}: ${l.value}`)).toEqual([]);
  });

  it('every link has a page in docs/', () => {
    const bad = links.filter((l) => !pageFile(l.value.split('#')[0]) && !isRepositoryOnly(l.value));
    expect(bad.map((l) => `${l.file} ${l.at}: ${l.value} has no page in docs/`)).toEqual([]);
  });

  it('every link is a published page', () => {
    const bad = links.filter((l) => isRepositoryOnly(l.value));
    expect(bad.map((l) => `${l.file} ${l.at}: ${l.value} is not published: add it to site/published.txt or link a published page`)).toEqual([]);
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

// A link written in the source of the page, not in a fixture: LearnLink path="..." and a learnPath string.
// The fixtures are walked above; these were not, so a typo here reached the site as a dead end.
describe('the static links of the source are published pages', () => {
  const SRC = new URL('./', import.meta.url).pathname;
  const files = ['ui', 'screens'].flatMap((dir) => readdirSync(join(SRC, dir)).filter((n) => n.endsWith('.tsx')).map((n) => `${dir}/${n}`));
  const found: Found[] = [];
  for (const f of files) {
    const text = readFileSync(join(SRC, f), 'utf8');
    for (const m of text.matchAll(/LearnLink\s+path="([^"]+)"/g)) found.push({ file: f, at: 'LearnLink', field: 'path', value: m[1] });
    for (const m of text.matchAll(/learnUrl\(\s*'([^']+)'\s*\)/g)) found.push({ file: f, at: 'learnUrl', field: 'path', value: m[1] });
    for (const m of text.matchAll(/learnPath\s*[:=]\s*['"]([^'"]+)['"]/g)) found.push({ file: f, at: 'learnPath', field: 'learnPath', value: m[1] });
  }

  it('finds the links (an empty sweep proves nothing)', () => {
    expect(files.length).toBeGreaterThan(10);
    const values = new Set(found.map((l) => l.value));
    for (const v of ['/glossary/', '/design/#after-a-ceremony']) expect(values.has(v), v).toBe(true);
  });

  it('every one is a path of the site, a published page, and an anchor that is a heading of it', () => {
    const bad: string[] = [];
    for (const l of found) {
      const [path, anchor] = l.value.split('#');
      if (!/^(?:\/[a-z0-9]+(?:[_.-]+[a-z0-9]+)*)+\/(?:#[a-z0-9_-]+)?$/.test(l.value)) bad.push(`${l.file}: ${l.value} is not a path of the site`);
      const file = pageFile(path);
      if (!file) {
        bad.push(`${l.file}: ${l.value} is not a published page`);
        continue;
      }
      if (anchor !== undefined && !headingIds(file).has(anchor)) bad.push(`${l.file}: ${l.value} (no heading "${anchor}")`);
    }
    expect(bad).toEqual([]);
  });
});
