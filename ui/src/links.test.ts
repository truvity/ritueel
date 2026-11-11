import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

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
// Finding.learn_path and PlanStep.learn_path through FindingCard and Plan, and
// Ceremony.guide_path through History.
const SITE_LINK_FIELDS = new Set(['learnPath', 'guidePath']);
// Fields of a fixture that are a path on the person's own computer, not on the site.
// They are checked by their own test: never absolute, never a URL, never a way out of the bundle.
const LOCAL_PATH_FIELDS = new Set(['savePath', 'bundlePath', 'path']);

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
// The fixtures sit in one directory for each example bundle (personal, acme, globex) and in
// common/, the answers they share. Walk all of them: a link in a bundle the demo shows only
// after the switch is as public as one on the first screen.
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
  it('walks every example bundle and the shared answers (an empty walk proves nothing)', () => {
    const dirs = new Set(FIXTURE_FILES.filter((f) => f.includes('/')).map((f) => f.split('/')[0]));
    expect(dirs).toEqual(new Set(['personal', 'acme', 'globex', 'common']));
    // A fixture directly in fixtures/ would be answered for no bundle: the demo reads only <bundle>/ and common/.
    expect(FIXTURE_FILES.filter((f) => !f.includes('/'))).toEqual([]);
    // The bundles hold the same call-named files, so a reader finds the same files in each.
    for (const call of ['inspect.get-summary.json', 'inspect.list-roots.json', 'inspect.list-cards.json', 'manifest.json']) {
      for (const b of ['personal', 'acme', 'globex']) expect(FIXTURE_FILES, `${b}/${call}`).toContain(`${b}/${call}`);
    }
  });

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

  it('keeps a path on the computer relative to its bundle: no URL, no "..", no anchor', () => {
    expect(localPaths.length).toBeGreaterThan(20);
    const bad = localPaths.filter((f) => f.value.includes('://') || f.value.includes('..') || f.value.includes('#') || f.value.startsWith('/'));
    expect(bad.map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
  });

  it('saves a plan as history/<ceremony>/plan.json (record 0006 rule 7)', () => {
    // Every savePath of a plan and every path of a saved plan names the ceremony twice: the
    // directory and the plan's id. The ceremony is the time in UTC, a hyphen and the command.
    const CEREMONY = '[0-9]{8}T[0-9]{6}Z-[a-z0-9]+(?:-[a-z0-9]+)*';
    const saved = localPaths.filter((f) => f.field === 'savePath' || (f.file.includes('plan.save-plan.') && f.field === 'path'));
    expect(saved.length).toBeGreaterThanOrEqual(6);
    expect(new Set(saved.map((f) => f.field))).toEqual(new Set(['savePath', 'path']));
    const re = new RegExp(`^history/(${CEREMONY})/plan\\.json$`);
    expect(saved.filter((f) => !re.test(f.value)).map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
    // The run command and the bundle path of a saved plan agree with it.
    for (const name of FIXTURE_FILES.filter((n) => n.includes('plan.save-plan.'))) {
      const d = JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as { planId: string; path: string; bundlePath: string; runCommand: string };
      // common/ is shared by every bundle: the demo puts the path of the open bundle in its place.
      const bundle = name.startsWith('common/') ? 'example' : name.split('/')[0];
      expect(d.path, name).toBe(`history/${d.planId}/plan.json`);
      expect(d.bundlePath, name).toBe(`~/ritueel/${bundle}`);
      const prefix = `ritueel --dir ~/ritueel/${bundle} run history/${d.planId}/plan.json --confirm `;
      expect(d.runCommand.startsWith(prefix), name).toBe(true);
      expect(d.runCommand.slice(prefix.length), name).toMatch(/^[0-9a-f]{64}$/);
    }
    // No plan is written in a pending area any more.
    expect(localPaths.filter((f) => /pending/.test(f.value) || f.value.endsWith('.plan')).map((f) => `${f.file} ${f.at}: ${f.value}`)).toEqual([]);
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
    for (const m of text.matchAll(/learnPath\s*[:=]\s*['"]([^'"]+)['"]/g)) found.push({ file: f, at: 'learnPath', field: 'learnPath', value: m[1] });
  }

  it('finds the links (an empty sweep proves nothing)', () => {
    expect(files.length).toBeGreaterThan(10);
    const values = new Set(found.map((l) => l.value));
    for (const v of ['/glossary/', '/learn/what-is-a-root/', '/learn/where-a-root-is-used/']) expect(values.has(v), v).toBe(true);
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
