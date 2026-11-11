import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, before, test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { docsLinksMdastPlugin, rewriteHref } from '../lib/docs-links.mjs';

const GH = 'https://github.com/truvity/ritueel/blob/main/docs/';
const REC = 'decisions/0007-ritueel-teaches.md';

// A small docs tree: four published pages, some that are not, a record (it has no page), the README and the template.
const published = new Set(['index.mdx', 'learn/index.md', 'learn/what-is-a-root.md', 'glossary.md']);
const files = [
  ...published,
  'reference/cards.md',
  'reference/index.md',
  'contributing.md',
  'contributing/tools.md',
  'learn/revoke.md',
  REC,
  'decisions/README.md',
  'decisions/0000-template.md',
];
let tmp;
let ctx;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'docs-links-'));
  for (const f of files) {
    mkdirSync(dirname(join(tmp, 'docs', f)), { recursive: true });
    writeFileSync(join(tmp, 'docs', f), '# x\n');
  }
  ctx = { docsRoot: join(tmp, 'docs'), isPublished: (f) => published.has(f) };
});
after(() => rmSync(tmp, { recursive: true, force: true }));

const cases = [
  // [href, source file, result]
  ['/reference/cards/#every-six-months', 'learn/what-is-a-root.md', GH + 'reference/cards.md#every-six-months'],
  ['/reference/cards/', REC, GH + 'reference/cards.md'],
  ['/reference/', 'learn/index.md', GH + 'reference/index.md'],
  ['/contributing/', 'index.mdx', GH + 'contributing.md'],
  ['/contributing/tools/#the-site', 'index.mdx', GH + 'contributing/tools.md#the-site'],
  ['/learn/revoke/', 'learn/index.md', GH + 'learn/revoke.md'],
  ['/learn/what-is-a-root/#why', REC, '/learn/what-is-a-root/#why'],
  ['/learn/', REC, '/learn/'],
  ['/', 'learn/index.md', '/'],
  ['/glossary/#bundle', REC, '/glossary/#bundle'],
  ['/decisions/0007-ritueel-teaches/', 'learn/index.md', GH + 'decisions/0007-ritueel-teaches.md'],
  ['/decisions/0007-ritueel-teaches/#status', 'reference/cards.md', GH + 'decisions/0007-ritueel-teaches.md#status'],
  ['decisions/0007-ritueel-teaches.md#why', 'index.mdx', GH + 'decisions/0007-ritueel-teaches.md#why'],
  // The old index has no file behind it any more: the address stays, and the redirect answers it.
  ['/decisions/', REC, '/decisions/'],
  ['/status/', REC, '/status/'],
  ['/demo/', REC, '/demo/'],
  ['/data/status.json', REC, '/data/status.json'],
  // A stale address has no file: it stays, so the validators still catch the mistake.
  ['/reference/glossary/', 'learn/index.md', '/reference/glossary/'],
  ['https://example.org/reference/cards/', 'learn/index.md', 'https://example.org/reference/cards/'],
  ['mailto:someone@example.org', 'learn/index.md', 'mailto:someone@example.org'],
  ['#local', 'learn/index.md', '#local'],
  ['', 'learn/index.md', ''],
  ['//example.org/reference/cards/', 'learn/index.md', '//example.org/reference/cards/'],
  ['/reference/cards/?x=1', 'learn/index.md', '/reference/cards/?x=1'],
  // Relative links to Markdown files.
  ['../reference/cards.md', 'learn/what-is-a-root.md', GH + 'reference/cards.md'],
  ['../reference/cards.md#a', 'learn/what-is-a-root.md', GH + 'reference/cards.md#a'],
  ['what-is-a-root.md', 'learn/index.md', 'what-is-a-root.md'],
  ['revoke.md', 'learn/index.md', GH + 'learn/revoke.md'],
  ['../index.mdx', 'learn/index.md', '../index.mdx'],
  ['../decisions/0000-template.md', 'learn/index.md', GH + 'decisions/0000-template.md'],
  ['../decisions/README.md', 'learn/index.md', GH + 'decisions/README.md'],
  ['/decisions/0000-template/', 'learn/index.md', GH + 'decisions/0000-template.md'],
  ['image.png', 'learn/index.md', 'image.png'],
  ['../../README.md', 'learn/index.md', '../../README.md'],
  ['/../../README.md', 'learn/index.md', '/../../README.md'],
  ['../../glossary.md', 'learn/x.md', '../../glossary.md'],
];

for (const [href, source, want] of cases) {
  test(`rewriteHref ${JSON.stringify(href)} in ${source}`, () => {
    assert.equal(rewriteHref(href, source, ctx), want);
  });
}

test('the plugin: none without a file URL or for a file outside docs/', () => {
  assert.equal(docsLinksMdastPlugin(undefined, ctx), undefined);
  assert.equal(docsLinksMdastPlugin(pathToFileURL(join(tmp, 'README.md')), ctx), undefined);
});

test('the plugin rewrites the url of a link and of a definition, and only that', () => {
  const plugin = docsLinksMdastPlugin(pathToFileURL(join(tmp, 'docs', REC)), ctx);
  assert.equal(plugin.name, 'ritueel-docs-links');
  const set = [];
  const context = { setProperty: (node, key, value) => set.push([node.url, key, value]) };
  plugin.link({ type: 'link', url: '/reference/cards/#a' }, context);
  plugin.definition({ type: 'definition', url: '/contributing/' }, context);
  plugin.link({ type: 'link', url: '/learn/' }, context);
  assert.deepEqual(set, [
    ['/reference/cards/#a', 'url', GH + 'reference/cards.md#a'],
    ['/contributing/', 'url', GH + 'contributing.md'],
  ]);
});
