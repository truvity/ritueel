import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { addressOf, githubUrl, isPublished, isRecord, publishedDocs } from '../lib/published.mjs';

// A checkout with these docs files and this site/published.txt.
function tree(files, list) {
  const root = mkdtempSync(join(tmpdir(), 'published-'));
  for (const f of ['decisions/0001-a.md', 'decisions/0000-template.md', ...files]) {
    mkdirSync(dirname(join(root, 'docs', f)), { recursive: true });
    writeFileSync(join(root, 'docs', f), '# x\n');
  }
  mkdirSync(join(root, 'site'), { recursive: true });
  writeFileSync(join(root, 'site', 'published.txt'), list);
  return root;
}

test('the real allowlist parses, names only files, and lists no record', () => {
  const list = publishedDocs();
  assert.ok(list.length >= 15, `only ${list.length} pages are listed`);
  for (const f of list) assert.ok(!isRecord(f), `${f} is a record`);
  assert.ok(list.includes('index.mdx') && list.includes('glossary.md') && list.includes('reference/hand-off-contract.md'));
});

test('addresses', () => {
  assert.equal(addressOf('index.mdx'), '/');
  assert.equal(addressOf('learn/index.md'), '/learn/');
  assert.equal(addressOf('roadmap.md'), '/roadmap/');
  assert.equal(addressOf('contributing/tools.md'), '/contributing/tools/');
  assert.equal(githubUrl('learn/revoke.md'), 'https://github.com/truvity/ritueel/blob/main/docs/learn/revoke.md');
});

test('records are not published, nor is the template, and the list decides the rest', () => {
  const root = tree(['index.mdx', 'learn/a.md', 'learn/b.md'], '# c\nindex.mdx\n\nlearn/a.md\n');
  try {
    assert.deepEqual(publishedDocs(root), ['index.mdx', 'learn/a.md']);
    assert.ok(isPublished('learn/a.md', root));
    assert.ok(!isPublished('learn/b.md', root));
    assert.ok(!isPublished('decisions/0001-a.md', root));
    assert.ok(!isPublished('decisions/0000-template.md', root));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

for (const [name, list, message] of [
  ['a duplicate', 'index.mdx\nindex.mdx\n', /listed twice/],
  ['a missing file', 'index.mdx\nlearn/none.md\n', /not a file of docs/],
  ['a record', 'decisions/0001-a.md\n', /decision record/],
  ['an underscore name', '_x.md\n', /underscore/],
]) {
  test(`the list refuses ${name}`, () => {
    const root = tree(['index.mdx', '_x.md'], list);
    try {
      assert.throws(() => publishedDocs(root), message);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
