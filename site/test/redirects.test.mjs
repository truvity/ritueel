import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { BEGIN, END, buildRedirects, oldRecordRules, unpublishedFiles } from '../scripts/gen-redirects.mjs';

const GH = 'https://github.com/truvity/ritueel/blob/main/docs/';
const SHA = '1634be413c5e7d8d173e421928665ba30971a46e';
const AT = `https://github.com/truvity/ritueel/blob/${SHA}/docs/decisions/`;
const OLD = `commit ${SHA}\n0001-first-name 0001-first-name.md\n0001-older-name 0001-first-name.md\n0002-second 0002-second.md\n`;

function tree(published, redirects, old = OLD) {
  const root = mkdtempSync(join(tmpdir(), 'redirects-'));
  const files = [
    'index.mdx', 'learn/index.md', 'learn/a.md', 'learn/b.md', 'reference/c.md', 'reference/index.md', 'contributing.md',
    'decisions/README.md', 'decisions/0000-template.md', 'decisions/0001-x.md',
  ];
  for (const f of files) {
    mkdirSync(dirname(join(root, 'docs', f)), { recursive: true });
    writeFileSync(join(root, 'docs', f), '# x\n');
  }
  mkdirSync(join(root, 'site', 'public'), { recursive: true });
  writeFileSync(join(root, 'site', 'published.txt'), published.join('\n') + '\n');
  writeFileSync(join(root, 'site', 'old-records.txt'), `# the old records\n\n${old}`);
  return { root, redirects };
}
const run = (published, redirects, old) => {
  const t = tree(published, redirects, old);
  try {
    return buildRedirects(t.root, redirects);
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
};
const base = ['index.mdx', 'learn/index.md', 'learn/a.md'];
const hand = [
  '# comment kept',
  '/old-a/ /learn/a/ 301',
  '/old-b/ /learn/b/ 301',
  '/old-rec/ /decisions/0001-x/ 301',
  '/old-status/ /status/ 301',
  '/old-gh/ ' + GH + 'learn/b.md#top 302',
].join('\n');

test('a published alias stays 301, an unpublished one and a record go to GitHub with a 302, with no chain', () => {
  const out = run(base, hand).split('\n');
  assert.ok(out.includes('# comment kept'));
  assert.ok(out.includes('/old-a/ /learn/a/ 301'));
  assert.ok(out.includes('/old-b/ ' + GH + 'learn/b.md 302'));
  assert.ok(out.includes('/old-rec/ ' + GH + 'decisions/0001-x.md 302'));
  assert.ok(out.includes('/old-status/ /status/ 301'));
  assert.ok(out.includes('/old-gh/ ' + GH + 'learn/b.md#top 302'));
});

test('the block holds the old records, then one 302 for each unpublished page, sorted, and not the records or the template', () => {
  const out = run(base, hand);
  const block = out.slice(out.indexOf(BEGIN)).split('\n');
  assert.deepEqual(block.slice(1, -2), [
    // the hand lines without their closing slash, in the order of the hand lines
    '/old-a /learn/a/ 301',
    '/old-b ' + GH + 'learn/b.md 302',
    '/old-rec ' + GH + 'decisions/0001-x.md 302',
    '/old-status /status/ 301',
    '/old-gh ' + GH + 'learn/b.md#top 302',
    // the old records, sorted, with and without the closing slash, 301 to the file at the commit
    `/decisions/0001-first-name/ ${AT}0001-first-name.md 301`,
    `/decisions/0001-first-name ${AT}0001-first-name.md 301`,
    `/decisions/0001-older-name/ ${AT}0001-first-name.md 301`,
    `/decisions/0001-older-name ${AT}0001-first-name.md 301`,
    `/decisions/0002-second/ ${AT}0002-second.md 301`,
    `/decisions/0002-second ${AT}0002-second.md 301`,
    '/contributing/ ' + GH + 'contributing.md 302',
    '/contributing ' + GH + 'contributing.md 302',
    '/learn/b/ ' + GH + 'learn/b.md 302',
    '/learn/b ' + GH + 'learn/b.md 302',
    '/reference/ ' + GH + 'reference/index.md 302',
    '/reference ' + GH + 'reference/index.md 302',
    '/reference/c/ ' + GH + 'reference/c.md 302',
    '/reference/c ' + GH + 'reference/c.md 302',
  ]);
  assert.equal(block[block.length - 2], END);
});

test('publishing a page again turns its alias back to a 301 and takes its line out of the block', () => {
  const first = run(base, hand);
  const out = run([...base, 'learn/b.md'], first);
  assert.ok(out.split('\n').includes('/old-b/ /learn/b/ 301'));
  assert.ok(out.split('\n').includes('/old-gh/ /learn/b/#top 301'));
  assert.ok(!out.includes('/learn/b/ https://'));
});

test('a hand line with a hand line for its no-slash form is not repeated', () => {
  const out = run(base, hand + '\n/old-a /learn/a/ 301');
  assert.equal(out.split('\n').filter((l) => l.startsWith('/old-a ')).length, 1);
});

test('a second run changes nothing', () => {
  const first = run(base, hand);
  assert.equal(run(base, first), first);
});

test('an address with a hand line is not generated again', () => {
  const out = run(base, hand + '\n/learn/b/ ' + GH + 'learn/b.md 302');
  assert.equal(out.split('\n').filter((l) => l.startsWith('/learn/b/ ')).length, 1);
});

test('a duplicate source, a published source and a missing file are refused', () => {
  assert.throws(() => run(base, '/x/ /learn/a/ 301\n/x/ /learn/a/ 301'), /two rules/);
  assert.throws(() => run(base, '/learn/a/ /learn/ 301'), /published address/);
  assert.throws(() => run(base, '/status/ /learn/ 301'), /published address/);
  assert.throws(() => run(base, '/x/ ' + GH + 'learn/none.md 302'), /not a file of docs/);
  assert.throws(() => run(base, '/x/ /learn/'), /not "from to code"/);
});

test('unpublishedFiles leaves out the records, the decisions README and the template', () => {
  const t = tree(base, '');
  try {
    assert.deepEqual(unpublishedFiles(t.root), ['contributing.md', 'learn/b.md', 'reference/c.md', 'reference/index.md']);
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});

test('the old records: both slash forms, one hop to the pinned commit, a second run changes nothing', () => {
  const first = run(base, hand);
  const lines = first.split('\n');
  for (const stem of ['0001-first-name', '0001-older-name', '0002-second']) {
    assert.equal(lines.filter((l) => l.startsWith(`/decisions/${stem}/ `) || l.startsWith(`/decisions/${stem} `)).length, 2);
  }
  assert.ok(lines.filter((l) => l.includes(`/blob/${SHA}/`)).every((l) => l.endsWith(' 301') && l.split(' ').length === 3));
  assert.equal(run(base, first), first);
});

test('the old records refuse a bad sha, a bad name, a duplicate stem and a live address', () => {
  const bad = (old, message) => assert.throws(() => run(base, hand, old), message);
  bad('commit 1634be4\n0001-a 0001-a.md\n', /40 hex/);
  bad('0001-a 0001-a.md\n', /no "commit/);
  bad(`commit ${SHA}\n`, /no old address/);
  bad(`commit ${SHA}\n0001-a 0001-a.md\n0001-a 0001-b.md\n`, /listed twice/);
  bad(`commit ${SHA}\n0001-a Bad_Name.md\n`, /not "<address stem>/);
  bad(`commit ${SHA}\n0001-a ../0001-a.md\n`, /not "<address stem>/);
  bad(`commit ${SHA}\ncommit ${SHA}\n0001-a 0001-a.md\n`, /second commit/);
  // a stem that is also the source of a hand line, and a stem that is a published address
  assert.throws(() => run(base, hand + '\n/decisions/0001-a/ /learn/a/ 301', `commit ${SHA}\n0001-a 0001-a.md\n`), /two rules/);
  assert.throws(() => run([...base, 'decisions/0001-a.md'], hand, OLD), /decision record/);
});

test('oldRecordRules reads the file and sorts the rules', () => {
  const t = tree(base, '');
  try {
    const { sha, stems, rules } = oldRecordRules(t.root);
    assert.equal(sha, SHA);
    assert.equal(stems.size, 3);
    assert.equal(rules.length, 6);
  } finally {
    rmSync(t.root, { recursive: true, force: true });
  }
});
