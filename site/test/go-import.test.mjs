import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const script = join(repo, 'site', 'scripts', 'check-go-import.mjs');
const GOOD = 'ritueel.id/ritueel git https://github.com/truvity/ritueel';
const page = (head) => `<!doctype html><html><head><meta charset="utf-8">${head}</head><body></body></html>`;
const tag = (content) => `<meta name="go-import" content="${content}">`;

// A scratch checkout with this go.mod and, if given, this page at <dist>/ritueel/index.html.
function tree(gomod, html, at = 'ritueel') {
  const root = mkdtempSync(join(tmpdir(), 'go-import-'));
  writeFileSync(join(root, 'go.mod'), gomod);
  mkdirSync(join(root, 'site', 'dist'), { recursive: true });
  if (html !== null) {
    mkdirSync(join(root, 'site', 'dist', at), { recursive: true });
    writeFileSync(join(root, 'site', 'dist', at, 'index.html'), html);
  }
  return root;
}

const run = (root) => spawnSync(process.execPath, [script, 'site/dist', root], { encoding: 'utf8' });

function expect(name, gomod, html, ok, message, at) {
  test(name, () => {
    const root = tree(gomod, html, at);
    try {
      const r = run(root);
      assert.equal(r.status, ok ? 0 : 1, r.stderr + r.stdout);
      if (!ok) assert.match(r.stderr, message);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

const MOD = 'module ritueel.id/ritueel\n\ngo 1.27.0\n';

test('the page in site/public and the module of the real go.mod agree', () => {
  const root = mkdtempSync(join(tmpdir(), 'go-import-real-'));
  try {
    cpSync(join(repo, 'go.mod'), join(root, 'go.mod'));
    cpSync(join(repo, 'site', 'public'), join(root, 'site', 'dist'), { recursive: true });
    const r = run(root);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    const html = readFileSync(join(repo, 'site', 'public', 'ritueel', 'index.html'), 'utf8');
    assert.match(html, /<meta name="robots" content="noindex">/);
    assert.ok(!/<script|<style|style=|http-equiv="refresh"/i.test(html), 'the page needs no script, no style and no redirect');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

expect('the page and go.mod agree', MOD, page(tag(GOOD)), true);
expect('a lost page fails', MOD, null, false, /ritueel\/index\.html is not in the built site/);
expect('a page without the tag fails', MOD, page('<title>x</title>'), false, /exactly one go-import tag.*has 0/);
expect('two tags fail', MOD, page(tag(GOOD) + tag(GOOD)), false, /exactly one go-import tag.*has 2/);
expect('a tag in the body does not count', MOD, `<!doctype html><html><head></head><body>${tag(GOOD)}</body></html>`, false, /has 0/);
expect('a renamed module fails', 'module ritueel.id/ritueel2\n', page(tag(GOOD)), false, /ritueel2\/index\.html is not in the built site/);
expect('a content of another module fails', MOD, page(tag('ritueel.id/other git https://github.com/truvity/ritueel')), false, /go-import content is/);
expect('another repository fails', MOD, page(tag('ritueel.id/ritueel git https://github.com/truvity/other')), false, /go-import content is/);
expect('another vcs fails', MOD, page(tag('ritueel.id/ritueel hg https://github.com/truvity/ritueel')), false, /go-import content is/);
expect('a module on another host fails', 'module github.com/truvity/ritueel\n', page(tag(GOOD)), false, /not under this site's host/);
expect('a module without a path fails', 'module ritueel.id\n', page(tag(GOOD)), false, /no path after the host/);
expect('a go.mod without a module fails', 'go 1.27.0\n', page(tag(GOOD)), false, /no module directive/);
expect('a module path of two elements maps to two folders', 'module ritueel.id/a/b\n', page(tag('ritueel.id/a/b git https://github.com/truvity/ritueel')), true, null, 'a/b');
