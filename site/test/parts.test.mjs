import assert from 'node:assert/strict';
import { test } from 'node:test';
import { partsMdastPlugin } from '../lib/parts.mjs';

// A page's top level as the Markdown processor gives it: a paragraph, then two `##` parts, the
// second with a `###` heading and a list inside it.
const node = (type, extra = {}) => ({ type, children: [], ...extra });
const h = (depth) => node('heading', { depth });
const page = () => [node('paragraph'), h(2), node('paragraph'), node('list'), h(2), h(3), node('paragraph')];

// What the plugin does to a page: the new top level it set on the root, or null if it set none.
function run(frontmatter, children) {
  let out = null;
  const root = { type: 'root', children };
  const ctx = {
    data: { astro: { frontmatter } },
    setProperty: (n, key, value) => {
      assert.equal(n, root);
      assert.equal(key, 'children');
      out = value;
    },
  };
  partsMdastPlugin.before(root, ctx);
  return out;
}
const isPart = (n) => n.data?.hName === 'section' && n.data.hProperties.class === 'ritueel-part';

test('a page without `flow: rows` is not touched', () => {
  assert.equal(run({}, page()), null);
  assert.equal(run({ title: 'x' }, page()), null);
  assert.equal(run(undefined, page()), null);
});

test('with `flow: rows` each `##` and what follows it is one part', () => {
  const src = page();
  const out = run({ flow: 'rows' }, src);
  assert.equal(out.length, 3);
  assert.equal(out[0], src[0]); // the text before the first `##` stays at the top level
  assert.ok(!isPart(out[0]));
  assert.ok(isPart(out[1]) && isPart(out[2]));
  assert.deepEqual(out[1].children, [src[1], src[2], src[3]]);
  assert.deepEqual(out[2].children, [src[4], src[5], src[6]]); // a `###` stays inside its part
});

test('a page with no `##` gets no part, and a page that starts with one has no text before it', () => {
  const plain = [node('paragraph'), h(3), node('paragraph')];
  assert.deepEqual(run({ flow: 'rows' }, plain), plain);
  const out = run({ flow: 'rows' }, [h(2), node('paragraph')]);
  assert.equal(out.length, 1);
  assert.ok(isPart(out[0]));
});
