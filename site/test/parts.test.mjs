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

// A landing as the Markdown processor gives it: the parts, "The pain" first. "does" has a thematic
// break before the block "next to" and another before the stage, which stays inside "does"; the
// last paragraph of "read next" is the row of the quiet links.
const text = (value) => ({ type: 'text', value });
const heading = (depth, value) => node('heading', { depth, children: [text(value)] });
const para = (...children) => node('paragraph', { children });
const button = para(node('strong', { children: [node('link')] }));
const brk = () => node('thematicBreak');
const landing = (withNext) => [
  heading(2, 'The pain'),
  node('list'),
  heading(2, 'What to do'),
  node('list'),
  heading(2, 'What not to do'),
  node('list'),
  heading(2, 'What ritueel does for you'),
  para(text('does')),
  ...(withNext ? [brk(), heading(3, 'Next to what you already run'), node('table'), para(text('Aim'))] : []),
  brk(),
  para(node('strong', { children: [text('stage')] })),
  para(text('built today')),
  button,
  heading(2, 'Read next'),
  node('list'),
  para(text('links')),
];
const cls = (n) => n.data?.hProperties?.class;

test('with `flow: landing` the parts have the classes of a landing, and not the class of the rows', () => {
  const out = run({ flow: 'landing' }, landing(true));
  assert.deepEqual(out.map(cls), ['lp-part lp-pain', 'lp-part lp-do', 'lp-part lp-dont', 'lp-part lp-does', 'lp-part lp-nextto', 'lp-part lp-read']);
  assert.ok(!out.some(isPart));
});

test('a landing without the block "next to" has no such part, and the thematic breaks are dropped', () => {
  const out = run({ flow: 'landing' }, landing(false));
  assert.deepEqual(out.map(cls), ['lp-part lp-pain', 'lp-part lp-do', 'lp-part lp-dont', 'lp-part lp-does', 'lp-part lp-read']);
  assert.ok(!JSON.stringify(out).includes('thematicBreak'));
});

test('in a landing the stage stays inside "does", the bold link is the button, and the last paragraph of "read next" is the row of quiet links', () => {
  const out = run({ flow: 'landing' }, landing(true));
  const does = out.find((n) => cls(n) === 'lp-part lp-does');
  const stage = does.children.find((n) => cls(n) === 'lp-stage');
  assert.deepEqual(stage.children.map(cls), ['lp-stagelabel', 'lp-stageline']);
  assert.equal(cls(does.children.at(-1)), 'lp-button'); // the button follows the stage, outside its block
  const next = out.find((n) => cls(n) === 'lp-part lp-nextto');
  assert.equal(next.children[0].depth, 2); // the same level as the other headings
  const read = out.find((n) => cls(n) === 'lp-part lp-read');
  assert.deepEqual(read.children.map(cls), [undefined, undefined, 'lp-links']);
});

test('a paragraph in "What to do" is a note under the list', () => {
  const src = landing(false);
  src.splice(src.findIndex((n) => n.type === 'list') + 2, 0, para(text('note')));
  const out = run({ flow: 'landing' }, src);
  const doPart = out.find((n) => cls(n) === 'lp-part lp-do');
  assert.deepEqual(doPart.children.map(cls), [undefined, 'lp-note', undefined]);
});

test('any other value of `flow` is not touched', () => {
  assert.equal(run({ flow: 'columns' }, page()), null);
});
