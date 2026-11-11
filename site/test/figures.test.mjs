// The regression check of the figures (runs in `just site-lint`, no build needed). A drawing is a
// string made by site/figures/*.mjs; this test holds every one to the rules the site's style
// depends on, so a builder who forgets one finds out here and not in a review.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { figures } from '../figures/index.mjs';
import { renderFigure } from '../figures/markup.mjs';
import { PIV_ROWS, ROOT_CARD_ROWS, rootCardCells, serverCardCells } from '../figures/slots.mjs';
import { docsFiles, repoRoot } from '../lib/published.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, '..', 'src', 'styles', 'figures.css'), 'utf8');
const all = Object.values(figures);

/** Every drawing of a figure: [{where, svg, caption}], caption being the text the label must not repeat. */
function drawings(fig) {
  if (fig.kind === 'strip') return fig.panels.map((p) => ({ where: `${fig.id} panel ${p.n}`, svg: p.svg, caption: p.caption }));
  if (fig.kind === 'layout') return [{ where: `${fig.id} wide`, svg: fig.wide, caption: fig.caption }, { where: `${fig.id} narrow`, svg: fig.narrow, caption: fig.caption }];
  return [{ where: fig.id, svg: fig.svg, caption: fig.caption }];
}

// The texts of a drawing; the halo copy of a label (drawn under it) is the same text, left out.
const textsOf = (svg) =>
  [...svg.matchAll(/<text class="([^"]*)"[^>]*>([^<]*)<\/text>/g)].map((m) => ({ cls: m[1].split(/\s+/), text: m[2] })).filter((t) => !t.cls.includes('halo'));
const label = (svg) => /aria-label="([^"]*)"/.exec(svg)?.[1] ?? '';
const unesc = (t) => t.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');

test('there are figures, each with an id that is its registry key and a known kind', () => {
  assert.ok(all.length >= 1);
  for (const [name, fig] of Object.entries(figures)) {
    assert.equal(fig.id, name);
    assert.ok(['strip', 'layout', 'single'].includes(fig.kind), `${name}: kind ${fig.kind}`);
    assert.ok(fig.label && fig.caption, `${name}: label and caption are required`);
  }
});

test('a strip has exactly six panels, numbered 1 to 6, each with a title and a short caption', () => {
  for (const fig of all.filter((f) => f.kind === 'strip')) {
    assert.equal(fig.panels.length, 6, fig.id);
    fig.panels.forEach((p, i) => {
      assert.equal(p.n, i + 1, `${fig.id}: panel number`);
      assert.ok(p.title && p.title.split(/\s+/).length <= 2, `${fig.id} panel ${p.n}: title is one or two words`);
      assert.ok(p.caption.split(/\s+/).length <= 18, `${fig.id} panel ${p.n}: caption has more than 18 words`);
    });
  }
});

test('a layout has a wide and a narrow drawing', () => {
  for (const fig of all.filter((f) => f.kind === 'layout')) {
    assert.ok(/class="fig-wide"/.test(fig.wide) && /viewBox="0 0 760 /.test(fig.wide), `${fig.id}: wide`);
    assert.ok(/class="fig-narrow"/.test(fig.narrow) && /viewBox="0 0 360 /.test(fig.narrow), `${fig.id}: narrow`);
  }
});

test('every drawing is an img with a label that is not the caption, kept out of search, and uses only what the CSS allows', () => {
  const banned = [/<style/i, /<script/i, /<foreignObject/i, /<image/i, /<use[\s>]/i, /<defs/i, /\sid=/i, /\sstyle=/i, /\shref=/i, /xlink/i, /\son\w+=/i];
  for (const fig of all) {
    for (const d of drawings(fig)) {
      assert.ok(/^<svg[^>]* role="img"/.test(d.svg), `${d.where}: role="img"`);
      assert.ok(/^<svg[^>]* data-pagefind-ignore/.test(d.svg), `${d.where}: data-pagefind-ignore`);
      assert.ok(/^<svg[^>]* viewBox="0 0 \d+ \d+"/.test(d.svg), `${d.where}: viewBox`);
      const l = label(d.svg);
      assert.ok(l.length >= 20, `${d.where}: aria-label is empty or too short`);
      assert.notEqual(unesc(l).trim(), d.caption.trim(), `${d.where}: aria-label repeats the caption`);
      for (const re of banned) assert.ok(!re.test(d.svg), `${d.where}: ${re} in a drawing`);
    }
  }
});

test('a strip panel is 280 x 224, so that the scale is the same everywhere', () => {
  for (const fig of all.filter((f) => f.kind === 'strip')) {
    for (const p of fig.panels) assert.ok(/viewBox="0 0 280 224"/.test(p.svg), `${fig.id} panel ${p.n}`);
  }
});

test('every class of a drawing, and of the figure markup, is defined in figures.css', () => {
  const defined = new Set([...css.matchAll(/\.([A-Za-z][\w-]*)/g)].map((m) => m[1]));
  for (const fig of all) {
    const html = renderFigure(fig);
    const used = new Set([...html.matchAll(/class="([^"]*)"/g)].flatMap((m) => m[1].split(/\s+/)).filter(Boolean));
    for (const c of used) assert.ok(defined.has(c) || c === 'not-content', `${fig.id}: class "${c}" is not in figures.css`);
  }
});

test('figures.css: no font under 12px, no !important, no colour of its own, no media query for a theme', () => {
  for (const m of css.matchAll(/font-size:\s*([\d.]+)px/g)) assert.ok(Number(m[1]) >= 12, `font-size ${m[1]}px is under 12px`);
  assert.ok(!/!important/.test(css), '!important');
  const code = css.replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(code), 'a colour literal: use Starlight variables');
  assert.ok(!/prefers-color-scheme/.test(code), 'a theme follows data-theme through the variables, not a media query');
  for (const m of code.matchAll(/var\((--[\w-]+)/g)) {
    assert.ok(/^--(sl-|ritueel-)/.test(m[1]), `${m[1]} is not a variable of Starlight or of the site`);
  }
});

test('no text of a drawing is smaller than 12px (every text carries a class with its size or the 13px base)', () => {
  for (const fig of all) {
    for (const d of drawings(fig)) {
      for (const t of textsOf(d.svg)) assert.ok(!t.cls.some((c) => /^t-(xs|xxs)$/.test(c)), `${d.where}: ${t.text}`);
    }
  }
});

test('a text label is at most three words; a longer note is marked t-long', () => {
  for (const fig of all) {
    for (const d of drawings(fig)) {
      for (const t of textsOf(d.svg)) {
        const words = unesc(t.text).trim().split(/\s+/).filter(Boolean).length;
        if (t.cls.includes('t-long')) assert.ok(words <= 12, `${d.where}: the note "${t.text}" is longer than 12 words`);
        else assert.ok(words <= 3, `${d.where}: "${t.text}" is ${words} words; shorten it or mark it t-long`);
      }
    }
  }
});

test('every arrow has a label', () => {
  for (const fig of all) {
    for (const d of drawings(fig)) {
      const groups = [...d.svg.matchAll(/<g class="ar"[^>]*>([\s\S]*?)<\/g>/g)];
      for (const g of groups) assert.ok(/<text /.test(g[1]), `${d.where}: an arrow has no label`);
      const heads = (d.svg.match(/<polygon /g) ?? []).length;
      assert.equal(heads, groups.length, `${d.where}: ${heads} arrow heads but ${groups.length} labelled arrows`);
    }
  }
});

test('words the owner decided against, and nothing that looks like a secret, a serial or an address', () => {
  const banned = [/\bstaff\b/i, /\bboard card\b/i, /\bceremony machine\b/i, /\btest card\b/i, /\bfolder\b/i];
  for (const fig of all) {
    const pieces = [fig.label, fig.caption, ...(fig.panels ?? []).flatMap((p) => [p.title, p.caption])];
    for (const d of drawings(fig)) pieces.push(unesc(label(d.svg)), ...textsOf(d.svg).map((t) => unesc(t.text)));
    for (const s of pieces) {
      for (const re of banned) assert.ok(!re.test(s), `${fig.id}: ${re} in "${s}"`);
      assert.ok(!/\bgate\b/i.test(s) || !/cloud/i.test(s), `${fig.id}: a gate near a cloud root: "${s}"`);
      assert.ok(!/\d{12}/.test(s), `${fig.id}: a 12-digit run in "${s}"`);
      for (const n of s.match(/\b\d{8,}\b/g) ?? []) assert.ok(/^0+\d$/.test(n), `${fig.id}: ${n} looks like a real serial (use 00000001)`);
      assert.ok(!/@\w/.test(s), `${fig.id}: an at-sign in "${s}"`);
      assert.ok(!/\b\d{1,3}(\.\d{1,3}){3}\b/.test(s), `${fig.id}: an IP address in "${s}"`);
    }
  }
});

test('at most one accent object in a figure, and an accent class has an accent object to belong to', () => {
  for (const fig of all) {
    const names = new Set();
    for (const d of drawings(fig)) {
      const here = [...d.svg.matchAll(/data-acc="([^"]+)"/g)].map((m) => m[1]);
      here.forEach((n) => names.add(n));
      if (/class="[^"]*\b(acc-f|acc-b|ln-acc|t-acc|hd-acc)\b/.test(d.svg)) assert.ok(here.length > 0, `${d.where}: accent colour outside an accent object`);
    }
    assert.ok(names.size <= 1, `${fig.id}: accent objects ${[...names].join(', ')}`);
  }
});

test('the wide and the narrow drawing of a layout hold the same slot ids and the same row labels', () => {
  for (const fig of all.filter((f) => f.kind === 'layout')) {
    const pick = (svg, c) => textsOf(svg).filter((t) => t.cls.includes(c)).map((t) => t.text).sort();
    assert.deepEqual(pick(fig.wide, 't-id'), pick(fig.narrow, 't-id'), `${fig.id}: slot ids differ`);
    assert.deepEqual(pick(fig.wide, 't-row'), pick(fig.narrow, 't-row'), `${fig.id}: row labels differ`);
  }
});

test('the root card shows the 24 slots of the table, once each, and the rows of the table', () => {
  const fig = figures['root-card'];
  assert.ok(fig, 'the root card figure is registered');
  const ids = PIV_ROWS.flat();
  assert.equal(ids.length, 24);
  assert.equal(new Set(ids).size, 24);
  assert.deepEqual(textsOf(fig.wide).filter((t) => t.cls.includes('t-id')).map((t) => t.text).sort(), [...ids].sort());
  assert.deepEqual(textsOf(fig.wide).filter((t) => t.cls.includes('t-row')).map((t) => t.text), ROOT_CARD_ROWS.map((r) => r.label));
  // the same kind of key in the same column in the rows that hold a bundle's root; a row with fewer
  // kinds leaves cells empty; row 1 holds no key at all
  const cells = rootCardCells();
  const kinds = ['X.509', 'OpenPGP', 'SSH CA', null];
  for (const row of ROOT_CARD_ROWS.filter((r) => r.kind === 'bundle')) {
    for (const c of cells.filter((c) => c.row === row.n)) {
      assert.equal(c.type, c.state === 'empty' ? null : kinds[c.col], `${row.label}: ${c.id} holds the kind of its column`);
    }
  }
  assert.ok(cells.filter((c) => c.row === 1).every((c) => c.state === 'empty'), 'row 1 holds no root');
  assert.equal(ROOT_CARD_ROWS.filter((r) => r.kind === 'free').length, 1, 'one row is kept free');
  assert.equal(ROOT_CARD_ROWS.filter((r) => r.kind === 'bundle' || r.kind === 'room').length, 4, 'four bundles on a pair of cards');
});

test('the server card shows the 24 slots once each in both drawings, ten held, and the accent on x509-intermediate only', () => {
  const fig = figures['server-card'];
  assert.ok(fig, 'the server card figure is registered');
  const cells = serverCardCells();
  assert.deepEqual(cells.map((c) => c.id), PIV_ROWS.flat());
  assert.equal(cells.filter((c) => c.state !== 'empty').length, 10);
  assert.deepEqual(cells.filter((c) => c.state === 'acme').map((c) => c.use), ['x509-intermediate']);
  for (const svg of [fig.wide, fig.narrow]) {
    assert.deepEqual(textsOf(svg).filter((t) => t.cls.includes('t-id')).map((t) => t.text).sort(), [...PIV_ROWS.flat()].sort());
  }
});

test('the day-to-day card holds three OpenPGP keys and an empty PIV application', () => {
  const fig = figures['day-to-day-card'];
  assert.ok(fig, 'the day-to-day card figure is registered');
  const all = textsOf(fig.svg).map((t) => t.text);
  for (const w of ['signing', 'decryption', 'authentication', 'passkey', 'stays empty']) assert.ok(all.includes(w), `the word "${w}" is drawn`);
});

test('every <Figure name> of docs/**/*.mdx is registered, and every registered figure is placed on a page', () => {
  const root = repoRoot();
  const placed = new Set();
  for (const file of docsFiles(root).filter((f) => f.endsWith('.mdx'))) {
    const src = readFileSync(join(root, 'docs', file), 'utf8');
    for (const m of src.matchAll(/<Figure\s+name="([^"]+)"/g)) {
      assert.ok(figures[m[1]], `docs/${file}: no figure named "${m[1]}"`);
      placed.add(m[1]);
    }
  }
  for (const name of Object.keys(figures)) assert.ok(placed.has(name), `the figure "${name}" is on no page of docs/`);
});

test('the figure markup: a figure has its caption, a strip is a list of six, a layout holds both drawings', () => {
  for (const fig of all) {
    const html = renderFigure(fig, 'The caption.');
    assert.ok(html.startsWith('<figure class="fig '), fig.id);
    assert.ok(html.includes('<figcaption>The caption.</figcaption>'), fig.id);
    assert.ok(html.includes('not-content'), fig.id);
    const n = (html.match(/<svg /g) ?? []).length;
    assert.equal(n, fig.kind === 'strip' ? 6 : fig.kind === 'layout' ? 2 : 1, `${fig.id}: svg count`);
    if (fig.kind === 'strip') assert.equal((html.match(/<li>/g) ?? []).length, 6);
  }
  assert.throws(() => renderFigure({ id: 'x', kind: 'nope' }), /unknown kind/);
});
