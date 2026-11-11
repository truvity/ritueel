// "The whole chain" of the home page: one picture, read from left to right. Your root in one of three
// stores, then the one ceremony of the year, then the keys used every day; under the chain, four
// years as two rows, which tell the contrast: a key file can be copied, so it is replaced on a
// calendar; a key that cannot be copied stays the same key and is renewed.
// Wide (760 units, three panels in a row) and narrow (360, the same panels in a column) are made from
// the same three panel functions and one timeline function, so they cannot drift.
// The accent is the root that cannot be copied: its two stores, the one step that uses it (sign), and
// the same key that is renewed. Rests on the records 0001 (three stores), 0002 (cannot be copied),
// 0005 (six steps; only step 4 uses the root), 0007 (same key, renewed; a copy replaced at the latest
// after three years) and 0008 (subkeys on the day-to-day card).
import { acc, arrow, card, circle, f, key, line, person, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { cloud } from './parts.mjs';

const at = (x, y, s) => `<g transform="translate(${f(x)} ${f(y)})">${s}</g>`;
const ACC = 'root';
const STEPS = ['plan', 'confirm', 'reserve', 'sign', 'verify', 'record'];
const PH = 236; // the height of a panel

// a panel: the heavy frame and a two-line title
const panel = (w, a, b) => rect(1.25, 1.25, w - 2.5, PH - 2.5, 'p-frame', 9) + text(w / 2, 26, a, 't t-b', 'm') + text(w / 2, 43, b, 't t-b', 'm');

// 1: your root, in three stores. Two cannot be copied (solid, accent); the key file can (dashed, grey).
function stores(w) {
  let s = panel(w, 'Your root,', 'in three stores');
  const row = (i, shape, icon, name, state, long = false) => {
    const y = 60 + i * 56;
    const box = rect(12, y, w - 24, 50, shape === 'root' ? 'acc-f cell-held' : 'cell-empty', 6);
    return (shape === 'root' ? acc(ACC, box) : box) + icon(y) + text(82, y + 22, name, 't t-b') + text(82, y + 39, state, 't t-s' + (long ? ' t-long' : ''));
  };
  s += row(0, 'root', (y) => card(20, y + 12, 38, 24, 'paper') + card(28, y + 18, 38, 24, 'paper'), 'two root cards', 'cannot be copied');
  s += row(1, 'root', (y) => cloud(21, y + 7, 1.5) + key(43, y + 34, 'ln ln-key'), 'cloud key', 'cannot be copied out', true);
  s += row(2, 'file', (y) => sheet(30, y + 7, 30, 36, { rows: 0 }) + key(45, y + 29, 'ln ln-key ln-dim'), 'key file', 'can be copied');
  return s;
}

// a calendar with one day marked: once a year
function calendar(x, y) {
  let s = rect(x, y + 3, 32, 28, 'paper', 3) + line(x, y + 11, x + 32, y + 11, 'ln ln-thin');
  s += line(x + 9, y, x + 9, y + 6, 'ln') + line(x + 23, y, x + 23, y + 6, 'ln');
  for (let r = 0; r < 2; r++) for (let c = 0; c < 4; c++) if (!(r === 1 && c === 2)) s += circle(x + 5 + c * 7.4, y + 17 + r * 8, 1.3, 'fill-ink');
  return s + circle(x + 5 + 2 * 7.4, y + 25, 3.4, 'fill-ink');
}

// 2: once a year, one ceremony: the holder with a root card, a calendar, and the six steps in order.
// Only the step "sign" uses the root. The cluster is 208 units wide and centred in the panel.
function ceremony(w) {
  let s = panel(w, 'Once a year,', 'one ceremony');
  const ox = (w - 208) / 2;
  // the holder is drawn in its own coordinates and moved, so that it stays inside the kit's limits
  s += at(ox, 0, person(44, 206, [[1, 80, 170]]) + acc(ACC, card(72, 144, 40, 26, 'acc-f')) + text(44, 226, 'you', 't t-s', 'm') + calendar(28, 66));
  const x0 = ox + 132;
  s += line(x0, 70, x0, 190, 'ln ln-thin ln-dim');
  STEPS.forEach((word, i) => {
    const y = 70 + i * 24;
    const root = word === 'sign';
    const num = `<text class="t t-s t-b ${root ? 't-acc' : 't-num'} t-mid" x="${f(x0)}" y="${f(y + 4.3)}">${i + 1}</text>`;
    s += (root ? acc(ACC, circle(x0, y, 9.5, 'acc-f') + num) : circle(x0, y, 9, 'fill-ink') + num) + text(x0 + 17, y + 4.3, word, 't t-s' + (root ? ' t-b t-acc' : ''));
  });
  return s;
}

// 3: keys for every day: an intermediate in the certificate system, subkeys on the day-to-day card
function daily(w) {
  let s = panel(w, 'Keys for', 'every day');
  const bx = 12, bw = w - 24;
  const box = (y, name, inner) => rect(bx, y, bw, 78, 'paper-t', 6) + text(bx + 12, y + 20, name, 't t-s') + inner;
  const inset = (y, icon, word) => rect(bx + 12, y + 30, bw - 24, 38, 'paper', 5) + icon(y) + text(bx + 56, y + 54, word, 't t-b');
  s += box(58, 'your certificate system', inset(58, (y) => key(bx + 36, y + 49, 'ln ln-key'), 'intermediate'));
  s += box(142, 'your day-to-day card', inset(142, (y) => card(bx + 20, y + 37, 28, 24), 'subkeys'));
  return s;
}

// the contrast: four years as two rows. A key file is replaced on a calendar (the first key stays
// until the fourth year); a key that cannot be copied is one key, renewed in each year. `side` puts
// the row names left of the rows (wide); otherwise above them (narrow).
function timeline(W, y0, side) {
  const ax = side ? 190 : 14;
  const yw = side ? 140 : 83;
  const h = 48;
  const yFile = y0 + (side ? 44 : 78);
  const yBar = yFile + h + (side ? 24 : 46);
  const H = yBar + h + 16 - y0;
  let s = rect(1.25, y0 + 1.25, W - 2.5, H - 2.5, 'p-frame', 9);
  for (let i = 0; i < 4; i++) s += text(ax + i * yw + yw / 2, y0 + 30, `year ${i + 1}`, 't t-s t-dim', 'm');
  // row names
  if (side) {
    s += text(24, yFile + 22, 'Key file', 't t-b') + text(24, yFile + 39, 'can be copied', 't t-s t-dim');
    s += text(24, yBar + 22, 'Card, cloud key', 't t-b') + text(24, yBar + 39, 'cannot be copied out', 't t-s t-dim t-long');
  } else {
    s += text(16, yFile - 10, 'Key file', 't t-b') + text(100, yFile - 10, 'can be copied', 't t-s t-dim');
    s += text(16, yBar - 10, 'Card, cloud key', 't t-b') + text(124, yBar - 10, 'cannot be copied out', 't t-s t-dim t-long');
  }
  // the key file: a new key in year 1 and in year 4; the first one stays in between
  const cell = (i) => ax + i * yw + 3;
  const cw = yw - 6;
  const cx = (i) => ax + i * yw + yw / 2;
  s += line(cell(0) + cw, yFile + h / 2, cell(3), yFile + h / 2, 'ln ln-dash ln-dim');
  for (const i of [0, 3]) s += rect(cell(i), yFile, cw, h, 'paper-g', 6) + key(cx(i), yFile + 17, 'ln ln-key ln-dim') + text(cx(i), yFile + 39, 'new key', 't t-s t-dim', 'm');
  // the key that cannot be copied: one bar, the same key, renewed in each following year
  let bar = rect(ax + 3, yBar, 4 * yw - 6, h, 'acc-f', 6);
  for (let i = 1; i < 4; i++) bar += line(ax + i * yw, yBar + 8, ax + i * yw, yBar + h - 8, 'ln ln-thin ln-acc');
  for (let i = 0; i < 4; i++) bar += key(cx(i), yBar + 17, 'ln ln-key ln-acc') + text(cx(i), yBar + 39, i === 0 ? 'same key' : 'renews', 't t-s t-acc', 'm');
  s += acc(ACC, bar);
  return { s, H };
}

const LABEL =
  'The chain of ritueel from the root to the keys of every day, with a four-year contrast under it. Your root in three stores: two root cards and a cloud key, drawn solid because they cannot be copied, and a key file, drawn dashed because it can be copied. ' +
  'The ceremony: a holder with a root card, a calendar with one day marked, and six numbered steps, plan, confirm, reserve, sign, verify, record, of which only sign uses the root. ' +
  'Keys for every day: an intermediate in your certificate system and subkeys on your day-to-day card. An arrow labelled uses leads from the root to the ceremony and one labelled signs from the ceremony to the keys. ' +
  'Under the chain, over four years: a key file gets a new key in year one and again in year four; a key on a card or in a cloud key service is the same key all four years and is renewed each year.';

function wide() {
  const pw = [216, 224, 216];
  const gap = 52;
  const px = [0, pw[0] + gap, pw[0] + gap + pw[1] + gap];
  let s = at(px[0], 0, stores(pw[0])) + at(px[1], 0, ceremony(pw[1])) + at(px[2], 0, daily(pw[2]));
  const ay = 140;
  s += arrow(px[0] + pw[0] + 4, ay, px[1] - 4, ay, 'uses') + arrow(px[1] + pw[1] + 4, ay, px[2] - 4, ay, 'signs');
  const y0 = PH + 14;
  const t = timeline(760, y0, true);
  return svgBox(760, y0 + t.H, LABEL, s + t.s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const gap = 44;
  let s = '';
  let y = 0;
  [stores, ceremony, daily].forEach((fn, i) => {
    s += at(0, y, fn(W));
    if (i < 2) s += arrow(180, y + PH + 4, 180, y + PH + gap - 4, i === 0 ? 'uses' : 'signs', { lx: 180 + 30, ly: y + PH + gap / 2 + 4 });
    y += PH + gap;
  });
  const y0 = y - gap + 14;
  const t = timeline(W, y0, false);
  return svgBox(W, y0 + t.H, LABEL.replace('with a four-year contrast under it', 'in a column, with a four-year contrast under it'), s + t.s, 'fig-narrow');
}

export default {
  id: 'whole-chain',
  kind: 'layout',
  label: 'The whole chain of ritueel: from your root to the keys of every day',
  caption:
    'The design, not a program: a key in a file can be copied without a trace, so it is replaced on a calendar. A key on a card or in a cloud key service cannot be copied out, so there is no calendar: you keep the same key and renew it once a year.',
  wide: wide(),
  narrow: narrow(),
};
