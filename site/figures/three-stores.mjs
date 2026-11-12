// The three stores of a root, side by side, and the two questions that choose one (the page "Choosing
// where a root lives"). Three panels say what each store holds, where it runs and when its key ends;
// under them the two questions of that page lead to a store. Words are the page's own and the records':
//   Key file: record 0002 rules 5, 6 and 15; 0005 rules 17 and 28; 0008 rule 6.
//   Two root cards: 0003 rules 1 and 3; 0005 rule 18; 0002 rule 16.
//   Cloud key: 0004 rules 1, 2, 5 and 8; 0005 rule 18; 0002 rule 16.
//   "Planned: M2 / M6 / M2" is the page's row "Built in" and the roadmap (M2 the file and the cloud store,
//   M6 the cards); it is in no record.
// The accent marks the two stores that cannot be copied, in the panels and in the flow. A key file can
// be copied, so its header and its name box are dashed. Wide (760 units) and narrow (360 units) are
// made from the same table, so their words cannot drift.
import { acc, arrow, line, rect, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { cloud, lock } from './parts.mjs';
import { card, key, sheet } from './draw.mjs';

const ACC = 'nocopy';
const at = (x, y, s) => `<g transform="translate(${x} ${y})">${s}</g>`;

const STORES = [
  {
    name: 'Key file',
    dim: 'can be copied',
    copyable: true,
    planned: 'Planned: M2',
    rows: [
      ['Holds', ['test roots, drills, development,', 'a person’s own primary']],
      ['Runs on', ['the offline system', '(a test root: also the workstation)']],
      ['Ends', ['replaced at most every three years']],
    ],
  },
  {
    name: 'Two root cards',
    dim: 'cannot be copied',
    planned: 'Planned: M6',
    rows: [
      ['Holds', ['keys A and B of your roots,', 'one key on each card']],
      ['Runs on', ['your workstation, under four', 'conditions, or the offline system']],
      ['Ends', ['on an event, not on a date']],
    ],
  },
  {
    name: 'Cloud key',
    dim: 'cannot be copied out',
    planned: 'Planned: M2',
    rows: [
      ['Holds', ['three keys in one account', 'used only for the roots']],
      ['Runs on', ['your workstation, through', 'the ceremony role that signs']],
      ['Ends', ['on an event, not on a date']],
    ],
  },
];

// --- icons, about 30 x 26, top left at (x, y) -------------------------------------------------------
const ICONS = [
  (x, y) => sheet(x + 2, y - 1, 24, 28, { rows: 0 }) + lock(x + 8, y + 8),
  (x, y) => card(x + 5, y, 22, 15, 'paper') + card(x - 1, y + 10, 22, 15, 'paper'),
  (x, y) => cloud(x, y, 0.9) + key(x + 12, y + 14, 'ln ln-key'),
];

// A panel of width w and height h at (0,0): its header (icon, name, tag, dim line), then three rows
// (a dim label on a line of its own, then the text, with a thin rule between rows).
function panel(store, i, w, h) {
  let s = rect(1.25, 1.25, w - 2.5, h - 2.5, 'p-frame', 9);
  const head = store.copyable ? rect(8, 8, w - 16, 40, 'paper-g', 6) : acc(ACC, rect(8, 8, w - 16, 40, 'acc-f cell-held', 6));
  s += head;
  s += ICONS[i](16, 15);
  s += text(48, 24, store.name, 't t-b') + text(48, 42, store.dim, 't t-s t-long');
  const pw = 78;
  s += rect(w - 12 - pw, 11, pw, 21, 'paper', 10.5) + text(w - 12 - pw / 2, 25.5, store.planned, 't t-s', 'm');
  let y = 65;
  store.rows.forEach(([label, lines], r) => {
    if (r > 0) {
      s += line(14, y - 13, w - 14, y - 13, 'ln ln-thin ln-dim');
    }
    s += text(14, y, label, 't t-s t-b t-dim');
    lines.forEach((l, k) => {
      s += text(14, y + 15 + k * 15, l, 't t-s t-long');
    });
    y += 15 + lines.length * 15 + 8;
  });
  return s;
}

// A name box in the flow: bold name; accent for a store that cannot be copied, dashed for a key file.
const nameBox = (x, y, w, h, name, copyable) =>
  copyable
    ? rect(x, y, w, h, 'paper-g', 5) + text(x + w / 2, y + h / 2 + 4.5, name, 't t-b', 'm')
    : acc(ACC, rect(x, y, w, h, 'acc-f cell-held', 5) + text(x + w / 2, y + h / 2 + 4.5, name, 't t-b', 'm'));

// A question box, its lines centred.
const qBox = (x, y, w, h, lines) =>
  rect(x, y, w, h, 'paper', 6) + lines.map((l, k) => text(x + w / 2, y + h / 2 + 4.5 - ((lines.length - 1) * 15) / 2 + k * 15, l, 't t-s t-long', 'm')).join('');

const Q1 = ['Will other people or systems', 'rely on this root?'];
const Q2 = ['Can your organisation set up a', 'separate cloud account used', 'only for the root?'];
const EXCEPTION = 'One exception: a person’s own primary.';

const LABEL =
  'Three panels and two questions. The panels show the three stores. ' +
  'The key file can be copied. It holds test roots, drills, development and a person’s own primary. It runs on the offline system. It is replaced at most every three years. ' +
  'Two root cards cannot be copied. They hold keys A and B of the roots, one key on each card. They run on the workstation under four conditions, or on the offline system. Their keys end on an event. ' +
  'The cloud key cannot be copied out. It is three keys in one account used only for the roots. It runs on the workstation through the ceremony role that signs. Its keys end on an event. ' +
  'Each panel is marked as planned for a milestone. Under the panels, two questions choose a store, and the first has a mark that says start. ' +
  'The first asks whether other people or systems rely on the root. No leads to the key file, with the note that a person’s own primary is the one exception. Yes leads to the second question. ' +
  'The second asks whether the organisation can set up a separate cloud account used only for the root. Yes leads to the cloud key. No leads to two root cards.';

const PH = 197;

function wide() {
  const pw = 244;
  const gap = 14;
  let s = '';
  STORES.forEach((st, i) => {
    s += at(i * (pw + gap), 0, panel(st, i, pw, PH));
  });
  // the flow: the exception above question 1, question 1 and 2 on one row, the three names at the right
  const fy = PH + 20; // top of the flow
  const qy = fy + 28; // top of the question boxes
  const qh = 50;
  const nx = 602;
  const nw = 156;
  s += text(3, qy - 8, 'Start', 't t-s t-b');
  s += qBox(1.5, qy, 204.5, qh, Q1) + qBox(262, qy, 214, qh, Q2);
  s += nameBox(nx, fy, nw, 22, 'Key file', true) + nameBox(nx, fy + 28, nw, 22, 'Cloud key', false) + nameBox(nx, fy + 56, nw, 22, 'Two root cards', false);
  // question 1: yes to question 2, no up and over to the key file
  s += arrow(206, qy + qh / 2, 262, qy + qh / 2, 'yes', { ly: qy + qh / 2 - 7 });
  s += line(190, qy, 190, fy + 11, 'ln') + arrow(190, fy + 11, nx, fy + 11, 'no', { ly: fy + 4, lx: 232 }) + text(262, fy + 4, EXCEPTION, 't t-s t-dim t-long');
  // question 2: yes to the cloud key, no to the root cards
  s += arrow(476, fy + 39, nx, fy + 39, 'yes', { ly: fy + 32 });
  s += arrow(476, fy + 67, nx, fy + 67, 'no', { ly: fy + 60 });
  return svgBox(760, fy + 81, LABEL, s, 'fig-wide');
}

function narrow() {
  const w = 360;
  const ph = PH;
  let s = '';
  STORES.forEach((st, i) => {
    s += at(0, i * (ph + 10), panel(st, i, w, ph));
  });
  const y = 3 * ph + 20 + 12;
  const q1y = y + 20;
  s += text(3, q1y - 8, 'Start', 't t-s t-b');
  const qh = 50;
  s += qBox(1.5, q1y, 204.5, qh, Q1) + nameBox(254, q1y + 13, 104, 24, 'Key file', true);
  s += arrow(206, q1y + qh / 2, 254, q1y + qh / 2, 'no', { ly: q1y + qh / 2 - 7 });
  s += ['One exception:', 'a person’s own', 'primary.'].map((l, k) => text(256, q1y + 58 + k * 15, l, 't t-s t-dim t-long')).join('');
  const q2y = q1y + qh + 36;
  const q2h = 62;
  s += qBox(1.5, q2y, 204.5, q2h, Q2) + nameBox(254, q2y + 19, 104, 24, 'Cloud key', false);
  s += arrow(103, q1y + qh, 103, q2y, 'yes', { lx: 130, ly: q1y + qh + 21 });
  s += arrow(206, q2y + q2h / 2, 254, q2y + q2h / 2, 'yes', { ly: q2y + q2h / 2 - 7 });
  const ry = q2y + q2h + 36;
  s += nameBox(36, ry, 134, 24, 'Two root cards', false);
  s += arrow(103, q2y + q2h, 103, ry, 'no', { lx: 124, ly: q2y + q2h + 21 });
  return svgBox(w, ry + 27, LABEL, s, 'fig-narrow');
}

export default {
  id: 'three-stores',
  kind: 'layout',
  label: 'The three stores of a root, side by side, and two questions that choose one',
  caption: 'Ask the two questions in order. The first answer that fits is your store.',
  wide: wide(),
  narrow: narrow(),
};
