// The five core ideas of ritueel, each as a small drawing: three stores under one set of ceremonies, a
// key that was born and not copied, one bundle for PKI and OpenPGP, requests in and answers out, and a
// defined workflow. Five tiles in a row (wide) or in a column (narrow); both are made from the same five
// drawing functions, so they cannot drift. The accent is the plan, which appears in the fifth tile.
import { acc, arrow, check, circle, f, folder, key, line, path, poly, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { lock } from './parts.mjs';

const planSheet = (x, y, w, h) => acc('plan', sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + w / 2, y + h / 2 + 7, 'plan', 't t-s t-b t-acc', 'm'));
const cloud = (x, y) => path(`M${f(x)} ${f(y + 24)} H${f(x + 28)} A8 8 0 0 0 ${f(x + 26)} ${f(y + 9)} A10 10 0 0 0 ${f(x + 8)} ${f(y + 11)} A7 7 0 0 0 ${f(x)} ${f(y + 24)} Z`, 'paper');

// each drawing is made in a box of 140 x 96, origin at its top left
const draw = [
  // 1: three stores, one set of ceremonies
  () =>
    sheet(10, 4, 28, 36, { rows: 0 }) + lock(18, 16) +
    rect(52, 12, 36, 24, 'paper', 4) + rect(57, 18, 9, 7, 'paper-t', 1.5) +
    cloud(100, 10) +
    text(24, 54, 'file', 't t-s', 'm') + text(70, 54, 'cards', 't t-s', 'm') + text(114, 54, 'cloud', 't t-s', 'm') +
    poly([[24, 60], [24, 66], [114, 66], [114, 60]], 'ln ln-thin') + line(70, 66, 70, 74, 'ln ln-thin') +
    line(22, 84, 118, 84, 'ln ln-thin') +
    [0, 1, 2, 3, 4, 5].map((i) => circle(22 + i * 19.2, 84, 6, 'fill-ink')).join(''),
  // 2: born in the store, not copied: the preferred side is the heavy one
  () =>
    rect(2, 2, 78, 70, 'paper', 8) +
    rect(12, 12, 58, 32, 'paper-t', 5) + key(41, 28, 'ln ln-key') +
    check(14, 58, 1) + text(34, 62, 'prefer', 't t-s t-b') +
    rect(110, 16, 26, 34, 'paper-g', 3) + rect(102, 24, 26, 34, 'paper-g', 3) + sheet(94, 32, 26, 34, { rows: 0 }) +
    text(40, 88, 'card, cloud', 't t-s', 'm') + text(112, 88, 'file', 't t-s', 'm'),
  // 3: one bundle for the roots of a PKI and of OpenPGP, with the cards
  () =>
    path('M8 8 H34 L40 0 H132 V92 H8 Z', 'paper') + rect(8, 8, 124, 84, 'paper', 5) +
    text(18, 26, 'bundle', 't t-s t-b') +
    rect(14, 34, 42, 20, 'paper-t', 4) + text(35, 48, 'X.509', 't t-s', 'm') +
    rect(60, 34, 66, 20, 'paper-t', 4) + text(93, 48, 'OpenPGP', 't t-s', 'm') +
    rect(14, 60, 112, 20, 'paper-t', 4) + text(70, 74, 'cards', 't t-s', 'm'),
  // 4: files in, files out
  () =>
    rect(4, 8, 26, 70, 'paper', 5) + rect(10, 16, 14, 10, 'paper-t', 2) + rect(10, 32, 14, 10, 'paper-t', 2) + rect(10, 54, 14, 14, 'paper-t', 2) +
    folder(88, 80, 38, 44) +
    arrow(34, 44, 84, 44, 'request', { lx: 59, ly: 36 }) + arrow(84, 68, 34, 68, 'answer', { lx: 59, ly: 60 }),
  // 5: a defined workflow: what is due, then the plan, then six steps
  () => {
    let c = rect(4, 4, 38, 40, 'paper', 4);
    [0, 1, 2].forEach((k) => (c += check(9, 16 + k * 11, 0.55) + line(20, 15 + k * 11, 36, 15 + k * 11, 'ln ln-thin')));
    let s = c + text(4, 58, 'what is due', 't t-s');
    s += line(46, 24, 62, 24, 'ln ln-thin') + planSheet(66, 8, 52, 30);
    s += line(10, 80, 122, 80, 'ln ln-thin ln-dim');
    for (let i = 0; i < 6; i++) s += circle(10 + i * 22.4, 80, 8, 'fill-ink') + `<text class="t t-s t-b t-num t-mid" x="${f(10 + i * 22.4)}" y="84.5">${i + 1}</text>`;
    return s;
  },
];

const titles = [['Same steps,', 'three stores'], ['Cannot be', 'copied'], ['One', 'bundle'], ['Requests in,', 'answers out'], ['Six steps,', 'defined']];

const dot = (cx, cy, n) => circle(cx, cy, 11, 'fill-ink') + `<text class="t t-s t-b t-num t-mid" x="${cx}" y="${cy + 4.5}">${n}</text>`;
const at = (x, y, s) => `<g transform="translate(${x} ${y})">${s}</g>`;

function wide() {
  const w = 140, gap = 15, h = 168;
  let s = '';
  draw.forEach((d, i) => {
    const x = i * (w + gap);
    s += rect(x + 1.25, 1.25, w - 2.5, h - 2.5, 'p-frame', 9) + dot(x + 18, 18, i + 1) + at(x + 0, 30, d()) + text(x + w / 2, 142, titles[i][0], 't t-b', 'm') + text(x + w / 2, 158, titles[i][1], 't t-b', 'm');
  });
  return svgBox(760, h, 'Five small drawings in a row, numbered 1 to 5. A file, cards and a cloud key over one row of six steps; a card or cloud key that was born there, against a file that can be copied; one bundle holding X.509 roots, OpenPGP roots and cards; a request going to a bundle and an answer coming back; and a checklist of what is due, a plan and six numbered steps.', s, 'fig-wide');
}

function narrow() {
  const h = 104, gap = 10;
  let s = '';
  draw.forEach((d, i) => {
    const y = i * (h + gap);
    s += rect(1.25, y + 1.25, 357.5, h - 2.5, 'p-frame', 9) + dot(16, y + 16, i + 1) + at(30, y + 4, d()) + text(176, y + 48, titles[i][0], 't t-b') + text(176, y + 64, titles[i][1], 't t-b');
  });
  return svgBox(360, 5 * h + 4 * gap, 'Five small drawings in a column, numbered 1 to 5, each with a title. A file, cards and a cloud key over one row of six steps; a card or cloud key that was born there, against a file that can be copied; one bundle holding X.509 roots, OpenPGP roots and cards; a request going to a bundle and an answer coming back; and a checklist of what is due, a plan and six numbered steps.', s, 'fig-narrow');
}

export default {
  id: 'ideas',
  kind: 'layout',
  label: 'The five ideas of ritueel, drawn small',
  caption: 'The five ideas of ritueel, one small drawing each.',
  wide: wide(),
  narrow: narrow(),
};
