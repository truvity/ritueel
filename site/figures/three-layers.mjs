// Three layers of a key: where it lives, what it is for, when it ends. The same keys, seen three ways,
// as three bands one under the other. They are the three views of the Inventory of the local page
// (record 0010 rule 10; docs/reference/wizard.md): by card, by root, by date.
//   Band 1, where it lives: a slot of a card, a cloud key, a key file (record 0002 rule 12, 0003 rule 3).
//   Band 2, what it is for: a root, and a delegated key that the root certifies or binds (0001 rule 28).
//   Band 3, when it ends: a delegated key about 13 months and renewed by re-signing (0007 rule 15,
//   0008 rule 10); a root key about 3 years, each use extends it (0007 rule 13, 0009 rule 1); a key
//   replaced on an event, a key file within 3 years (0002 rules 15 and 16).
// The accent is the root, in all three bands: its slot, its box and its bar.
// Wide (760 units, bands are rows) and narrow (360 units, the same bands with their parts stacked) are
// made from the same band functions, so they cannot drift. Words are the records' own; the shapes
// stand for nothing that no record decides.
import { acc, arrow, f, key, line, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { cloud, lock } from './parts.mjs';

const ACC = 'root';
const at = (x, y, s) => `<g transform="translate(${f(x)} ${f(y)})">${s}</g>`;

// A band: the heavy frame of width `w` and height `h`, its title and its dim word. `side` puts the
// title at the left with a rule after it (wide); otherwise the title is on top (narrow).
function frame(w, h, title, word, side) {
  let s = rect(1.25, 1.25, w - 2.5, h - 2.5, 'p-frame', 9);
  if (side) {
    s += text(18, h / 2 - 4, title, 't t-b t-long') + text(18, h / 2 + 15, word, 't t-s t-dim');
    s += line(158, 12, 158, h - 12, 'ln ln-thin ln-dim');
  } else {
    s += text(16, 27, title, 't t-b t-long') + text(w - 16, 27, word, 't t-s t-dim', 'e');
  }
  return s;
}

// --- the parts of band 1: a card with its slots, a cloud key, a key file -----------------------------
// A card of 2 x 4 slots, 132 x 52, top left (x,y). One slot holds a key; it is the accent.
function cardSlots(x, y) {
  let s = rect(x, y, 132, 52, 'paper', 6);
  for (let r = 0; r < 2; r++) {
    for (let c = 0; c < 4; c++) {
      const cx = x + 8 + c * 30;
      const cy = y + 8 + r * 20;
      if (r === 0 && c === 2) s += acc(ACC, rect(cx, cy, 26, 16, 'acc-f cell-held', 3) + key(cx + 13, cy + 8, 'ln ln-key ln-acc'));
      else s += rect(cx, cy, 26, 16, 'cell-empty', 3);
    }
  }
  return s;
}
const cloudKey = (x, y) => cloud(x, y, 1.7) + key(x + 26, y + 29, 'ln ln-key');
const keyFile = (x, y) => sheet(x, y, 36, 46, { rows: 0 }) + lock(x + 12, y + 17);

// Band 1 as one list of [centre x, label, drawing] for a row of three; the icons are 54 units high.
function band1Wide() {
  let s = cardSlots(182, 8) + text(248, 76, 'card slot', 't t-s', 'm');
  s += cloudKey(344, 10) + text(368, 76, 'cloud key', 't t-s', 'm');
  s += keyFile(448, 7) + text(466, 76, 'key file', 't t-s', 'm');
  s += text(560, 43, 'A key is born in one place.', 't t-s t-long');
  return s;
}
function band1Narrow() {
  let s = cardSlots(16, 42) + text(82, 112, 'card slot', 't t-s', 'm');
  s += cloudKey(176, 42) + text(200, 112, 'cloud key', 't t-s', 'm');
  s += keyFile(274, 40) + text(292, 112, 'key file', 't t-s', 'm');
  s += text(16, 140, 'A key is born in one place.', 't t-s t-long');
  return s;
}

// --- band 2: a root, and the delegated key it certifies or binds ---------------------------------------
const rootBox = (x, y) => acc(ACC, rect(x, y, 140, 52, 'acc-f cell-held', 6) + text(x + 70, y + 23, 'root', 't t-b t-acc', 'm') + text(x + 70, y + 41, 'what outsiders trust', 't t-s t-acc', 'm'));
const delegatedBox = (x, y) => rect(x, y, 148, 52, 'paper-t', 6) + text(x + 74, y + 23, 'delegated key', 't t-b', 'm') + text(x + 74, y + 41, 'does daily work', 't t-s t-dim', 'm');

function band2Wide() {
  let s = rootBox(182, 12) + delegatedBox(450, 12);
  s += arrow(322, 38, 446, 38, 'certifies or binds', { ly: 30 });
  s += text(620, 34, 'A root is built from', 't t-s t-long') + text(620, 51, 'one or more keys.', 't t-s t-long');
  return s;
}
function band2Narrow() {
  let s = rootBox(110, 42) + delegatedBox(106, 150);
  s += arrow(180, 98, 180, 146, 'certifies or binds', { lx: 280, ly: 126 });
  s += text(16, 224, 'A root is built from one or more keys.', 't t-s t-long');
  return s;
}

// --- band 3: when it ends. Two bars on one time line, 8 units a month: 13 months and 3 years. ----------
const MONTH = 8;
const bar = (x, y, months, name, accent) => {
  const w = months * MONTH;
  const body = accent
    ? rect(x, y, w, 28, 'acc-f cell-held', 5) + text(x + 12, y + 18.5, name, 't t-b t-acc')
    : rect(x, y, w, 28, 'paper-t', 5) + text(x + 12, y + 18.5, name, 't t-s t-b');
  return accent ? acc(ACC, body) : body;
};

function band3Wide() {
  const x0 = 182;
  let s = bar(x0, 10, 13, 'delegated key') + text(x0 + 13 * MONTH + 12, 28.5, 'about 13 months', 't t-s') + text(x0 + 13 * MONTH + 124, 28.5, 'renewed by re-signing', 't t-s t-dim');
  s += bar(x0, 46, 36, 'root key', true) + text(x0 + 36 * MONTH + 12, 64.5, 'about 3 years', 't t-s') + text(x0 + 36 * MONTH + 106, 64.5, 'each use extends it', 't t-s t-dim t-long');
  s += text(x0, 90, 'Replaced on an event; a key file within 3 years.', 't t-s t-long');
  return s;
}
function band3Narrow() {
  const x0 = 16;
  let s = bar(x0, 42, 13, 'delegated key') + text(x0, 90, 'about 13 months', 't t-s') + text(x0 + 112, 90, 'renewed by re-signing', 't t-s t-dim');
  s += bar(x0, 102, 36, 'root key', true) + text(x0, 150, 'about 3 years', 't t-s') + text(x0 + 112, 150, 'each use extends it', 't t-s t-dim t-long');
  s += text(x0, 176, 'Replaced on an event; a key file within 3 years.', 't t-s t-long');
  return s;
}

const LABEL =
  'Three bands, one above the other, that show one key three ways. Where it lives: a key in a slot of a card, a cloud key and a key file. What it is for: a root and a delegated key, with an arrow from the root to the delegated key that says certifies or binds. When it ends: a delegated key lasts about 13 months and is renewed by re-signing; a root key lasts about 3 years and each use extends it. The root, drawn in the accent colour, is the same root in all three bands.';

function wide() {
  const hs = [82, 76, 98];
  const gap = 6;
  const bands = [
    ['Where it lives', 'by card', band1Wide()],
    ['What it is for', 'by root', band2Wide()],
    ['When it ends', 'by date', band3Wide()],
  ];
  let y = 0;
  let s = '';
  bands.forEach(([t, w, body], i) => {
    s += at(0, y, frame(760, hs[i], t, w, true) + body);
    y += hs[i] + gap;
  });
  return svgBox(760, y - gap, LABEL, s, 'fig-wide');
}

function narrow() {
  const hs = [152, 240, 188];
  const gap = 8;
  const bands = [
    ['Where it lives', 'by card', band1Narrow()],
    ['What it is for', 'by root', band2Narrow()],
    ['When it ends', 'by date', band3Narrow()],
  ];
  let y = 0;
  let s = '';
  bands.forEach(([t, w, body], i) => {
    s += at(0, y, frame(360, hs[i], t, w, false) + body);
    y += hs[i] + gap;
  });
  return svgBox(360, y - gap, LABEL, s, 'fig-narrow');
}

export default {
  id: 'three-layers',
  kind: 'layout',
  label: 'One key seen three ways: where it lives, what it is for, when it ends',
  caption: 'One key, seen three ways: where it lives, what it is for, when it ends.',
  wide: wide(),
  narrow: narrow(),
};
