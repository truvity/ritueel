// The root card, slot by slot: the PIV application's 24 key slots as six rows of four. The wide and the
// tall drawing are both functions of the table in slots.mjs, so they cannot drift apart. The accent
// marks the example bundle acme (row 3) and nothing else.
import { acc, cell, circle, key, line, path, rect, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { COLUMNS, PIV_ROWS, ROOT_CARD_NOTES, ROOT_CARD_ROWS } from './slots.mjs';

const LABEL =
  'The root card as 24 PIV key slots in six rows of four. Row 1, the card’s own jobs, holds no root; its slot 9d holds a spare key, as an example. ' +
  'Rows 2 to 6 hold one root each with the same kind of key in the same column: X.509 root key, OpenPGP primary, SSH CA key, empty. ' +
  'Row 2 is the bundle personal and row 3 the example bundle acme, root A, whose partner root B sits in the same row on the second card. ' +
  'Rows 4 and 5 are room for a bundle; row 6 is kept free for a replacement root. Rows 2 to 5 give four bundles on a pair of cards.';

const dot = (cx, cy, n) => circle(cx, cy, 10, 'fill-ink') + `<text class="t t-s t-b t-num t-mid" x="${cx}" y="${cy + 4.5}">${n}</text>`;
const rowName = (x, y, row, a) => text(x, y, row.label, 't t-s t-row' + (a ? ' t-acc' : '')) ;
const typeOf = (row, c) => (row.types ? row.types[c] : null) ?? '';

/** The four legend entries: a small slot of each state, and the example bundle. */
function legend(x, y, step, wrap) {
  const items = [
    ['held', (sx, sy) => rect(sx, sy, 26, 16, 'paper cell-held', 4) + key(sx + 14, sy + 8, 'ln ln-key')],
    ['empty', (sx, sy) => rect(sx, sy, 26, 16, 'cell-empty', 4)],
    ['kept free', (sx, sy) => rect(sx, sy, 26, 16, 'cell-free', 4) + line(sx + 7, sy + 12, sx + 17, sy + 4, 'ln ln-thin ln-dim')],
    ['example bundle', (sx, sy) => acc('acme', rect(sx, sy, 26, 16, 'acc-f', 4))],
  ];
  let s = '';
  items.forEach(([name, draw], i) => {
    const sx = x + (wrap ? (i % 2) * step : i * step);
    const sy = y + (wrap ? Math.floor(i / 2) * 26 : 0);
    s += draw(sx, sy) + text(sx + 34, sy + 12.5, name, 't t-s');
  });
  return s;
}

function wide() {
  const W = 760;
  const H = 484;
  const x0 = 134, w = 86, g = 6;
  const rowY = (r) => (r === 0 ? 56 : 154 + (r - 1) * 54);
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10) + text(22, 28, 'The root card', 't t-b');
  s += rect(14, 44, 494, 392, 'paper-t', 16);
  COLUMNS.forEach((c, i) => {
    const cx = x0 + i * (w + g) + w / 2;
    s += text(cx, 132, c.type, 't t-s t-b', 'm') + text(cx, 146, c.sub, 't t-s t-dim', 'm');
  });
  s += line(24, 112, 498, 112, 'ln ln-thin ln-dim');
  s += text(34, 138, 'rows 2 to 6', 't t-s t-dim t-long');
  ROOT_CARD_ROWS.forEach((row, r) => {
    const y = rowY(r);
    const a = row.accent;
    let g1 = dot(34, y + 24, row.n) + rowName(52, y + 21, row, a) + text(52, y + 37, row.sub, 't t-s t-dim');
    row.states.forEach((st, c) => {
      g1 += cell(x0 + c * (w + g), y, w, 48, PIV_ROWS[r][c], st, typeOf(row, c));
    });
    s += a ? acc('acme', g1) : g1;
  });
  // notes: a thin rule at the left of each, bold then regular; the bracket joins rows 2 to 5
  const nx = 548;
  const note = (y, lines, accent) => {
    let n = line(nx - 8, y - 12, nx - 8, y + (lines.length - 1) * 15 + 6, accent ? 'ln ln-acc' : 'ln ln-thin');
    lines.forEach((l, i) => {
      n += text(nx, y + i * 15, l, 't t-s t-long' + (accent ? ' t-acc' : '') + (i === 0 ? ' t-b' : ''));
    });
    return n;
  };
  s += line(508, 80, nx - 14, 80, 'ln ln-thin');
  s += note(70, [ROOT_CARD_NOTES.own.title, "the card's own jobs, no root.", '9d, a spare key, is an example.']);
  s += path('M520 154 H526 V358 H520', 'ln ln-thin');
  s += note(296, ['Rows 2 to 5', 'four bundles on a', 'pair of cards.']);
  s += acc('acme', line(508, 232, nx - 14, 232, 'ln ln-acc') + note(224, ['acme/A', 'card two holds acme/B', 'in this row.'], true));
  s += line(508, 394, nx - 14, 394, 'ln ln-thin');
  s += note(384, ['Row 6', 'kept free: a replacement', 'root is born here.']);
  s += legend(24, 452, 150, false);
  return svgBox(W, H, LABEL, s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const x0 = 22, w = 76, g = 4;
  let s = '';
  let y = 40;
  s += text(16, 27, 'The root card', 't t-b');
  COLUMNS.forEach((c, i) => {
    const cx = x0 + i * (w + g) + w / 2;
    s += text(cx, y + 6, c.type, 't t-s t-b', 'm') + text(cx, y + 20, c.sub, 't t-s t-dim', 'm');
  });
  y += 30;
  const body = [];
  ROOT_CARD_ROWS.forEach((row, r) => {
    const a = row.accent;
    if (r === 1) {
      body.push(line(16, y + 6, 344, y + 6, 'ln ln-thin ln-dim') + text(16, y + 24, 'Rows 2 to 5: four bundles on a pair of cards.', 't t-s t-b t-long'));
      y += 34;
    }
    let g1 = dot(26, y + 6, row.n) + rowName(42, y + 10, row, a) + text(42 + (row.label.length * 7) + 8, y + 10, row.sub, 't t-s t-dim');
    row.states.forEach((st, c) => {
      g1 += cell(x0 + c * (w + g), y + 20, w, 42, PIV_ROWS[r][c], st, typeOf(row, c));
    });
    y += 74;
    const noteFor = { 0: ROOT_CARD_NOTES.own, 2: ROOT_CARD_NOTES.bundle, 5: ROOT_CARD_NOTES.free }[r];
    if (noteFor) {
      const lines = { 0: ['9d, a spare key, is an example.'], 2: ['card two holds acme/B in this row.'], 5: ['a replacement root is born here.'] }[r];
      g1 += line(22, y - 10, 22, y + 5, a ? 'ln ln-acc' : 'ln ln-thin') + text(30, y + 3, lines[0], 't t-s t-long' + (a ? ' t-acc' : ''));
      y += 22;
    }
    body.push(a ? acc('acme', g1) : g1);
  });
  s += body.join('');
  y += 4;
  s += legend(22, y, 160, true);
  const H = y + 62;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-narrow');
}

export default {
  id: 'root-card',
  kind: 'layout',
  label: 'The root card as 24 key slots in six rows of four',
  caption:
    'One root card, slot by slot: each row is one bundle’s root, each column one kind of key. This is how ritueel is designed to lay a card out; the program does not exist yet. The accent marks the example bundle acme.',
  wide: wide(),
  narrow: narrow(),
};
