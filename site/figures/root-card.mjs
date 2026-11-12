// The root card, slot by slot: the PIV application's 24 key slots as six rows of four. The wide and the
// tall drawing are both functions of the table in slots.mjs, so they cannot drift apart. The accent
// marks the example bundle acme (row 2) and nothing else. The bundle names are made up.
import { acc, cell, circle, key, line, rect, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { COLUMNS, PIV_ROWS, ROOT_CARD_NOTES, ROOT_CARD_PASSKEY, ROOT_CARD_ROWS } from './slots.mjs';

const LABEL =
  'A root card drawn as 24 PIV key slots in six rows of four, with the key kind written in each held slot. ' +
  'Row 1, the card’s own jobs, holds no root: all four slots are drawn empty. 9d is tagged spare key, a key made there only if the passkey way cannot be used. 9e is tagged never used. ' +
  'Rows 2 to 6 each hold the keys of one bundle, the same kind of key in the same column: X.509 root key, OpenPGP primary, SSH CA key, empty. ' +
  'Row 2 is the example bundle acme. Its key A is on this card and its key B is in the same row of the second card. Row 3 is bundle personal, with an OpenPGP primary only. Row 4 is bundle initech, without an SSH CA key. ' +
  'Row 5 is room for a new bundle, dashed like any empty slot. Row 6 is kept free for a replacement root, dotted and hatched. A pill under the card says a passkey on the card opens key files, decided and not yet proven.';

const dot = (cx, cy, n) => circle(cx, cy, 10, 'fill-ink') + `<text class="t t-s t-b t-num t-mid" x="${cx}" y="${cy + 4.5}">${n}</text>`;
const typeOf = (row, c) => (row.types ? row.types[c] : null) ?? '';
const tagOf = (row, c) => (row.tags ? row.tags[c] : null) ?? '';
const words = (t) => t.trim().split(/\s+/).length;
const sub = (x, y, t) => text(x, y, t, 't t-s t-dim' + (words(t) > 3 ? ' t-long' : ''));

/** One slot of a row, with the small tag of an empty slot written inside it. */
function slot(x, y, w, h, row, r, c) {
  let s = cell(x, y, w, h, PIV_ROWS[r][c], row.states[c], typeOf(row, c));
  const tag = tagOf(row, c);
  if (tag) s += text(x + w / 2, y + h - 9, tag, 't t-s', 'm');
  return s;
}

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

/** The pill under the card: a passkey on each root card opens key files (record 0002). */
function pill(x, y, w, lines) {
  const h = lines.length === 1 ? 30 : 42;
  let s = rect(x, y, w, h, 'paper-t', h / 2 > 15 ? 15 : h / 2) + key(x + 26, y + h / 2, 'ln ln-key');
  lines.forEach((l, i) => {
    s += text(x + 46, y + h / 2 + 4.5 - ((lines.length - 1) * 15) / 2 + i * 15, l, 't t-s t-long');
  });
  return s;
}

function wide() {
  const W = 760;
  const H = 520;
  const x0 = 176, w = 78, g = 6;
  const rowY = (r) => (r === 0 ? 56 : 154 + (r - 1) * 54);
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10) + text(22, 28, 'The root card', 't t-b');
  s += rect(14, 44, 502, 392, 'paper-t', 16);
  COLUMNS.forEach((c, i) => {
    const cx = x0 + i * (w + g) + w / 2;
    s += text(cx, 132, c.type, 't t-s t-b', 'm') + text(cx, 146, c.sub, 't t-s t-dim', 'm');
  });
  s += line(24, 112, 506, 112, 'ln ln-thin ln-dim');
  s += text(34, 138, 'rows 2 to 6:', 't t-s t-dim t-long') + text(34, 152, 'same kind per column', 't t-s t-dim t-long');
  ROOT_CARD_ROWS.forEach((row, r) => {
    const y = rowY(r);
    const a = row.accent;
    let g1 = dot(34, y + 24, row.n) + text(52, y + 21, row.label, 't t-s t-row' + (a ? ' t-acc' : '')) + sub(52, y + 37, row.sub);
    row.states.forEach((st, c) => {
      g1 += slot(x0 + c * (w + g), y, w, 48, row, r, c);
    });
    s += a ? acc('acme', g1) : g1;
  });
  // The notes: a thin rule at the left of each, joined to the rows it speaks about, bold then regular.
  const nx = 550;
  const note = (y0, y1, lines) => {
    let n = line(nx - 10, y0, nx - 10, y1, 'ln ln-thin');
    lines.forEach((l, i) => {
      n += text(nx, y0 + 16 + i * 15, l, 't t-s t-long' + (i === 0 ? ' t-b' : ''));
    });
    return n;
  };
  s += note(50, 130, ROOT_CARD_NOTES.own);
  s += note(154, 364, ROOT_CARD_NOTES.bundles);
  s += note(370, 418, ROOT_CARD_NOTES.free);
  s += pill(14, 450, 440, [ROOT_CARD_PASSKEY.join(' ')]);
  s += legend(24, 494 - 4, 150, false);
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
  const noteLines = {
    0: ['9d: a spare key to open key files,', 'only if the passkey way cannot be used.'],
    5: ['kept free: a replacement root is born', 'here, beside the old one.'],
  };
  ROOT_CARD_ROWS.forEach((row, r) => {
    const a = row.accent;
    if (r === 1) {
      body.push(
        line(16, y + 6, 344, y + 6, 'ln ln-thin ln-dim') +
          text(16, y + 24, 'Rows 2 to 5: four bundles on a pair of cards.', 't t-s t-b t-long') +
          text(16, y + 40, 'Key A here; key B in the same row of card two.', 't t-s t-long') +
          text(16, y + 56, 'Fewer kinds of key leave cells empty.', 't t-s t-long'),
      );
      y += 66;
    }
    let g1 = dot(26, y + 6, row.n) + text(42, y + 10, row.label, 't t-s t-row' + (a ? ' t-acc' : '')) + sub(42 + row.label.length * 7 + 8, y + 10, row.sub);
    row.states.forEach((st, c) => {
      g1 += slot(x0 + c * (w + g), y + 20, w, 42, row, r, c);
    });
    y += 74;
    const lines = noteLines[r];
    if (lines) {
      g1 += line(22, y - 10, 22, y + 5 + (lines.length - 1) * 15, 'ln ln-thin');
      lines.forEach((l, i) => {
        g1 += text(30, y + 3 + i * 15, l, 't t-s t-long');
      });
      y += 8 + lines.length * 15;
    }
    body.push(a ? acc('acme', g1) : g1);
  });
  s += body.join('');
  y += 6;
  s += pill(16, y, 328, ROOT_CARD_PASSKEY);
  y += 56;
  s += legend(22, y, 160, true);
  const H = y + 62;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-narrow');
}

export default {
  id: 'root-card',
  kind: 'layout',
  label: 'The root card as 24 key slots in six rows of four',
  caption:
    'Six rows of four PIV slots. Row 1 is the card’s own jobs; each other row holds the keys of one bundle, the same key kind in each column.',
  wide: wide(),
  narrow: narrow(),
};
