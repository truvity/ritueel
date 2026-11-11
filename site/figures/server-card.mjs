// The server card: a card that stays plugged into a server of a requester system and signs for its
// services. ritueel lists it and only reads it; its slots follow the requester's own plan. The example
// is the plan that the requester sluis publishes (see SERVER_PLAN in slots.mjs for the source and the
// date read). The accent marks the one slot that ritueel's root certifies, x509-intermediate. The wide
// and the narrow drawing are both functions of the same table.
import { acc, arrow, circle, key, line, rect, server, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { serverCardCells } from './slots.mjs';

const LABEL =
  'A server card drawn as a rack with two drawers and its card standing in a slot, with an arrow to the services it signs for, ' +
  'and the 24 PIV slots of that card as a grid, each used slot named by its purpose in the example plan of the requester sluis. ' +
  'The slot for the x509 intermediate, which the root signs, is in the accent colour. Ten slots are held; the other fourteen are dashed, thirteen spare and one unused. ' +
  'A tag says ritueel only reads this card.';

const TAG = ['ritueel only reads this card:', 'it lists it, adopts nothing,', 'seals nothing, checks no layout.'];

/** One slot: outline by state, the id, the purpose, and a key glyph on a held slot. */
function slot(x, y, w, h, c, narrow) {
  const held = c.state !== 'empty';
  const a = c.state === 'acme';
  let s = rect(x, y, w, h, held ? (a ? 'acc-f cell-held' : 'paper cell-held') : 'cell-empty', 5);
  const ty = narrow ? y + 14 : y + 15;
  s += text(x + 7, ty, c.id, 't t-s t-mono t-id' + (a ? ' t-acc' : ' t-dim'));
  // the key glyph stays inside the cell: its teeth end 9 units short of the border
  if (held) s += key(x + w - 21, y + (narrow ? 10 : 12), 'ln ln-key' + (a ? ' ln-acc' : ''));
  const cls = 't t-s' + (a ? (narrow ? ' t-acc' : ' t-acc t-b') : c.state === 'empty' ? ' t-dim' : '');
  // the purpose has a line of its own under the id and the key
  s += text(x + 8, narrow ? y + 29 : y + 36, c.use, cls);
  return a ? acc('x509', s) : s;
}

function legend(x, y, step, wrap) {
  const items = [
    ['held', (sx, sy) => rect(sx, sy, 26, 16, 'paper cell-held', 4) + key(sx + 14, sy + 8, 'ln ln-key')],
    ['empty', (sx, sy) => rect(sx, sy, 26, 16, 'cell-empty', 4)],
    ['signed by the root', (sx, sy) => acc('x509', rect(sx, sy, 26, 16, 'acc-f', 4))],
  ];
  let s = '';
  items.forEach(([name, draw], i) => {
    const sx = x + (wrap ? (i % 2) * step : i * step);
    const sy = y + (wrap ? Math.floor(i / 2) * 26 : 0);
    s += draw(sx, sy) + text(sx + 34, sy + 12.5, name, 't t-s' + (name.split(' ').length > 3 ? ' t-long' : ''));
  });
  return s;
}

function tag(x, y, w, lines, glass = true) {
  const h = 14 + lines.length * 15;
  let s = rect(x, y, w, h, 'paper-t', 10);
  if (glass) s += circle(x + 21, y + h / 2 - 2, 7, 'ln') + line(x + 26, y + h / 2 + 3, x + 33, y + h / 2 + 10, 'ln');
  lines.forEach((l, i) => {
    s += text(x + 46, y + 22 + i * 15, l, 't t-s t-long');
  });
  return s;
}

function wide() {
  const W = 760;
  const H = 504;
  const cells = serverCardCells();
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10) + text(22, 28, 'The server card', 't t-b');
  // the rack with its card, and what it signs for
  s += rect(30, 62, 120, 30, 'paper-t', 8) + text(90, 82, 'its services', 't t-s', 'm');
  s += arrow(90, 148, 90, 96, 'signs for', { lx: 132, ly: 126 });
  s += server(64, 250, 52);
  s += text(90, 274, 'its server card', 't t-s', 'm') + text(90, 289, 'stays plugged in', 't t-s t-dim', 'm');
  // the slot plan
  const x0 = 186, w = 134, g = 6;
  s += text(x0, 54, 'Example: sluis’s own slot plan (default map, version 1)', 't t-s t-b t-long');
  cells.forEach((c, i) => {
    s += slot(x0 + (i % 4) * (w + g), 68 + Math.floor(i / 4) * 52, w, 46, c, false);
  });
  s += tag(x0, 392, 554, TAG.slice(0, 1).concat([TAG[1] + ' ' + TAG[2]]));
  s += legend(24, 466, 150, false);
  return svgBox(W, H, LABEL, s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const cells = serverCardCells();
  let s = text(16, 27, 'The server card', 't t-b');
  s += server(24, 150, 52);
  s += text(16, 170, 'its server card', 't t-s') + text(16, 185, 'stays plugged in', 't t-s t-dim');
  s += rect(228, 62, 116, 30, 'paper-t', 8) + text(286, 82, 'its services', 't t-s', 'm');
  s += arrow(82, 77, 224, 77, 'signs for', { lx: 153, ly: 66 });
  s += tag(100, 106, 244, TAG);
  s += text(16, 224, 'Example: sluis’s own slot plan', 't t-s t-b t-long') + text(16, 239, '(default map, version 1)', 't t-s t-long');
  const y0 = 254;
  cells.forEach((c, i) => {
    s += slot(12 + (i % 2) * 170, y0 + Math.floor(i / 2) * 44, 164, 38, c, true);
  });
  const ly = y0 + 11 * 44 + 38 + 22;
  s += legend(16, ly, 160, true);
  const H = ly + 52 + 6;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-narrow');
}

export default {
  id: 'server-card',
  kind: 'layout',
  label: 'The server card and the slot plan of an example requester',
  caption:
    'A server card stays plugged into a server and signs for its services; its slots follow the requester’s own plan, here sluis’s. Another requester’s plan will differ.',
  wide: wide(),
  narrow: narrow(),
};
