// Drawing helpers for the figures of the site (the "comic" style). Plain Node, no dependency: a
// helper returns an SVG string. A figure module (site/figures/<id>.mjs) puts the strings together;
// site/test/figures.test.mjs checks the result; site/src/components/Figure.astro places it.
//
// Rules the helpers keep, so that a figure cannot break them by accident:
//  - No <style>, <script>, <foreignObject>, <image>, <use>, <defs>, id=, style=, href= or on*= in a
//    drawing. Everything is a class of site/src/styles/figures.css, and the classes use Starlight's
//    own variables, so the light and the dark theme need nothing here.
//  - An arrow always carries its label (arrow() has no form without one).
//  - The one accent object of a figure sits in acc('name', ...): the test counts the names.
import { svgBox } from './svg.mjs';

export { svgBox };

/** A number with at most one decimal, no trailing zero. */
export const f = (v) => {
  const s = (Math.round(v * 10) / 10).toFixed(1).replace(/\.0$/, '');
  return s === '-0' ? '0' : s;
};

export const esc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** A text of the drawing. `cls` is the classes ('t t-s ...'); anchor is 'm' (middle) or 'e' (end). */
export function text(x, y, s, cls = 't', anchor = null) {
  const c = cls + (anchor === 'm' ? ' t-mid' : anchor === 'e' ? ' t-end' : '');
  return `<text class="${c}" x="${f(x)}" y="${f(y)}">${esc(s)}</text>`;
}

/** A text with a paper-coloured halo, for a label that crosses a line. */
export function halo(x, y, s, cls = 't t-s', anchor = null) {
  return text(x, y, s, `${cls} halo`, anchor) + text(x, y, s, cls, anchor);
}

export const rect = (x, y, w, h, cls = 'paper', rx = 4) =>
  `<rect class="${cls}" x="${f(x)}" y="${f(y)}" width="${f(w)}" height="${f(h)}" rx="${f(rx)}"/>`;

export const line = (x1, y1, x2, y2, cls = 'ln') =>
  `<line class="${cls}" x1="${f(x1)}" y1="${f(y1)}" x2="${f(x2)}" y2="${f(y2)}"/>`;

export const path = (d, cls = 'ln') => `<path class="${cls}" d="${d}"/>`;

export const circle = (cx, cy, r, cls = 'paper') =>
  `<circle class="${cls}" cx="${f(cx)}" cy="${f(cy)}" r="${f(r)}"/>`;

export const poly = (pts, cls = 'ln') =>
  `<polyline class="${cls}" points="${pts.map(([a, b]) => `${f(a)},${f(b)}`).join(' ')}"/>`;

/** The accent object of a figure: everything inside is accent-coloured and is named, once. */
export const acc = (name, inner) => `<g data-acc="${name}">${inner}</g>`;

function head(x2, y2, dx, dy, cls) {
  const n = Math.hypot(dx, dy) || 1;
  const ux = dx / n;
  const uy = dy / n;
  const bx = x2 - ux * 9;
  const by = y2 - uy * 9;
  const px = -uy * 4.5;
  const py = ux * 4.5;
  return `<polygon class="${cls}" points="${f(x2)},${f(y2)} ${f(bx + px)},${f(by + py)} ${f(bx - px)},${f(by - py)}"/>`;
}

// An arrow is a group; an accent arrow names the accent object it belongs to (accent: 'plan').
const arrowOpen = (accent) => (accent ? `<g class="ar" data-acc="${accent}">` : '<g class="ar">');

/**
 * A straight arrow from (x1,y1) to (x2,y2) with its label, which is required: an arrow says what
 * moves ("copies", "carries", "writes"). The label sits at (lx,ly), by default above the middle.
 */
export function arrow(x1, y1, x2, y2, label, { accent = false, lx, ly, dashed = false } = {}) {
  if (!label) throw new Error('arrow: a label is required');
  const n = Math.hypot(x2 - x1, y2 - y1);
  const ux = (x2 - x1) / n;
  const uy = (y2 - y1) / n;
  const c = 'ln' + (accent ? ' ln-acc' : '') + (dashed ? ' ln-dash' : '');
  const h = accent ? 'hd hd-acc' : 'hd';
  const mx = lx ?? (x1 + x2) / 2;
  const my = ly ?? (y1 + y2) / 2 - 8;
  return (
    arrowOpen(accent) +
    line(x1, y1, x2 - ux * 7, y2 - uy * 7, c) +
    head(x2, y2, ux, uy, h) +
    halo(mx, my, label, 't t-s' + (accent ? ' t-acc' : ''), 'm') +
    '</g>'
  );
}

/** A curved arrow (one control point) with its required label. */
export function arrowq(x1, y1, cx, cy, x2, y2, label, { accent = false, lx, ly, dashed = false } = {}) {
  if (!label) throw new Error('arrowq: a label is required');
  const c = 'ln' + (accent ? ' ln-acc' : '') + (dashed ? ' ln-dash' : '');
  const h = accent ? 'hd hd-acc' : 'hd';
  const dx = x2 - cx;
  const dy = y2 - cy;
  const n = Math.hypot(dx, dy) || 1;
  const ex = x2 - (dx / n) * 7;
  const ey = y2 - (dy / n) * 7;
  return (
    arrowOpen(accent) +
    path(`M${f(x1)} ${f(y1)} Q${f(cx)} ${f(cy)} ${f(ex)} ${f(ey)}`, c) +
    head(x2, y2, dx, dy, h) +
    halo(lx ?? cx, ly ?? cy - 6, label, 't t-s' + (accent ? ' t-acc' : ''), 'm') +
    '</g>'
  );
}

export const check = (x, y, s = 1) => poly([[x, y], [x + 4 * s, y + 4 * s], [x + 11 * s, y - 6 * s]], 'ln');

/** A key glyph (ring and shaft with two teeth), centred near (cx,cy). */
export function key(cx, cy, cls = 'ln ln-key') {
  return (
    circle(cx - 8, cy, 4.5, cls) +
    line(cx - 3.5, cy, cx + 10, cy, cls) +
    line(cx + 5, cy, cx + 5, cy + 4.5, cls) +
    line(cx + 10, cy, cx + 10, cy + 4.5, cls)
  );
}

// --- the holder ("you"): one fixed figure --------------------------------------------------------
/**
 * Round head with a hair cap, two dot eyes and a smile, a pin-shaped torso standing on `base`,
 * outlined arms ending in round hands. `hands` is a list of [side, hx, hy]: side -1 is the left
 * shoulder, +1 the right; a shoulder without a hand gets an arm hanging down.
 */
export function person(cx, base = 168, hands = []) {
  const hy0 = base - 70;
  const out = [];
  const given = new Map(hands.map(([s, hx, hy]) => [s, [hx, hy]]));
  for (const side of [-1, 1]) {
    const sx = cx + side * 22;
    const sy = base - 46;
    const [hx, hy] = given.get(side) ?? [cx + side * 29, base - 12];
    // the holder (hands included) stays inside a 280-unit panel with a margin: shift the scene, not the holder
    if (hx - 5 < 8 || hx + 5 > 272 || cx - 27 < 8 || cx + 27 > 272) throw new Error(`person: cx ${cx} / hand ${hx} is too close to the panel edge`);
    const qx = (sx + hx) / 2 + side * 3;
    const qy = (sy + hy) / 2 + 8;
    const d = `M${f(sx)} ${f(sy)} Q${f(qx)} ${f(qy)} ${f(hx)} ${f(hy)}`;
    out.push(path(d, 'arm-o'), path(d, 'arm-i'), circle(hx, hy, 4.5, 'paper'));
  }
  out.push(
    path(
      `M${f(cx - 27)} ${f(base)} V${f(base - 38)} Q${f(cx - 27)} ${f(base - 55)} ${f(cx - 11)} ${f(base - 56)} H${f(cx + 11)} Q${f(cx + 27)} ${f(base - 55)} ${f(cx + 27)} ${f(base - 38)} V${f(base)} Z`,
      'paper',
    ),
    circle(cx, hy0, 13, 'paper'),
    path(
      `M${f(cx - 13)} ${f(hy0 - 1)} A13 13 0 0 1 ${f(cx + 13)} ${f(hy0 - 1)} Q${f(cx)} ${f(hy0 - 8)} ${f(cx - 13)} ${f(hy0 - 1)} Z`,
      'fill-ink',
    ),
    circle(cx - 4.5, hy0 + 2, 1.7, 'fill-ink'),
    circle(cx + 4.5, hy0 + 2, 1.7, 'fill-ink'),
    path(`M${f(cx - 4)} ${f(hy0 + 7)} Q${f(cx)} ${f(hy0 + 10.5)} ${f(cx + 4)} ${f(hy0 + 7)}`, 'ln ln-thin'),
  );
  return out.join('');
}

// --- things ---------------------------------------------------------------------------------------
/** A laptop: the screen is (x,y,w,h), the base sits under it. */
export const laptop = (x, y, w, h) => rect(x, y, w, h, 'paper', 5) + rect(x - 9, y + h, w + 18, 7, 'paper', 3.5);

/** A rack with two drawers, its server card standing in a slot. `base` is the ground line. */
export function server(x, base = 168, w = 52) {
  const top = base - 96;
  return (
    rect(x, top, w, 96, 'paper', 5) +
    rect(x + 8, top + 10, w - 16, 15, 'paper-t', 3) + circle(x + 15, top + 17.5, 2, 'fill-ink') +
    rect(x + 8, top + 31, w - 16, 15, 'paper-t', 3) + circle(x + 15, top + 38.5, 2, 'fill-ink') +
    rect(x + 8, base - 30, w - 16, 7, 'paper-t', 2) +
    rect(x + 10, base - 42, w - 20, 24, 'paper', 3) + rect(x + 14, base - 37, 9, 7, 'paper-t', 1.5)
  );
}

/** A card: rounded rectangle, a chip square, one line. */
export function card(x, y, w = 44, h = 28, cls = 'paper') {
  return rect(x, y, w, h, cls, 4) + rect(x + 6, y + 7, 10, 8, 'paper-t', 1.5) + line(x + 22, y + h - 8, x + w - 6, y + h - 8, 'ln ln-thin');
}

/** A small USB stick: a box with a connector (on the right) and a hole. */
export function stick(x, y, w = 28, h = 14, ghost = false) {
  const b = ghost ? 'paper-g' : 'paper';
  const t = ghost ? 'paper-g' : 'paper-t';
  return rect(x + w, y + 3, 10, h - 6, t, 1.5) + rect(x, y, w, h, b, 3) + (ghost ? '' : circle(x + 7, y + h / 2, 2, 'fill-ink'));
}

/**
 * A stick drawn big enough to show what is on it: one chip per entry of `chips` ({text, accent}; accent is the name of the accent object, such as 'plan').
 * The box is (x,y,w,h); its connector is on the right.
 */
export function stickWithChips(x, y, w, chips) {
  const h = 14 + chips.length * 18;
  let s = rect(x + w, y + h / 2 - 9, 10, 18, 'paper-t', 2) + rect(x, y, w, h, 'paper', 6);
  s += circle(x + 10, y + 9, 2, 'fill-ink');
  chips.forEach((c, i) => {
    const cy = y + 14 + i * 18;
    const chip = rect(x + 8, cy, w - 16, 15, c.accent ? 'acc-f' : 'paper-t', 3) + text(x + w / 2, cy + 11.5, c.text, 't t-s' + (c.accent ? ' t-acc' : ''), 'm');
    s += c.accent ? acc(c.accent, chip) : chip;
  });
  return s;
}

/** A sheet with a folded corner and `rows` lines of text-like strokes. */
export function sheet(x, y, w, h, { accent = false, rows = 3 } = {}) {
  const c = accent ? 'acc-f' : 'paper';
  let s = path(`M${f(x)} ${f(y)} H${f(x + w - 9)} L${f(x + w)} ${f(y + 9)} V${f(y + h)} H${f(x)} Z`, c);
  s += path(`M${f(x + w - 9)} ${f(y)} V${f(y + 9)} H${f(x + w)}`, 'ln ln-thin' + (accent ? ' ln-acc' : ''));
  for (let i = 0; i < rows; i++) {
    const yy = y + 18 + i * 8;
    if (yy < y + h - 5) s += line(x + 6, yy, x + w - 7 - (i % 2) * 6, yy, 'ln ln-thin' + (accent ? ' ln-acc' : ''));
  }
  return s;
}

/**
 * A speech bubble (x,y,w,h) whose tail leaves the bottom edge near tx and ends at (tipx,tipy). Keep
 * it for the words a person really says or types ("PIN"), at most one in a panel.
 */
export function bubble(x, y, w, h, tx, tipx, tipy, lines, cls = 't t-s') {
  const r = 9;
  const d =
    `M${f(x + r)} ${f(y)} H${f(x + w - r)} Q${f(x + w)} ${f(y)} ${f(x + w)} ${f(y + r)} V${f(y + h - r)} ` +
    `Q${f(x + w)} ${f(y + h)} ${f(x + w - r)} ${f(y + h)} H${f(tx + 7)} L${f(tipx)} ${f(tipy)} L${f(tx - 7)} ${f(y + h)} ` +
    `H${f(x + r)} Q${f(x)} ${f(y + h)} ${f(x)} ${f(y + h - r)} V${f(y + r)} Q${f(x)} ${f(y)} ${f(x + r)} ${f(y)} Z`;
  const lh = 15;
  const y0 = y + h / 2 - ((lines.length - 1) * lh) / 2 + 4.5;
  return path(d, 'paper') + lines.map((l, i) => text(x + w / 2, y0 + i * lh, l, cls, 'm')).join('');
}

/** A wifi mark with a stroke through it, centred on (cx,cy). */
export function wifiOff(cx, cy) {
  let s = '';
  for (const r of [16, 10, 4]) {
    const a = (40 * Math.PI) / 180;
    const y = cy - r * Math.cos(a) + 12;
    s += path(`M${f(cx - r * Math.sin(a))} ${f(y)} A${r} ${r} 0 0 1 ${f(cx + r * Math.sin(a))} ${f(y)}`, 'ln ln-thin');
  }
  return s + circle(cx, cy + 12, 1.8, 'fill-ink') + line(cx - 17, cy - 8, cx + 17, cy + 22, 'ln');
}

/** The frame of a strip panel: heavy frame, a numbered black dot at the top left, a one-word place. */
export function panel(n, place, body, label, w = 280, h = 224) {
  return svgBox(
    w,
    h,
    label,
    rect(2, 2, w - 4, h - 4, 'p-frame', 9) +
      circle(21, 20, 11, 'fill-ink') +
      `<text class="t t-s t-b t-num t-mid" x="21" y="24.5">${n}</text>` +
      text(38, 24.5, place, 't t-s t-dim t-b') +
      body,
  );
}

// --- slots ------------------------------------------------------------------------------------------
/**
 * One slot cell (x,y,w,h). state: 'empty' (dashed grey outline), 'held' (solid outline, key glyph),
 * 'acme' (held, in the accent of the example bundle), 'free' (dotted heavy outline and a hatch: a
 * row kept free). `id` is the slot id ("86"), `kind` the key type written inside a held slot.
 */
export function cell(x, y, w, h, id, state, kind = '') {
  let s = '';
  if (state === 'empty' || state === 'free') {
    s += rect(x, y, w, h, state === 'empty' ? 'cell-empty' : 'cell-free', 5);
    if (state === 'free') {
      for (let k = 14; k < w + h - 4; k += 9) {
        const x1 = Math.min(k, w - 4);
        const y1 = k - x1;
        const y2 = Math.min(k, h - 4);
        const x2 = k - y2;
        if (x1 > x2 + 1) s += line(x + x1, y + y1 + 2, x + x2 + 2, y + y2, 'ln ln-thin ln-dim');
      }
    }
    s += (state === 'free' ? rect(x + 3, y + 3, 24, 17, 'chip', 3) + text(x + 7, y + 15, id, 't t-s t-mono t-dim t-id') : text(x + 7, y + 15, id, 't t-s t-mono t-dim t-id'));
  } else {
    const a = state === 'acme';
    s += rect(x, y, w, h, a ? 'acc-f cell-held' : 'paper cell-held', 5);
    s += text(x + 7, y + 15, id, 't t-s t-mono t-id' + (a ? ' t-acc' : ' t-dim'));
    s += key(x + w - 21, y + 12, 'ln ln-key' + (a ? ' ln-acc' : ''));
    if (kind) s += text(x + w / 2, y + h - 8, kind, 't t-s t-b' + (a ? ' t-acc' : ''), 'm');
  }
  return s;
}
