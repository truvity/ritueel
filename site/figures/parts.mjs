// Parts shared by the strips of the page "How it works" (ceremony, sign-intermediate, bind-subkeys) and
// its other figures: the walking holder, the terminal, the plan sheet, the stick with chips, the bundle.
// They are built from the primitives of draw.mjs and use only classes of figures.css.
import { acc, arrowq, circle, f, line, path, person, rect, sheet, text, wifiOff } from './draw.mjs';
import { svgBox } from './svg.mjs';

export const B = 168; // the ground line of every panel
export const DIGEST = '7f3a 91c2'; // the example digest: the same string wherever the plan appears
export const FP = 'e1b4 02ac'; // an example fingerprint

/** A label under an object, on the shared baseline. */
export const under = (x, s, y = 194, cls = 't t-s') => text(x, y, s, cls, 'm');

/** The frame of a strip panel; the place word is optional, the number dot is always there. */
export function pnl(n, place, body, label) {
  return svgBox(
    280,
    224,
    label,
    rect(2, 2, 276, 220, 'p-frame', 9) +
      circle(21, 20, 11, 'fill-ink') +
      `<text class="t t-s t-b t-num t-mid" x="21" y="24.5">${n}</text>` +
      (place ? text(38, 24.5, place, 't t-s t-dim t-b') : '') +
      body,
  );
}

/** A terminal: a window with a title bar and three dots; the caller writes the lines from y+28. */
export function terminal(x, y, w, h) {
  return (
    rect(x, y, w, h, 'paper', 5) +
    line(x, y + 14, x + w, y + 14, 'ln ln-thin') +
    [0, 1, 2].map((i) => circle(x + 9 + i * 8, y + 7.3, 1.8, 'fill-ink')).join('') +
    rect(x - 3, y + h, w + 6, 6, 'paper', 3)
  );
}

/** The plan: one accent sheet with its digest. The same drawing wherever it appears. */
export const plan = (x, y, w = 78, h = 50) =>
  acc('plan', sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 8, y + 22, 'plan', 't t-s t-b t-acc') + text(x + 8, y + 40, DIGEST, 't t-s t-mono t-acc t-b'));

/** A sheet with a word on it (certificate, request, record). */
export const note = (x, y, w, h, word, accent = false, bold = true) => sheet(x, y, w, h, { rows: 0, accent }) + text(x + w / 2, y + h / 2 + 8, word, 't t-s' + (bold ? ' t-b' : ''), 'm');

/** A bundle: a folder with its name on it, `base` the bottom edge. */
export function bundle(x, base, w, h, name) {
  const top = base - h;
  return (
    path(`M${f(x)} ${f(top)} H${f(x + 26)} L${f(x + 33)} ${f(top - 8)} H${f(x + w)} V${f(base)} H${f(x)} Z`, 'paper') +
    rect(x, top, w, h, 'paper', 5) +
    text(x + 9, top + 17, name, 't t-s t-b')
  );
}

/** A cloud of width 28k and height 24k with its top left at (x,y); k = 1 is the smallest cloud (three-layers and whole-chain use larger ones). */
export const cloud = (x, y, k = 1) =>
  path(`M${f(x)} ${f(y + 24 * k)} H${f(x + 28 * k)} A${f(8 * k)} ${f(8 * k)} 0 0 0 ${f(x + 26 * k)} ${f(y + 9 * k)} A${f(10 * k)} ${f(10 * k)} 0 0 0 ${f(x + 8 * k)} ${f(y + 11 * k)} A${f(7 * k)} ${f(7 * k)} 0 0 0 ${f(x)} ${f(y + 24 * k)} Z`, 'paper');

/** A padlock mark, (x,y) its top left, 12 wide. */
export const lock = (x, y) => path(`M${f(x + 2.5)} ${f(y + 6)} V${f(y + 3.5)} A3.5 3.5 0 0 1 ${f(x + 9.5)} ${f(y + 3.5)} V${f(y + 6)}`, 'ln ln-thin') + rect(x, y + 6, 12, 9, 'paper-t', 2);

/** The holder in mid-stride on the ground line: legs apart, torso above, an arm to (hx,hy) holding a thing. */
export function walker(cx, hx, hy, side = 1) {
  const hipY = B - 26;
  const leg = (x1, x2) => {
    const d = `M${f(x1)} ${f(hipY)} L${f(x2)} ${f(B - 5)}`;
    return path(d, 'arm-o') + path(d, 'arm-i') + circle(x2 + 3, B - 3, 4.5, 'paper');
  };
  return leg(cx - 7, cx - 22) + leg(cx + 8, cx + 20) + person(cx, hipY, [[side, hx, hy]]);
}

/**
 * A stick big enough to show what is on it. chips: [{text, accent, lock, mark}]; the connector is on the right.
 * `mark` names an accent object drawn as a small sheet at the right end of the chip (the plan inside a bundle).
 */
export function stickBig(x, y, w, chips) {
  const h = 14 + chips.length * 18;
  // the plug: a metal shell on the right with two contacts, as on the stick of the stick figure
  let s = rect(x + w, y + h / 2 - 10, 12, 20, 'paper-t', 2) + rect(x + w + 4, y + h / 2 - 6, 4, 4, 'fill-ink', 1) + rect(x + w + 4, y + h / 2 + 2, 4, 4, 'fill-ink', 1) + rect(x, y, w, h, 'paper', 6) + circle(x + 10, y + 8, 2, 'fill-ink');
  chips.forEach((c, i) => {
    const cy = y + 14 + i * 18;
    const left = c.lock || c.mark; // a chip with a mark at its right end writes its word a little to the left
    const chip =
      rect(x + 8, cy, w - 16, 15, c.accent ? 'acc-f' : 'paper-t', 3) +
      text(x + (left ? w / 2 - 8 : w / 2), cy + 11.5, c.text, 't t-s' + (c.accent ? ' t-acc' : ''), 'm') +
      (c.lock ? lock(x + w - 24, cy + 1) : '') +
      (c.mark ? acc(c.mark, sheet(x + w - 22, cy + 1, 11, 13, { accent: true, rows: 0 })) : '');
    s += c.accent ? acc(c.accent, chip) : chip;
  });
  return s;
}

/** The walk of the stick: you in mid-stride with the stick, the offline laptop it goes to, a ground line under both. */
export function carryBody(chips) {
  const h = 14 + chips.length * 18;
  const y = 150 - h;
  let b = '';
  b += line(8, B + 2, 272, B + 2, 'ln ln-thin ln-dash ln-dim');
  b += walker(46, 84, y + h / 2);
  b += stickBig(84, y, 90, chips);
  b += under(129, 'USB stick', 164);
  b += rect(190, 108, 78, 52, 'paper', 5) + rect(182, 160, 94, 7, 'paper', 3.5);
  b += wifiOff(229, 114);
  b += text(229, 154, 'no network', 't t-s t-dim', 'm');
  b += arrowq(129, y - 6, 176, 44, 226, 98, 'carries', { lx: 176, ly: 52 });
  b += text(46, 52, 'you', 't t-s', 'm');
  b += under(229, 'offline system', 186);
  b += text(12, 196, 'the plan records the digest', 't t-s t-long') + text(12, 211, 'of the ritueel that made it', 't t-s t-long');
  return b;
}
