// One PIV slot, up close: a slot holds one private key that never leaves the card, an optional
// certificate, and two rules (PIN and touch) chosen when the key is made and never changed; and the
// kind of key says what it can do. Four parts, drawn once and arranged twice (four across, or two by
// two on a phone), so the two drawings cannot drift apart. The accent is the private key and the way
// out that is closed. Rests on the page's section "One PIV slot, up close" and its Yubico sources,
// read 2026-11-10 (PIV certificate slots, PIN and touch policies, key kinds).
import { acc, arrow, circle, line, path, rect, sheet, text } from './draw.mjs';
import { keyBig } from './key-big.mjs';
import { svgBox } from './svg.mjs';

const LABEL =
  'One PIV slot drawn as a frame with four parts side by side. A private key in an accent box, with an arrow that tries to leave the box and is crossed out at its wall. ' +
  'A certificate sheet next to a dashed empty sheet marked or. Two rows of options, the PIN rule (always, once, never) and the touch rule (yes, no), with the first option of each filled. Two chips, signs and key exchange, for what the key can do.';

/** The four icons. `ix` is the left edge of a 150-wide icon, `y` its top; each is 60 high. */
const ICONS = [
  (ix, y) =>
    acc('key', rect(ix, y, 70, 60, 'acc-f', 9) + keyBig(ix + 33, y + 28, 'ln ln-key ln-acc')) +
    // the arrow tries to leave through the wall of the box and is crossed out there
    arrow(ix + 50, y + 44, ix + 148, y + 44, 'read out', { accent: 'key', lx: ix + 112, ly: y + 36 }) +
    circle(ix + 70, y + 44, 8, 'paper') +
    line(ix + 65.5, y + 39.5, ix + 74.5, y + 48.5, 'ln') +
    line(ix + 74.5, y + 39.5, ix + 65.5, y + 48.5, 'ln'),
  (ix, y) =>
    sheet(ix, y, 50, 60, { rows: 3 }) +
    text(ix + 75, y + 34, 'or', 't t-s t-dim', 'm') +
    path(`M${ix + 100} ${y} H${ix + 141} L${ix + 150} ${y + 9} V${y + 60} H${ix + 100} Z`, 'paper-g') +
    text(ix + 125, y + 38, 'none', 't t-s t-dim', 'm'),
  (ix, y) => {
    // two rules, each a row of options with the chosen one filled: the choice is made at birth
    const row = (yy, name, opts) => {
      let s = text(ix + 4, yy, name, 't t-s t-b');
      let cx = ix + 4;
      opts.forEach(([word, w], i) => {
        s += rect(cx, yy + 5, w, 19, i === 0 ? 'hl' : 'paper-t', 9.5) + text(cx + w / 2, yy + 18.5, word, 't t-s' + (i === 0 ? ' t-b' : ''), 'm');
        cx += w + 4;
      });
      return s;
    };
    return row(y + 8, 'PIN rule', [['always', 54], ['once', 42], ['never', 46]]) + row(y + 46, 'touch rule', [['yes', 40], ['no', 36]]);
  },
  (ix, y) =>
    rect(ix + 20, y, 110, 22, 'paper-t', 11) +
    text(ix + 75, y + 15.5, 'signs', 't t-s', 'm') +
    text(ix + 75, y + 35.5, 'or', 't t-s t-dim', 'm') +
    rect(ix + 20, y + 38, 110, 22, 'paper-t', 11) +
    text(ix + 75, y + 53.5, 'key exchange', 't t-s', 'm'),
];

const PARTS = [
  { title: 'private key', sub: ['on the card,', 'never read out'] },
  { title: 'certificate', sub: ['a separate object,', 'optional'] },
  { title: 'chosen at birth', sub: ['never changed'] },
  { title: 'kind of key', sub: ['signs, or agrees on', 'a shared secret'] },
];

/** One part in a column of width `w` whose left edge is `x`; `y` is the top of its icon. */
function part(i, x, y, w) {
  const cx = x + w / 2;
  let s = ICONS[i](cx - 75, y);
  s += text(cx, y + 86, PARTS[i].title, 't t-b t-row', 'm');
  PARTS[i].sub.forEach((l, k) => {
    s += text(cx, y + 104 + k * 16, l, 't t-s t-long', 'm');
  });
  return s;
}

function wide() {
  const W = 760;
  const H = 200;
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 14) + text(18, 29, 'One PIV slot', 't t-b');
  PARTS.forEach((_, i) => {
    const x = 14 + i * 183;
    s += part(i, x, 56, 176);
    if (i > 0) s += line(x - 4, 50, x - 4, 172, 'ln ln-thin ln-dim');
  });
  return svgBox(W, H, LABEL, s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const H = 360;
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 14) + text(18, 29, 'One PIV slot', 't t-b');
  PARTS.forEach((_, i) => {
    const x = 14 + (i % 2) * 168;
    const y = 56 + Math.floor(i / 2) * 150;
    s += part(i, x, y, 164);
  });
  s += line(180, 50, 180, 330, 'ln ln-thin ln-dim') + line(18, 196, 342, 196, 'ln ln-thin ln-dim');
  return svgBox(W, H, LABEL, s, 'fig-narrow');
}

export default {
  id: 'one-piv-slot',
  kind: 'layout',
  label: 'One PIV slot: a private key, a certificate, two rules and a kind',
  caption: 'A slot holds one private key that never leaves the card, an optional certificate, and two rules fixed at birth.',
  wide: wide(),
  narrow: narrow(),
};
