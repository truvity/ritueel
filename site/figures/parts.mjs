// Parts shared by the strips of the page "How it works" (ceremony, sign-intermediate, bind-subkeys) and
// its other figures: the terminal, the moments inside a panel, the bundle.
// They are built from the primitives of draw.mjs and use only classes of figures.css.
import { acc, circle, f, line, path, poly, rect, sheet, text } from './draw.mjs';
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

const isNote = (l) => l.split(/\s+/).length > 3; // a line of more than three words is a note: t-long

/**
 * The moments inside one panel, drawn as a short sequence with no numbers: for each row an icon (`icon(cy)`
 * draws it around the middle line cy) and a few short lines of text at textX, with a small chevron between
 * two rows at chevX. A line is a string, or [string, classes]. A row is 44 units high unless it says `h`.
 */
export function moments(y0, rows, { textX = 134, chevX = 30 } = {}) {
  let b = '';
  let y = y0;
  rows.forEach((r, i) => {
    const h = r.h ?? 44;
    const cy = y + h / 2;
    b += r.icon(cy);
    r.lines.forEach((l, k) => {
      const [s, cls] = Array.isArray(l) ? l : [l, isNote(l) ? 't t-s t-long' : 't t-s'];
      b += text(textX, cy - ((r.lines.length - 1) * 15) / 2 + 4 + k * 15, s, cls);
    });
    if (i < rows.length - 1) b += poly([[chevX - 5, y + h - 3], [chevX, y + h + 2], [chevX + 5, y + h - 3]], 'ln ln-thin');
    y += h;
  });
  return b;
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
