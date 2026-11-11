// Parts shared by the three figures of the page "How passkeys work": the ground line, a program in
// a terminal, a browser window with its address bar, and a card in its reader (the FIDO2 compartment
// shaded). Built from draw.mjs and parts.mjs; classes of figures.css only.
import { check, circle, line, rect, text } from './draw.mjs';
import { B, terminal } from './parts.mjs';

export const AY = 122; // the height of the arrows between the objects
export const LY = 188; // the baseline of the labels under the objects

export const CH = 60; // the height of the flat card, as in the cards figures

export const ground = () => line(8, B + 2, 272, B + 2, 'ln ln-thin ln-dash ln-dim');

/** The program: a terminal standing on the ground line; `lines` are mono lines inside it. */
export function program(x, w, lines, h = 86) {
  return terminal(x, B - 6 - h, w, h) + lines.map((l, i) => text(x + 8, B - 6 - h + 32 + i * 16, l, 't t-s t-mono')).join('');
}

/**
 * A browser window standing on the ground line: a title bar with three dots and an address bar that
 * holds `addr` (mono). With `ok`, a check mark and the word under the address bar.
 */
export function browser(x, w, addr, ok = '', h = 80) {
  const y = B - 6 - h;
  let s = terminal(x, y, w, h) + rect(x + 6, y + 20, w - 12, 18, 'paper-t', 4) + text(x + 12, y + 33, addr, 't t-s t-mono');
  if (ok) s += check(x + 12, y + 58) + text(x + 30, y + 61, ok, 't t-s');
  return s;
}

/**
 * The card in its reader: three small compartments on top (PIV, OpenPGP, FIDO2) of which `sel` is
 * shaded (2 is FIDO2). Its face carries a chip and a line, or, with `touch`, the round touch spot.
 */
export function cardAt(x, w, sel = 2, touch = false) {
  const y = B - 8 - CH;
  const cw = (w - 8 - 24) / 3;
  let s = rect(x, B - 8, w, 8, 'paper-t', 2) + rect(x + 4, y, w - 8, CH, 'paper', 7);
  for (let i = 0; i < 3; i++) s += rect(x + 12 + i * (cw + 4), y + 8, cw, 16, i === sel ? 'hl' : 'paper-t', 3);
  if (touch) return s + circle(x + 34, y + 38, 10, 'paper-t') + circle(x + 34, y + 38, 16, 'paper-g') + text(x + w - 12, y + 42, 'touch', 't t-s t-b', 'e');
  return s + rect(x + 12, y + 32, 14, 12, 'paper-t', 2) + line(x + 34, y + 38, x + w - 16, y + 38, 'ln ln-thin') + line(x + 34, y + 47, x + w - 28, y + 47, 'ln ln-thin');
}
