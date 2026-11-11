// The day-to-day card: one card, three applications. The OpenPGP application holds one set of a
// person's subkeys (signing, decryption, authentication); the FIDO2 application holds passkeys for
// signing in; the PIV application stays empty. The accent marks the one set of OpenPGP keys. What is
// born on the card and what is made in software is record 0017, "Day-to-day cards".
import { acc, key, line, rect, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { DAY_CARD } from './slots.mjs';

const LABEL =
  'A day-to-day card drawn as a card with a chip and three bands, with the edge of a second card behind it. ' +
  'The OpenPGP band holds three keys with a key symbol each: signing and authentication, born on the card, and decryption, made in software, loaded on and backed up wrapped in the bundle. ' +
  'The FIDO2 band holds one passkey symbol. The PIV band is a dashed empty outline.';

const W = 360;
const H = 524;
const cx = 10;
const bx = 20;
const bw = 302;

function openpgp(y) {
  let s = rect(bx, y, bw, 170, 'paper-t', 10);
  s += text(bx + 12, y + 21, 'OpenPGP', 't t-b') + text(bx + bw - 12, y + 21, 'one set per card', 't t-s t-dim t-long', 'e');
  const cw = 92;
  const set = DAY_CARD.openpgp.map((k, i) => {
    const x = bx + 7 + i * (cw + 6);
    return rect(x, y + 32, cw, 58, 'acc-f cell-held', 6) + key(x + cw / 2 + 4, y + 50, 'ln ln-key ln-acc') + text(x + cw / 2, y + 80, k.name, 't t-s t-acc', 'm');
  });
  s += acc('openpgp-set', set.join(''));
  DAY_CARD.openpgp.forEach((k, i) => {
    const x = bx + 7 + i * (cw + 6) + cw / 2;
    k.how.forEach((l, j) => {
      s += text(x, y + 108 + j * 15, l, 't t-s t-long', 'm');
    });
  });
  return s;
}

function fido(y) {
  let s = rect(bx, y, bw, 78, 'paper-t', 10) + text(bx + 12, y + 21, 'FIDO2', 't t-b');
  s += rect(bx + 7, y + 32, 92, 36, 'paper cell-held', 6) + key(bx + 57, y + 45, 'ln ln-key') + text(bx + 53, y + 62, 'passkey', 't t-s t-b', 'm');
  s += text(bx + 112, y + 54, 'for signing in', 't t-s t-long');
  return s;
}

function piv(y) {
  return rect(bx, y, bw, 62, 'cell-empty', 10) + text(bx + 12, y + 25, 'PIV', 't t-b') + text(bx + 12, y + 45, 'stays empty', 't t-s t-dim');
}

function drawing() {
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10) + text(16, 27, 'The day-to-day card', 't t-b');
  // the second card behind: its edge shows at the top and the right
  s += rect(cx + 16, 50, 322, 412, 'paper-t', 18) + text(344, 43, 'another card: its own set', 't t-s t-dim t-long', 'e');
  s += rect(cx, 66, 322, 396, 'paper', 18);
  s += rect(bx + 4, 77, 24, 18, 'paper-t', 3) + line(bx + 40, 86, bx + 110, 86, 'ln ln-thin');
  s += openpgp(106) + fido(288) + piv(378);
  // legend
  s += rect(24, 488, 26, 16, 'paper cell-held', 4) + key(38, 496, 'ln ln-key') + text(58, 500.5, 'held', 't t-s');
  s += rect(120, 488, 26, 16, 'cell-empty', 4) + text(154, 500.5, 'empty', 't t-s');
  return svgBox(W, H, LABEL, s, 'fig-small');
}

export default {
  id: 'day-to-day-card',
  kind: 'single',
  label: 'The day-to-day card: OpenPGP subkeys, passkeys, an empty PIV application',
  caption:
    'One day-to-day card holds one set of OpenPGP subkeys and your passkeys, and nothing in PIV. A second day-to-day card gets its own set.',
  svg: drawing(),
};
