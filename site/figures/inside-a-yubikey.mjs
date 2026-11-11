// What is inside a YubiKey 5: three applications that hold keys, side by side, each with its own keys
// and its own lock, with a heavy wall of "separate storage" between them. The wide and the tall drawing
// are both made from the same helpers below, so they cannot drift apart. The accent is the wall.
// Rests on the page's own table and on Yubico, read 2026-11-10: YubiKey 5 applications (separate,
// with separate storage for keys), YubiKey 5 PIV (24 key slots and the factory key in f9), YubiKey 5
// OpenPGP (three keys), YubiKey 5 firmware 5.7 (up to 100 passkeys from firmware 5.7.4).
import { acc, key, line, rect, text } from './draw.mjs';
import { lock } from './parts.mjs';
import { PIV_ROWS } from './slots.mjs';
import { svgBox } from './svg.mjs';

const LABEL =
  'A YubiKey 5 drawn as one card outline with three compartments. The PIV compartment holds 24 small slot squares in six rows of four, set apart from a separate square for the factory key f9, and a padlock for its PIN, PUK and management key. ' +
  'The OpenPGP compartment holds three keys, to sign, to decrypt and to authenticate, and a padlock for its PIN and Admin PIN. ' +
  'The FIDO2 compartment holds eight passkey squares, up to a hundred on newer firmware, and a padlock for one PIN. A heavy wall labelled separate storage stands between each pair of compartments.';

const FACTORY = 'f9';

/** A compartment: paper inside the tinted card; its name (bold) and what it holds (grey). */
function room(x, y, w, h, name, holds) {
  return (
    rect(x, y, w, h, 'paper', 8) +
    text(x + 14, y + 25, name, 't t-b t-row') +
    text(x + w - 14, y + 25, holds, 't t-s t-dim', 'e')
  );
}

/** The lock of a compartment: a padlock and the words, on the line `y` (its baseline). */
const lockRow = (x, y, words) => lock(x, y - 12) + text(x + 20, y, words, 't t-s t-long');

/** The 24 slot squares as six rows of four, from the table of slots.mjs; (x,y) is the top left. */
function slots(x, y, w, h, gx, gy) {
  let s = '';
  PIV_ROWS.forEach((row, r) => {
    row.forEach((id, c) => {
      const cx = x + c * (w + gx);
      const cy = y + r * (h + gy);
      s += rect(cx, cy, w, h, 'paper-t', 4) + text(cx + w / 2, cy + h / 2 + 4, id, 't t-s t-mono t-id', 'm');
    });
  });
  return s;
}

/** The factory key: a square apart from the 24, with its own key glyph. (x,y) top left, 70 wide. */
function factory(x, y) {
  return (
    line(x - 8, y - 14, x - 8, y + 96, 'ln ln-thin ln-dim ln-dash') +
    rect(x, y, 70, 46, 'paper cell-held', 5) +
    text(x + 8, y + 15, FACTORY, 't t-s t-mono t-id t-dim') +
    key(x + 35, y + 32, 'ln ln-key') +
    text(x + 35, y + 66, 'factory key', 't t-s', 'm')
  );
}

/** The three keys of OpenPGP, one row each; (x,y) top left, w wide. */
function openpgpKeys(x, y, w, h, gap) {
  return ['sign', 'decrypt', 'authenticate']
    .map((name, i) => {
      const ky = y + i * (h + gap);
      return rect(x, ky, w, h, 'paper cell-held', 6) + key(x + 24, ky + h / 2, 'ln ln-key') + text(x + 46, ky + h / 2 + 4.5, name, 't t-s');
    })
    .join('');
}

/** Eight passkey squares in two rows of four; (x,y) top left. */
function passkeys(x, y) {
  let s = '';
  for (let i = 0; i < 8; i++) {
    const cx = x + (i % 4) * 44;
    const cy = y + Math.floor(i / 4) * 38;
    s += rect(cx, cy, 38, 32, 'paper cell-held', 5) + key(cx + 20, cy + 16, 'ln ln-key');
  }
  return s;
}

const passkeyWords = (x, y, mid = false) =>
  text(x, y, 'up to 100 passkeys', 't t-s t-b t-long', mid ? 'm' : null) + text(x, y + 17, 'firmware 5.7.4 and later', 't t-s t-long', mid ? 'm' : null);

/** The accent: a wall of separate storage, vertical in the wide drawing, horizontal in the tall one. */
function wallV(x, y, h) {
  return acc(
    'wall',
    rect(x, y, 22, h, 'acc-f', 4) + `<text class="t t-s t-acc t-mid" transform="rotate(-90 ${x + 15.5} ${y + h / 2})" x="${x + 15.5}" y="${y + h / 2}">separate storage</text>`,
  );
}
const wallH = (x, y, w) => acc('wall', rect(x, y, w, 24, 'acc-f', 4) + text(x + w / 2, y + 16.5, 'separate storage', 't t-s t-acc', 'm'));

function wide() {
  const W = 760;
  const H = 330;
  const top = 46;
  const h = 262;
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 14) + text(18, 29, 'A YubiKey 5', 't t-b');
  // PIV
  s += room(14, top, 300, h, 'PIV', '24 key slots');
  s += slots(28, top + 40, 40, 24, 6, 6);
  s += factory(232, top + 58);
  s += lockRow(28, top + h - 16, 'PIN, PUK, management key');
  s += wallV(314, top, h);
  // OpenPGP
  s += room(336, top, 190, h, 'OpenPGP', '3 keys');
  s += openpgpKeys(350, top + 40, 162, 44, 10);
  s += lockRow(350, top + h - 16, 'PIN and Admin PIN');
  s += wallV(526, top, h);
  // FIDO2
  s += room(548, top, 198, h, 'FIDO2', 'passkeys');
  s += passkeys(562, top + 40);
  s += passkeyWords(562, top + 140);
  s += lockRow(562, top + h - 16, 'one PIN');
  return svgBox(W, H, LABEL, s, 'fig-wide');
}

function narrow() {
  const W = 360;
  let y = 44;
  let s = text(16, 29, 'A YubiKey 5', 't t-b');
  // PIV
  const hp = 262;
  s += room(14, y, 332, hp, 'PIV', '24 key slots');
  s += slots(28, y + 40, 50, 24, 6, 6);
  s += factory(262, y + 58);
  s += lockRow(28, y + hp - 16, 'PIN, PUK, management key');
  y += hp;
  s += wallH(14, y, 332);
  y += 24;
  // OpenPGP
  const ho = 196;
  s += room(14, y, 332, ho, 'OpenPGP', '3 keys');
  s += openpgpKeys(28, y + 40, 304, 34, 10);
  s += lockRow(28, y + ho - 16, 'PIN and Admin PIN');
  y += ho;
  s += wallH(14, y, 332);
  y += 24;
  // FIDO2
  const hf = 214;
  s += room(14, y, 332, hf, 'FIDO2', 'passkeys');
  s += passkeys(28, y + 40);
  s += passkeyWords(28, y + 138);
  s += lockRow(28, y + hf - 16, 'one PIN');
  y += hf;
  const H = y + 16;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 14) + s, 'fig-narrow');
}

export default {
  id: 'inside-a-yubikey',
  kind: 'layout',
  label: 'A YubiKey 5 as three separate applications, each with its own keys and lock',
  caption:
    'PIV, OpenPGP and FIDO2 side by side. Each has its own keys and its own lock, and a wall of separate storage stands between them.',
  wide: wide(),
  narrow: narrow(),
};
