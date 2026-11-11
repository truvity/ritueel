// The two kinds of passkey, side by side: one kept on the card (the card holds the record and finds
// it by site name), one not kept on the card (the card holds one small secret and rebuilds the key
// from a key handle that the program or site keeps and hands back). Both panels are drawn once, as
// one function, and arranged twice: side by side (760 wide) or stacked (360 wide, for a phone).
// The accent is the key handle, the thing that tells the two kinds apart.
// Rests on the page's table and its section "Kept on the card, or rebuilt from a key handle", on
// Yubico's FIDO page (100 passkeys from firmware 5.7.4; nothing stored for a passkey not kept on the
// card; reset) and on OpenSSH PROTOCOL.u2f (a small secret of the device plus the key handle),
// all read 2026-11-10 and 2026-11-11 as the page's Sources say. example.com is a made-up domain.
import { acc, arrow, key, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';

const LABEL_W =
  'Two framed panels side by side. On the left, a card that holds three records, each with a site name, an account id and a private key; a chip with the site name example.com points an arrow at the first record. ' +
  'On the right, a card that holds only one small secret, with a dashed key below it that is rebuilt each time, and a separate accent sheet, the key handle, kept outside the card with an arrow that hands it back into the card.';
const LABEL_N = LABEL_W.replace('side by side', 'one above the other');

const P = 340; // the width of a panel
const PH = 256; // its height

/** The left panel: a passkey kept on the card. (px,py) is its top left. */
function kept(px, py) {
  let s = rect(px, py, P, PH, 'p-frame', 12);
  s += text(px + 16, py + 30, 'Kept on the card', 't t-b t-long') + text(px + P - 16, py + 30, '100 at most', 't t-s', 'e');
  s += rect(px + 16, py + 52, 100, 24, 'paper-t', 6) + text(px + 66, py + 68, 'example.com', 't t-s t-mono', 'm');
  s += rect(px + 16, py + 96, 308, 106, 'paper', 8);
  ['example.com', 'globex.com', 'example.org'].forEach((name, i) => {
    const y = py + 106 + i * 32;
    s += rect(px + 26, y, 288, 26, i === 0 ? 'hl' : 'paper-t', 5);
    s += text(px + 36, y + 17, name, 't t-s t-mono') + text(px + 140, y + 17, 'account id', 't t-s');
    s += key(px + 292, y + 13, 'ln ln-key');
  });
  s += arrow(px + 66, py + 78, px + 66, py + 106, 'finds by name', { lx: px + 138, ly: py + 88 });
  s += text(px + 16, py + 224, 'each record: site name, account id, key', 't t-s t-long');
  s += text(px + 16, py + 244, 'after a FIDO reset: erased', 't t-s t-b t-long');
  return s;
}

/** The right panel: a passkey not kept on the card. */
function rebuilt(px, py) {
  let s = rect(px, py, P, PH, 'p-frame', 12);
  s += text(px + 16, py + 30, 'Not kept on the card', 't t-b t-long') + text(px + P - 16, py + 30, 'no limit', 't t-s', 'e');
  s += rect(px + 16, py + 96, 150, 106, 'paper', 8);
  s += rect(px + 26, py + 104, 130, 24, 'paper-t', 5) + key(px + 46, py + 116, 'ln ln-key') + text(px + 64, py + 121, 'one secret', 't t-s');
  s += arrow(px + 91, py + 130, px + 91, py + 148, 'makes', { lx: px + 127, ly: py + 144 });
  s += rect(px + 26, py + 150, 130, 44, 'paper-g', 5) + key(px + 91, py + 165, 'ln ln-key ln-dash') + text(px + 91, py + 186, 'rebuilt each time', 't t-s', 'm');
  s += acc('handle', sheet(px + 250, py + 140, 74, 56, { accent: true, rows: 0 }) + text(px + 287, py + 165, 'key', 't t-s t-b t-acc', 'm') + text(px + 287, py + 181, 'handle', 't t-s t-b t-acc', 'm'));
  s += arrow(px + 248, py + 172, px + 168, py + 172, 'hands back', { accent: 'handle', lx: px + 208, ly: py + 164 });
  s += text(px + 324, py + 216, 'kept by the site', 't t-s t-long', 'e') + text(px + 324, py + 230, 'or the program', 't t-s t-long', 'e');
  s += text(px + 16, py + 224, 'the card needs the handle', 't t-s t-long');
  s += text(px + 16, py + 244, 'after a FIDO reset: stops working', 't t-s t-b t-long');
  return s;
}

function wide() {
  return svgBox(760, PH + 20, LABEL_W, kept(20, 10) + rebuilt(400, 10), 'fig-wide');
}

function narrow() {
  return svgBox(360, PH * 2 + 30, LABEL_N, kept(10, 10) + rebuilt(10, PH + 20), 'fig-narrow');
}

export default {
  id: 'two-kinds-of-passkey',
  kind: 'layout',
  label: 'Two kinds of passkey: kept on the card, or rebuilt in the card from a key handle',
  caption: 'A passkey is kept on the card, or rebuilt inside it from a key handle that someone else keeps.',
  wide: wide(),
  narrow: narrow(),
};
