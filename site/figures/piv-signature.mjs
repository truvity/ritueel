// How a PIV signature happens: six panels, five steps of the page ("How a PIV signature happens")
// with the last one drawn as two: the card signs inside, then the signature goes out. The accent is
// the digest, the one thing the card sees. The digest c4e1 90b7 is made up. Rests on the page's own
// section and its Yubico sources, read 2026-11-10 (PIV PIN and touch policies, PIV).
import { acc, arrow, bubble, circle, line, person, rect, text } from './draw.mjs';
import { keyBig } from './key-big.mjs';
import { B, note, pnl, terminal, under } from './parts.mjs';

const DIG = 'c4e1 90b7';
const ground = () => line(8, B + 2, 272, B + 2, 'ln ln-thin ln-dash ln-dim');
const AY = 122; // the height of the arrows between the program and the card
const LY = 188; // the baseline of the labels under the objects

/** The program: a terminal standing on the ground line; `lines` are mono lines inside it. */
function program(x, w, lines) {
  const h = 86;
  return terminal(x, B - 6 - h, w, h) + lines.map((l, i) => text(x + 8, B - 6 - h + 32 + i * 16, l, 't t-s t-mono')).join('');
}

/**
 * The card in its reader: three small compartments on top (PIV, OpenPGP, FIDO2), `sel` marks one.
 * Its face carries a chip and a line, or, with `touch`, the round touch spot (centre returned in .spot).
 */
function cardAt(x, w, sel = -1, touch = false) {
  const y = B - 8 - 82;
  const cw = (w - 8 - 24) / 3;
  let s = rect(x, B - 8, w, 8, 'paper-t', 2) + rect(x + 4, y, w - 8, 82, 'paper', 7);
  for (let i = 0; i < 3; i++) s += rect(x + 12 + i * (cw + 4), y + 10, cw, 18, i === sel ? 'hl' : 'paper-t', 3);
  if (touch) return s + circle(x + 34, y + 56, 12, 'paper-t') + circle(x + 34, y + 56, 19, 'paper-g') + text(x + w - 12, y + 60, 'touch', 't t-s t-b', 'e');
  return s + rect(x + 12, y + 40, 14, 12, 'paper-t', 2) + line(x + 34, y + 62, x + w - 16, y + 62, 'ln ln-thin') + line(x + 34, y + 70, x + w - 28, y + 70, 'ln ln-thin');
}

function p1() {
  let b = ground() + program(10, 88, ['> PIV']) + cardAt(182, 90, 0);
  b += arrow(102, AY, 178, AY, 'picks PIV', { lx: 140, ly: AY - 8 });
  b += under(54, 'program', LY) + under(227, 'card', LY);
  return pnl(1, '', b, 'A terminal on the left and a card in its reader on the right, on a ground line. The card shows three small compartments and the first is shaded. An arrow runs from the terminal to the card.');
}

function p2() {
  let b = ground() + person(36, B, [[1, 82, 144]]) + program(84, 78, ['> ••••']) + cardAt(190, 82, 0);
  b += bubble(30, 30, 84, 30, 44, 38, 80, ['PIN ••••']);
  b += arrow(166, AY, 187, AY, 'PIN', { lx: 177, ly: AY - 8 });
  b += under(36, 'you', LY) + under(123, 'program', LY) + under(231, 'card', LY);
  return pnl(2, '', b, 'A person on a ground line types at a terminal; a speech bubble above their head shows a masked PIN. A short arrow runs from the terminal to the card in its reader.');
}

function p3() {
  let b = ground() + program(8, 88, ['> digest']) + cardAt(182, 90, 0);
  b += acc('digest', rect(100, 42, 76, 26, 'acc-f', 6) + text(138, 59.5, DIG, 't t-s t-mono t-b t-acc', 'm'));
  b += rect(108, 74, 60, 24, 'paper-t', 6) + text(138, 90, 'slot 9c', 't t-s t-mono', 'm');
  b += arrow(100, AY + 4, 178, AY + 4, 'sends', { lx: 139, ly: AY - 4 });
  b += under(52, 'program', LY) + under(227, 'card', LY);
  b += text(140, 212, 'the card sees only a digest', 't t-s t-long', 'm');
  return pnl(3, '', b, 'A terminal and a card in its reader. Above the arrow between them two chips travel, a digest in accent colour and a slot number. A note under the scene says the card sees only a digest.');
}

function p4() {
  const x = 148;
  let b = ground() + person(56, B, [[1, x + 34, B - 8 - 82 + 56]]) + cardAt(x, 124, -1, true);
  b += under(56, 'you', LY) + under(x + 62, 'card', LY);
  return pnl(4, '', b, 'A person on a ground line reaches an arm to a card in its reader and rests a hand on a round touch spot on the card, which has a dashed ring around it.');
}

function p5() {
  let b = rect(30, 44, 220, 122, 'paper', 10);
  for (let i = 0; i < 3; i++) b += rect(44 + i * 30, 54, 26, 16, i === 0 ? 'hl' : 'paper-t', 3);
  b += rect(44, 90, 88, 28, 'paper-t', 7) + text(88, 108, DIG, 't t-s t-mono', 'm');
  b += circle(212, 108, 30, 'paper-g') + keyBig(212, 108);
  b += arrow(134, 104, 178, 104, 'signs', { lx: 156, ly: 96 });
  b += text(140, 196, 'the key stays inside', 't t-s t-long', 'm');
  return pnl(5, '', b, 'A large card outline with a digest chip on the left and a big key inside a dashed ring on the right. An arrow from the chip to the key shows the card signing. The key sits still inside the card.');
}

function p6() {
  let b = ground() + cardAt(10, 90, 0) + program(182, 90, ['> ']);
  b += note(104, 48, 72, 46, 'signature');
  b += arrow(104, AY, 178, AY, 'returns', { lx: 141, ly: AY - 8 });
  b += under(55, 'card', LY) + under(227, 'program', LY);
  return pnl(6, '', b, 'A card in its reader on the left and a terminal on the right. A sheet marked signature sits above an arrow that runs from the card to the terminal.');
}

export default {
  id: 'piv-signature',
  kind: 'strip',
  label: 'Six panels: a PIV signature, from picking PIV to the signature coming out',
  caption: 'A PIV signature in five steps. The card sees only a digest, and its key never leaves it.',
  panels: [
    { n: 1, title: 'Pick PIV', caption: 'The program picks the PIV application on the card.', svg: p1() },
    { n: 2, title: 'PIN', caption: 'You type the PIN. The program sends it, if the slot’s rule asks for it.', svg: p2() },
    { n: 3, title: 'Send digest', caption: 'The program sends a digest and the slot number.', svg: p3() },
    { n: 4, title: 'Touch', caption: 'The card waits for a touch, if the slot’s rule asks for it. You touch it.', svg: p4() },
    { n: 5, title: 'Sign inside', caption: 'The card signs inside. The key does not move.', svg: p5() },
    { n: 6, title: 'Signature out', caption: 'The card returns the signature.', svg: p6() },
  ],
};
