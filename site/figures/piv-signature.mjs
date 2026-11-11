// How a PIV signature happens: six panels, five steps of the page ("How a PIV signature happens")
// with the last one drawn as two: the card signs inside, then the signature goes out. The accent is
// the digest, the one thing the card sees. The digest c4e1 90b7 is made up. Rests on the page's own
// section and its Yubico sources, read 2026-11-10 (PIV PIN and touch policies, PIV).
import { acc, arrow, bubble, circle, person, rect, text } from './draw.mjs';
import { keyBig } from './key-big.mjs';
import { B, note, pnl, under } from './parts.mjs';
import { AY, LY, cardAt, ground, program } from './passkey-parts.mjs';

const DIG = 'c4e1 90b7';

function p1() {
  let b = ground() + program(10, 88, ['> PIV']) + cardAt(182, 90, 0);
  b += arrow(102, AY, 178, AY, 'picks PIV', { lx: 140, ly: AY - 8 });
  b += under(54, 'program', LY) + under(227, 'card', LY);
  return pnl(1, '', b, 'A terminal on the left and a card in its reader on the right, on a ground line. The card shows three small compartments and the first is shaded. An arrow runs from the terminal to the card.');
}

function p2() {
  let b = ground() + person(44, B, [[1, 84, 144]]) + program(84, 78, ['> ••••']) + cardAt(190, 82, 0);
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
  let b = ground() + cardAt(x, 124, -1, true) + person(56, B, [[1, x + 34, B - 8 - 60 + 38]]);
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
  caption: 'A PIV signature in six panels, five steps. The card sees only a digest, and its key never leaves it.',
  panels: [
    { n: 1, title: 'Pick PIV', caption: 'The program picks the PIV application on the card.', svg: p1() },
    { n: 2, title: 'PIN', caption: 'You type the PIN. The program sends it, if the slot’s rule asks for it.', svg: p2() },
    { n: 3, title: 'Send digest', caption: 'The program sends a digest and the slot number.', svg: p3() },
    { n: 4, title: 'Touch', caption: 'The card waits for a touch, if the slot’s rule asks for it. You touch it.', svg: p4() },
    { n: 5, title: 'Sign inside', caption: 'The card signs inside. The key does not move.', svg: p5() },
    { n: 6, title: 'Signature out', caption: 'The card returns the signature.', svg: p6() },
  ],
};
