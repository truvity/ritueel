// A passkey on a root card opens a key file, in six panels (record 0002, rules 19 to 23 and "Not yet
// proven", and the page's section "A passkey that opens a key file"): a program
// reads the key file, asks the card for the secret of its passkey, you give the PIN and the touch, the
// secret unwraps the private half of the unlock key, and a recovery key is the other way in. The
// accent is the unlock key. The badge "decided, not yet proven" is drawn once, in panel 2. There is no
// site and no signature here. Where the key handle is kept is not decided, so nothing here draws it.
import { acc, arrow, bubble, card, key, line, person, poly, rect, sheet, text } from './draw.mjs';
import { keyBig } from './key-big.mjs';
import { B, lock, pnl, terminal, under } from './parts.mjs';
import { AY, LY, cardAt, ground, program } from './passkey-parts.mjs';

function p1() {
  let b = ground() + program(8, 84, ['> open']);
  b += sheet(150, 40, 120, 124, { rows: 0 }) + lock(160, 50) + text(178, 61, 'key file', 't t-s t-b');
  b += acc('unlock', rect(160, 76, 100, 26, 'acc-f', 5) + text(210, 93, 'unlock key', 't t-s t-acc t-b', 'm'));
  b += rect(160, 110, 100, 26, 'paper-t', 5) + text(210, 127, 'recovery key', 't t-s', 'm');
  b += arrow(94, AY, 146, AY, 'reads', { lx: 120, ly: AY - 8 });
  b += under(50, 'program', LY) + under(210, 'key file', LY);
  return pnl(1, '', b, 'A terminal and, on a ground line, a key file sheet with a padlock. Two tags sit on the sheet: an accent tag, unlock key, and a plain tag, recovery key. An arrow runs from the terminal to the sheet.');
}

function p2() {
  let b = ground() + program(8, 78, ['> ask']) + cardAt(190, 82);
  b += rect(36, 34, 208, 24, 'paper-g', 12) + text(140, 50, 'decided, not yet proven', 't t-s t-long', 'm');
  b += arrow(88, AY, 186, AY, 'asks for secret', { lx: 137, ly: AY - 8 });
  b += under(47, 'program', LY) + under(231, 'card', LY);
  return pnl(2, '', b, 'A terminal and a card in its reader, with its passkey compartment shaded, on a ground line. An arrow runs from the terminal to the card. A dashed badge above the scene says the way is decided, not yet proven.');
}

function p3() {
  let b = ground() + person(44, B, [[1, 84, 144]]) + program(80, 80, ['> ••••']) + cardAt(192, 80);
  b += bubble(30, 30, 84, 30, 44, 38, 80, ['PIN ••••']);
  b += arrow(164, AY, 190, AY, 'PIN', { lx: 177, ly: AY - 8 });
  b += under(36, 'you', LY) + under(120, 'program', LY) + under(232, 'card', LY);
  return pnl(3, '', b, 'A person on a ground line types at a terminal; a speech bubble above their head shows a masked PIN. A short arrow runs from the terminal to the card in its reader.');
}

function p4() {
  const x = 148;
  let b = ground() + cardAt(x, 124, 2, true) + person(56, B, [[1, x + 34, B - 8 - 60 + 38]]);
  b += under(56, 'you', LY) + under(x + 62, 'card', LY);
  return pnl(4, '', b, 'A person on a ground line reaches an arm to a card in its reader and rests a hand on a round touch spot on the card, which has a dashed ring around it.');
}

function p5() {
  let b = terminal(10, 36, 260, 126);
  b += sheet(24, 84, 60, 56, { rows: 0 }) + lock(30, 90) + text(54, 132, 'wrapped', 't t-s', 'm');
  b += rect(104, 62, 60, 22, 'paper-t', 6) + text(134, 77.5, 'secret', 't t-s', 'm');
  b += arrow(88, 118, 172, 118, 'unwraps', { lx: 130, ly: 110 });
  b += acc('unlock', rect(176, 80, 86, 64, 'acc-f', 7) + keyBig(219, 102, 'ln ln-key ln-acc') + text(219, 132, 'unlock key', 't t-s t-acc', 'm'));
  b += text(140, 194, 'now in memory', 't t-s t-long', 'm');
  return pnl(5, '', b, 'Inside a terminal window, a wrapped key sheet with a padlock and a secret chip above an arrow that leads to an accent box holding a key, the unlock key, which sits in the program’s memory.');
}

function p6() {
  let b = sheet(118, 36, 44, 46, { rows: 0 }) + lock(128, 44) + text(140, 74, 'file', 't t-s', 'm');
  // two root cards of a pair, one overlapping the other
  b += card(10, 108, 52, 34) + card(70, 108, 52, 34);
  b += poly([[10, 150], [10, 156], [122, 156], [122, 150]], 'ln ln-thin');
  b += arrow(96, 104, 118, 82, 'opens', { lx: 80, ly: 90 });
  // the drawer with the recovery key, kept apart
  b += rect(196, 96, 74, 62, 'paper', 5) + line(196, 127, 270, 127, 'ln ln-thin');
  b += line(222, 116, 244, 116, 'ln ln-thin') + line(222, 146, 244, 146, 'ln ln-thin') + key(238, 108, 'ln ln-key');
  b += arrow(200, 94, 164, 80, 'opens', { lx: 212, ly: 80 });
  b += line(176, 96, 176, 204, 'ln ln-thin ln-dash ln-dim');
  b += under(66, 'any one card', 174) + under(66, 'of the pair', 188) + under(66, 'is enough', 202);
  b += under(233, 'recovery key', 176) + under(233, 'kept apart', 190);
  return pnl(6, '', b, 'A key file sheet with a padlock at the top. Two arrows lead to it: one from a pair of root cards side by side under a bracket on the left, one from a drawer holding the recovery key on the right. A dashed line sets the drawer apart from the cards.');
}

export default {
  id: 'passkey-opens-key-file',
  kind: 'strip',
  label: 'Six panels: a passkey on a root card opens a key file, and a recovery key is kept apart',
  caption: 'A passkey on a root card unwraps the unlock key that opens a key file. A recovery key is kept apart.',
  panels: [
    { n: 1, title: 'Read file', caption: 'The program reads the key file, which is locked to the unlock key and the recovery key.', svg: p1() },
    { n: 2, title: 'Ask card', caption: 'The program asks the card for the secret of its passkey. The card waits for the PIN.', svg: p2() },
    { n: 3, title: 'PIN', caption: 'You type the PIN. The record requires it.', svg: p3() },
    { n: 4, title: 'Touch', caption: 'You touch the card. It returns the same secret each time for the same passkey and input.', svg: p4() },
    { n: 5, title: 'Unwrap', caption: 'The secret unwraps the unlock key, and the program opens the file. The key is now in memory.', svg: p5() },
    { n: 6, title: 'Other way', caption: 'Any one root card opens it. The recovery key, a passphrase-protected file kept apart, is the other way.', svg: p6() },
  ],
};
