// What a person does in a ceremony, in three panels: say what is wanted, read the plan, run apply.
// Rests on record 0005 (a person says what is wanted, reads the plan of what is not applied yet, and runs
// apply, which a typed confirmation allows). The accent is the root card, because only apply uses the root.
import { acc, arrow, bubble, card, line, person, rect, sheet, text } from './draw.mjs';
import { B, DIGEST, pnl, terminal, under } from './parts.mjs';

function p1() {
  let b = '';
  // the holder edits one plain file; no card, nothing signed
  b += terminal(10, 58, 150, 106);
  b += text(18, 86, 'wanted', 't t-b');
  [[100, 150], [114, 128], [128, 142], [142, 106]].forEach(([y, x2]) => (b += line(18, y, x2, y, 'ln ln-thin')));
  b += under(85, 'a plain file');
  b += person(232, B, [[-1, 166, 122]]);
  b += under(232, 'you edit');
  return pnl(1, '', b, 'A holder at a window edits one plain file, called wanted. No card is in the picture and no terminal command is run.');
}

function p2() {
  let b = '';
  b += terminal(6, 112, 92, 52) + text(12, 140, '$ apply', 't t-s t-mono') + text(12, 155, '--plan-only', 't t-s t-mono');
  b += arrow(104, 138, 136, 138, 'writes', { lx: 120, ly: 130 });
  // the plan: one sheet, with what is fixed in it, and the digest written on it
  const x = 142, y = 38, w = 132, h = 140;
  let p = sheet(x, y, w, h, { rows: 0 }) + text(x + 10, y + 24, 'plan', 't t-b');
  ['root', 'keys', 'serials', 'times', 'touches'].forEach((s, i) => {
    const yy = y + 46 + i * 15;
    p += text(x + 10, yy, s, 't t-s') + line(x + 66, yy - 4, x + w - 12, yy - 4, 'ln ln-thin');
  });
  p += line(x + 10, y + 108, x + w - 12, y + 108, 'ln ln-thin') + text(x + 10, y + 128, DIGEST, 't t-mono t-b');
  b += p;
  b += under(52, 'no card needed', 190);
  return pnl(2, 'Anywhere', b, 'A terminal runs the command apply with the option that stops after the plan. It writes one sheet, the plan. The plan has lines for the root, the keys, the serials, the times and the touches, and the digest 7f3a 91c2 at its foot. No card is in the picture.');
}

function p3() {
  let b = '';
  // apply, in a terminal: the notes beside it say what matters to the reader, in no numbered order
  b += terminal(6, 36, 156, 84) + text(14, 64, '$ apply', 't t-s t-mono');
  b += text(14, 82, 'attempt first', 't t-s t-dim') + text(14, 97, 'checked by other code', 't t-s t-dim t-long') + text(14, 112, 'record last', 't t-s t-dim');
  // the holder types the first eight characters, then touches the root card, which signs
  b += bubble(170, 30, 104, 42, 232, 232, 84, []) + text(222, 50, DIGEST, 't t-s t-mono t-b', 'm') + text(222, 64, 'first eight', 't t-s t-dim', 'm');
  b += rect(120, 172, 62, 8, 'paper-t', 2) + acc('root', card(128, 148, 46, 28, 'acc-f'));
  b += under(151, 'root card');
  b += text(151, 141, 'touch', 't t-s t-b', 'm');
  b += arrow(122, 162, 66, 162, 'signs', { accent: 'root', lx: 94, ly: 154 });
  b += sheet(26, 142, 36, 44, { rows: 0 }) + text(44, 169, 'cert', 't t-s t-b', 'm');
  b += person(232, B, [[-1, 186, 164]]);
  b += under(232, 'you');
  return pnl(3, '', b, 'A terminal runs apply. The holder types the first eight characters of the plan’s digest, shown in a speech bubble, then touches the root card in its reader; an arrow from the card to a certificate sheet shows what the card signs. Three notes in the terminal say that the attempt is written first, that other code checks the result, and that the ceremony record is last.');
}

export default {
  id: 'ceremony',
  kind: 'strip',
  label: 'Three panels: what you do in a ceremony, from what is wanted to running apply',
  caption: 'What you do in a ceremony: say what is wanted, read the plan, run apply.',
  panels: [
    { n: 1, title: 'Wanted', caption: 'You write what is wanted in plain files. Nothing is signed.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'ritueel finds what is not applied yet. The plan fixes every byte to sign, except new keys.', svg: p2() },
    { n: 3, title: 'Apply', caption: 'You type eight characters and touch the card. The attempt comes first, the ceremony record last.', svg: p3() },
  ],
};
