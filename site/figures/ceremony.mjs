// Every ceremony is the same six steps, and only step 4 uses the root. Rests on record 0005 (a ceremony has six
// steps, in this order). The accent is the plan, whose digest is the one thing the person types.
import { acc, arrow, bubble, card, check, circle, line, person, poly, rect, sheet, text } from './draw.mjs';
import { B, DIGEST, FP, bundle, note, plan, pnl, terminal, under } from './parts.mjs';

function p1() {
  let b = '';
  b += terminal(10, 116, 66, 44) + text(17, 144, '$ apply', 't t-s t-mono');
  b += arrow(82, 138, 116, 138, 'writes', { lx: 99, ly: 130 });
  // the plan: one sheet, with what is fixed in it, and the digest written on it
  const x = 122, y = 38, w = 150, h = 140;
  let p = sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 10, y + 24, 'plan', 't t-b t-acc');
  ['root', 'keys', 'serials', 'times', 'touches'].forEach((s, i) => {
    const yy = y + 46 + i * 15;
    p += text(x + 10, yy, s, 't t-s t-acc') + line(x + 66, yy - 4, x + w - 12, yy - 4, 'ln ln-thin ln-acc');
  });
  p += line(x + 10, y + 108, x + w - 12, y + 108, 'ln ln-thin ln-acc') + text(x + 10, y + 128, DIGEST, 't t-mono t-acc t-b');
  b += acc('plan', p);
  b += under(52, 'no card needed', 190);
  return pnl(1, 'Anywhere', b, 'A terminal shows the command apply and writes one sheet, the plan, with lines for the root, the keys, the serials, the times and the touches, and the digest 7f3a 91c2 at its foot. No card is in the picture.');
}

function p2() {
  let b = '';
  b += terminal(34, 82, 124, 66);
  b += text(42, 110, 'type to confirm', 't t-s t-dim');
  b += acc('plan', text(42, 130, DIGEST, 't t-d t-mono t-acc t-b') + line(42, 135, 118, 135, 'ln ln-thin ln-acc'));
  b += text(42, 145, '>', 't t-s t-mono');
  b += under(96, 'terminal');
  b += person(230, B, [[-1, 184, 152]]);
  b += under(230, 'you');
  b += bubbleTyped();
  return pnl(2, '', b, 'A terminal shows the digest of the plan; the holder at the keyboard types its first eight characters, shown in a speech bubble.');
}

function bubbleTyped() {
  return bubble(170, 30, 100, 42, 230, 230, 84, []) + text(220, 50, DIGEST, 't t-s t-mono t-b', 'm') + text(220, 64, 'first eight', 't t-s t-dim', 'm');
}

function p3() {
  let b = '';
  b += terminal(8, 116, 62, 44) + text(15, 144, 'apply', 't t-s t-mono');
  b += arrow(76, 138, 112, 138, 'writes', { lx: 94, ly: 130 });
  // the history sheet with the attempt marked, and a stamp
  b += sheet(118, 44, 92, 124, { rows: 0 }) + text(128, 66, 'history', 't t-s t-b');
  b += rect(126, 78, 76, 18, 'hl', 3) + text(164, 91, 'attempt', 't t-s t-b', 'm');
  b += line(128, 110, 196, 110, 'ln ln-thin') + line(128, 122, 186, 122, 'ln ln-thin');
  b += circle(178, 148, 14, 'paper') + circle(178, 148, 10, 'ln ln-thin') + poly([[172, 148], [176, 152], [184, 143]], 'ln');
  // the signature that has not happened yet: a ghost card
  b += rect(226, 110, 44, 28, 'paper-g', 4);
  b += text(248, 154, 'not yet', 't t-s t-dim', 'm');
  b += under(140, 'before the first key', 192, 't t-s t-long');
  return pnl(3, '', b, 'A terminal writes an attempt line into the history sheet and stamps it; a dashed ghost card shows that nothing has been signed yet and no key exists yet.');
}

function p4() {
  let b = '';
  b += terminal(6, 74, 112, 78);
  b += text(14, 102, 'fingerprint', 't t-s t-dim') + text(14, 122, FP, 't t-d t-mono t-b') + text(14, 142, 'then touch', 't t-s');
  b += under(62, 'terminal');
  b += rect(120, 156, 62, 8, 'paper-t', 2) + card(128, 126, 46, 28);
  b += under(151, 'root card');
  b += arrow(142, 120, 142, 84, 'signs', { lx: 172, ly: 98 });
  b += sheet(126, 46, 32, 40, { rows: 0 }) + text(142, 70, 'cert', 't t-s t-b', 'm');
  b += text(172, 120, 'touch', 't t-s t-b', 'm');
  b += person(232, B, [[-1, 188, 146]]);
  b += under(232, 'you');
  return pnl(4, '', b, 'The terminal shows the fingerprint first; the holder touches the root card in its reader, and an arrow from the card to a certificate sheet shows what the card signs.');
}

function p5() {
  let b = '';
  b += terminal(6, 116, 50, 40) + text(13, 144, 'apply', 't t-s t-mono');
  b += arrow(64, 138, 114, 138, 'verifies', { lx: 89, ly: 128 });
  b += note(120, 108, 34, 48, 'cert') + plan(160, 106, 82, 50);
  b += circle(160, 88, 22, 'ln') + line(176, 72, 190, 58, 'arm-o') + line(176, 72, 190, 58, 'arm-i');
  b += check(250, 134, 1.2);
  b += under(140, 'by code that did not sign', 192, 't t-s t-long');
  return pnl(5, '', b, 'A magnifier rests over the certificate sheet and the plan sheet, with a tick beside them; the check is made by code that did not sign.');
}

function p6() {
  let b = '';
  b += terminal(6, 124, 52, 40) + text(13, 152, 'apply', 't t-s t-mono');
  b += arrow(64, 150, 100, 150, 'writes', { lx: 82, ly: 140 });
  // in the order they are written: the transcript first, the ceremony record last
  b += note(104, 62, 78, 44, 'transcript');
  b += sheet(188, 62, 82, 44, { rows: 0 }) + text(229, 82, 'ceremony', 't t-s t-b', 'm') + text(229, 97, 'record', 't t-s t-b', 'm');
  b += bundle(116, 178, 154, 54, 'history');
  return pnl(6, '', b, 'A terminal runs apply, which writes two sheets into the history part of the bundle: the transcript on the left, written first, and the ceremony record on the right, written last.');
}

export default {
  id: 'ceremony',
  kind: 'strip',
  label: 'Six panels: the six steps of every ceremony',
  caption: 'The six steps of every ceremony.',
  panels: [
    { n: 1, title: 'Plan', caption: 'apply finds what is not applied yet. The plan fixes every byte to sign, except new keys.', svg: p1() },
    { n: 2, title: 'Confirm', caption: 'You type the first eight characters of its digest.', svg: p2() },
    { n: 3, title: 'Reserve', caption: 'An attempt is written before the first key is born.', svg: p3() },
    { n: 4, title: 'Sign', caption: 'The fingerprint shows first. Then you touch the card.', svg: p4() },
    { n: 5, title: 'Verify', caption: 'Code that did not sign checks the result.', svg: p5() },
    { n: 6, title: 'Record', caption: 'The transcript is written first, the ceremony record last.', svg: p6() },
  ],
};
