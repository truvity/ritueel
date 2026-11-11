// How ritueel helps you bind the subkeys of your day-to-day card to your own OpenPGP primary: six panels.
// Rests on the personal reference ("The ceremony of personal subkey add"), record 0008 (a person's own
// key: the primary is a software key in a key file, used only in the offline system because it can be
// copied, record 0005 rule 17) and record 0002 (the key file opens with a passkey on each root card:
// decided, not yet proven). The accent is the plan, as in the other strips.
import { acc, arrow, bubble, card, key, line, person, rect, sheet, text } from './draw.mjs';
import { B, DIGEST, FP, bundle, carryBody, lock, plan, pnl, terminal, under } from './parts.mjs';

const keyRow = (cx, y, word) => key(cx, y, 'ln ln-key') + text(cx + 16, y + 4, word, 't t-s');
const cardHead = (x, y, word = 'day-to-day') => rect(x, y, 16, 12, 'paper-t', 2) + text(x + 22, y + 10.5, word, 't t-s t-b');

function p1() {
  let b = '';
  b += person(46, B, [[1, 78, 150]]);
  b += terminal(78, 118, 52, 44) + text(84, 146, '$ plan', 't t-s t-mono');
  b += arrow(136, 140, 176, 140, 'writes', { lx: 156, ly: 132 });
  const x = 180, y = 38, w = 94, h = 140;
  let p = sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 10, y + 24, 'plan', 't t-b t-acc');
  p += text(x + 10, y + 42, 'card', 't t-s t-acc') + text(x + 10, y + 57, '00000001', 't t-s t-mono t-acc');
  ['slot', 'created', 'touches'].forEach((s, i) => {
    const yy = y + 76 + i * 15;
    p += text(x + 10, yy, s, 't t-s t-acc') + line(x + 62, yy - 4, x + w - 10, yy - 4, 'ln ln-thin ln-acc');
  });
  p += line(x + 10, y + 108, x + w - 10, y + 108, 'ln ln-thin ln-acc') + text(x + 10, y + 128, DIGEST, 't t-mono t-acc t-b');
  b += acc('plan', p);
  b += under(46, 'you');
  return pnl(1, 'Your workstation', b, 'You sit at a terminal that writes the plan: a sheet with the card’s example number 00000001, a slot, a creation time, the number of touches and the digest 7f3a 91c2.');
}

function p2() {
  return pnl(2, '', carryBody([{ text: 'ritueel' }, { text: 'personal' }, { text: 'key file', lock: true }, { text: 'plan', accent: 'plan' }]), 'You are in mid-stride on a ground line with a USB stick in your hand. Chips on the stick show a copy of ritueel, the personal bundle, a key file with a padlock mark and the plan. A curved arrow leads to the offline laptop.');
}

function p3() {
  let b = '';
  b += rect(36, 36, 208, 22, 'paper-g', 11) + text(140, 51, 'decided, not yet proven', 't t-s t-long', 'm');
  b += sheet(8, 92, 52, 56, { rows: 0 }) + lock(28, 116);
  b += under(34, 'key file');
  b += rect(108, 144, 62, 8, 'paper-t', 2) + card(116, 116, 46, 28);
  b += arrow(112, 130, 66, 130, 'unlocks', { lx: 89, ly: 118 });
  b += under(139, 'root card') + under(139, 'passkey, PIN, touch', 208);
  // the drawer with the recovery key, kept apart
  b += rect(198, 104, 72, 62, 'paper', 5) + line(198, 135, 270, 135, 'ln ln-thin');
  b += line(226, 124, 242, 124, 'ln ln-thin') + line(226, 154, 242, 154, 'ln ln-thin');
  b += key(240, 118, 'ln ln-key');
  b += under(234, 'recovery key') + under(234, 'kept apart', 208);
  return pnl(4, 'Offline system', b, 'A key file with a padlock, a root card in a reader and an arrow from the card to the file. Apart from them, a drawer holds the recovery key. A dotted badge says the way is decided but not yet proven.');
}

function p4() {
  let b = '';
  b += rect(8, 42, 144, 100, 'paper', 8) + cardHead(16, 50, 'day-to-day card');
  b += arrow(24, 68, 24, 88, 'makes', { lx: 58, ly: 82 });
  b += rect(16, 90, 128, 46, 'paper-g', 5) + keyRow(30, 104, 'signing') + keyRow(30, 124, 'authentication');
  b += arrow(30, 146, 30, 170, 'back-signs', { lx: 92, ly: 162 });
  b += sheet(8, 172, 68, 40, { rows: 0 }) + text(42, 198, 'back-sig', 't t-s t-b', 'm');
  b += line(152, 118, 162, 138, 'ln ln-thin');
  b += terminal(160, 120, 52, 40) + text(167, 148, '$ _', 't t-s t-mono');
  b += person(232, B, [[-1, 214, 146]]);
  b += bubble(170, 30, 94, 40, 232, 232, 84, []) + text(217, 47, 'PIN', 't t-s t-dim', 'm') + text(217, 63, '••••••', 't t-s t-mono t-b', 'm');
  b += under(232, 'you');
  return pnl(3, 'Offline system', b, 'The day-to-day card is plugged into the terminal. Inside the card, an arrow makes two keys, one ceremony each, a signing key and an authentication key, that stay in the card. The holder types the PIN, and the card gives a back-signature sheet.');
}

function p5() {
  let b = '';
  b += terminal(6, 62, 90, 98);
  b += text(14, 90, 'fingerprint', 't t-s t-dim') + text(14, 108, FP, 't t-d t-mono t-b');
  b += key(28, 138, 'ln ln-key') + text(44, 142, 'primary', 't t-s');
  b += rect(150, 56, 124, 116, 'paper', 8) + cardHead(158, 64);
  b += keyRow(172, 104, 'signing') + keyRow(172, 144, 'authentication');
  b += arrow(102, 104, 146, 104, 'binds', { lx: 124, ly: 96 });
  b += arrow(102, 144, 146, 144, 'binds', { lx: 124, ly: 136 });
  return pnl(5, 'Offline system', b, 'A terminal shows a fingerprint first and the primary key in its memory. Two arrows from the primary lead to the two keys in the card.');
}

function p6() {
  let b = '';
  b += bundle(112, 178, 76, 108, 'personal');
  b += rect(118, 94, 64, 40, 'paper-t', 4) + text(125, 108, 'history', 't t-s t-dim') + rect(122, 112, 56, 17, 'hl', 3) + text(150, 124.5, 'record', 't t-s t-b', 'm');
  b += rect(118, 140, 64, 28, 'paper-t', 4) + text(150, 158, 'certificate', 't t-s', 'm');
  b += terminal(6, 112, 48, 40) + text(12, 140, '$ run', 't t-s t-mono');
  b += arrow(60, 114, 104, 114, 'writes', { lx: 82, ly: 106 });
  b += arrow(60, 146, 104, 146, 'rebuilds', { lx: 82, ly: 138 });
  b += person(232, B, [[-1, 204, 124]]);
  b += card(196, 32, 26, 20) + text(246, 46, 'git, ssh', 't t-s', 'm');
  b += text(232, 76, 'you', 't t-s', 'm');
  return pnl(6, 'Offline system', b, 'A terminal writes a record into the history part of the personal bundle and rebuilds the certificate sheet. You hold the unplugged card, marked for git and ssh.');
}

export default {
  id: 'bind-subkeys',
  kind: 'strip',
  label: 'Six panels: binding the subkeys of a day-to-day card to your own OpenPGP primary',
  caption: 'Binding the subkeys of a day-to-day card to your own OpenPGP primary.',
  panels: [
    { n: 1, title: 'Plan', caption: 'The plan names the card, slot, time and touches.', svg: p1() },
    { n: 2, title: 'Carry', caption: 'The stick holds ritueel, your bundle, key file and plan.', svg: p2() },
    { n: 3, title: 'Birth', caption: 'After your PIN, the card makes a subkey. Once for each.', svg: p4() },
    { n: 4, title: 'Unlock', caption: 'To bind, a root card opens the key file. The recovery key stays apart.', svg: p3() },
    { n: 5, title: 'Bind', caption: 'Your primary binds the subkey, one at a time. The fingerprint shows first.', svg: p5() },
    { n: 6, title: 'Record', caption: 'ritueel records it and rebuilds your certificate.', svg: p6() },
  ],
};
