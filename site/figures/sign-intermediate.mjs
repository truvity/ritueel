// How ritueel helps you sign an intermediate certificate with a root card on your own workstation, told in
// the three things of every ceremony, like the figure `ceremony`: what is wanted, the plan, apply. The
// accent is the plan, the one sheet that carries the digest and the numbers of signatures and touches.
// Rests on the hand-off contract (What travels, Messages and files) and on these records:
// - record 0005, rule 7: the plan; record 0005, rule 9: the eight typed characters;
// - record 0005, rules 10 and 12: the attempt first, the ceremony record last;
// - record 0005, rule 23: a key that cannot be copied may be used on the holder's workstation with a
//   touch for every signature, the number of signatures stated in the plan, no retry of a failed touch
//   and the result checked against the plan on a second device.
// The check on the second device and the hand-over come after the ceremony: the page says them in the
// caption of the figure; they are not panels.
import { acc, arrow, card, line, rect, server, sheet, text } from './draw.mjs';
import { DIGEST, FP, bundle, moments, note, pnl, terminal, under } from './parts.mjs';

function p1() {
  let b = '';
  // the requester's server prints the fingerprint of its key and writes the request and the proof
  b += server(18, 150, 44);
  b += under(40, 'server card', 170);
  b += arrow(66, 66, 100, 66, 'prints', { lx: 83, ly: 58 });
  b += rect(104, 36, 168, 38, 'paper', 5) + text(112, 53, 'key fingerprint', 't t-s t-dim') + text(112, 69, FP, 't t-d t-mono t-b');
  b += arrow(66, 104, 100, 104, 'writes', { lx: 83, ly: 96 });
  b += note(104, 82, 58, 42, 'request', false, false) + note(168, 82, 46, 42, 'proof', false, false);
  // you put the files in the requests part of your bundle
  b += arrow(114, 128, 114, 158, 'copies', { lx: 150, ly: 148 });
  b += bundle(100, 212, 172, 52, 'bundle acme');
  b += rect(108, 186, 156, 20, 'paper-t', 4) + text(116, 200, 'requests/', 't t-s t-mono');
  return pnl(1, '', b, 'A rack with two drawers and its server card in a slot. One arrow prints the key’s fingerprint on a small screen, and another writes two sheets, the request and the proof. An arrow copies the sheets into the requests part of a bundle called acme.');
}

function p2() {
  let b = '';
  b += terminal(6, 112, 92, 52) + text(12, 140, '$ apply', 't t-s t-mono') + text(12, 155, '--plan-only', 't t-s t-mono');
  b += arrow(104, 138, 136, 138, 'writes', { lx: 120, ly: 130, accent: 'plan' });
  // the plan: one sheet, with what this job fixes in it, and the digest written on it
  const x = 142, y = 38, w = 132, h = 140;
  let p = sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 10, y + 24, 'plan', 't t-b t-acc');
  ['request', 'serial', 'times'].forEach((s, i) => {
    const yy = y + 46 + i * 15;
    p += text(x + 10, yy, s, 't t-s t-acc') + line(x + 66, yy - 4, x + w - 12, yy - 4, 'ln ln-thin ln-acc');
  });
  ['signatures', 'touches'].forEach((s, i) => {
    const yy = y + 91 + i * 15;
    p += text(x + 10, yy, s, 't t-s t-acc') + text(x + w - 14, yy, '1', 't t-s t-mono t-acc t-b', 'e');
  });
  p += line(x + 10, y + 108, x + w - 12, y + 108, 'ln ln-thin ln-acc') + text(x + 10, y + 128, DIGEST, 't t-mono t-acc t-b');
  b += acc('plan', p);
  b += under(52, 'no card needed', 190);
  b += under(208, 'in history/', 194);
  return pnl(2, 'Anywhere', b, 'A terminal runs the command apply with the option that stops after the plan. It writes one sheet, the plan, with lines for the request, the serial and the times, the number of signatures and of touches, each 1, and the digest 7f3a 91c2 at its foot. A note says it goes into history. No card is in the picture.');
}

function p3() {
  const cx = 14;
  let b = '';
  b += moments(
    38,
    [
      {
        h: 54,
        icon: (cy) => acc('plan', rect(cx, cy - 16, 96, 32, 'acc-f', 6) + text(cx + 48, cy + 5, DIGEST, 't t-d t-mono t-acc t-b', 'm')),
        lines: ['you type the first', 'eight characters'],
      },
      {
        h: 54,
        icon: (cy) => rect(cx - 4, cy + 14, 52, 6, 'paper-t', 2) + card(cx, cy - 14, 44, 28) + arrow(cx + 50, cy, cx + 82, cy, 'signs', { lx: cx + 66, ly: cy - 8 }) + note(cx + 86, cy - 17, 34, 34, 'cert'),
        lines: [['one touch', 't t-s t-b'], 'for each signature'],
      },
      {
        h: 54,
        icon: (cy) => note(cx, cy - 19, 58, 38, 'record'),
        lines: ['ceremony record', ['written last', 't t-s t-b']],
      },
    ],
    { textX: 144, chevX: cx + 40 },
  );
  return pnl(3, 'Your workstation', b, 'Three moments one under another, with a small chevron between them. The digest 7f3a 91c2 in an accent box, with the words that you type its first eight characters. A root card in its reader, an arrow signs to a certificate sheet, and the words one touch for each signature. A sheet called record and the words ceremony record written last.');
}

export default {
  id: 'sign-intermediate',
  kind: 'strip',
  label: 'Three panels: signing the intermediate of a requester with a root card on a workstation, from the request to apply',
  caption: 'Signing the intermediate of a requester with a root card, on your workstation. The accent follows the plan.',
  panels: [
    { n: 1, title: 'Wanted', caption: 'The requester asks with a request and a proof. You put both in requests/.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'ritueel writes the plan: one signature, one touch, and its digest. No card is needed.', svg: p2() },
    { n: 3, title: 'Apply', caption: 'You type eight characters and touch the card for each signature. The ceremony record comes last.', svg: p3() },
  ],
};
