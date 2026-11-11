// How ritueel helps you sign an intermediate certificate with a root card: six panels. The accent is
// the plan, the one sheet that travels (workstation, stick, offline system) with its digest. Rests on
// the hand-off contract (What travels, Messages and files, What the requester checks), ADR 0004 and
// ADR 0016 (Where a plan runs: vanilla AirgapOS on a stick with one extra partition, and the plan records
// the digest of the stick's copy of ritueel; the directory names on that partition are proposed).
import { acc, arrow, bubble, card, check, circle, line, person, poly, rect, server, sheet, text } from './draw.mjs';
import { B, DIGEST, FP, bundle, carryBody, note, plan, pnl, terminal, under, walker } from './parts.mjs';

function p1() {
  let b = '';
  b += server(14, B, 52);
  b += arrow(70, 86, 104, 86, 'prints', { lx: 87, ly: 78 });
  b += rect(108, 44, 156, 58, 'paper', 5) + text(118, 66, 'key fingerprint', 't t-s t-dim') + text(118, 88, FP, 't t-d t-mono t-b');
  b += arrow(70, 142, 104, 142, 'writes', { lx: 87, ly: 134 });
  b += note(112, 118, 58, 46, 'request', false, false) + note(176, 118, 46, 46, 'proof', false, false);
  b += under(40, 'server card');
  return pnl(1, 'The requester’s server', b, 'A rack with two drawers and its server card in a slot. One arrow writes two sheets, the request and the proof, and another prints the key’s fingerprint on a small screen.');
}

function p2() {
  let b = '';
  b += note(6, 60, 58, 44, 'request', false, false) + note(68, 60, 40, 44, 'proof', false, false);
  // the bundle: requests on top, its history below, and the plan written there
  b += bundle(150, 214, 124, 160, 'bundle acme');
  b += rect(158, 76, 108, 32, 'paper-t', 4) + text(166, 97, 'requests/', 't t-s t-mono');
  b += rect(158, 116, 108, 90, 'paper-t', 4) + text(166, 132, 'history', 't t-s t-b');
  b += plan(172, 142, 80, 54);
  b += arrow(112, 82, 160, 90, 'copies', { lx: 129, ly: 68 });
  b += terminal(6, 142, 82, 44) + text(14, 170, '$ plan', 't t-s t-mono');
  b += arrow(96, 168, 170, 168, 'writes', { lx: 124, ly: 160, accent: 'plan' });
  return pnl(2, 'Your workstation', b, 'Two sheets, request and proof, are copied into the requests part of the bundle acme. Then the terminal writes the plan sheet, with its digest, into the history part of the same bundle.');
}

function p3() {
  return pnl(3, '', carryBody([{ text: 'ritueel' }, { text: 'bundles' }, { text: 'plan', accent: 'plan' }]), 'You are in mid-stride on a ground line with a USB stick in your hand. Chips on the stick show a copy of ritueel, the bundles and the plan. A curved arrow leads to a laptop with a crossed-out wifi mark, where a dashed stick waits.');
}

function p4() {
  let b = '';
  b += terminal(6, 60, 114, 96);
  b += text(14, 90, 'type to confirm', 't t-s t-dim');
  b += acc('plan', text(14, 109, DIGEST, 't t-d t-mono t-acc t-b') + line(14, 114, 90, 114, 'ln ln-thin ln-acc'));
  b += text(14, 131, `fp ${FP}`, 't t-s t-mono');
  b += text(14, 147, 'same as printed?', 't t-s t-dim');
  b += rect(126, 156, 62, 8, 'paper-t', 2) + card(134, 126, 46, 28);
  b += under(157, 'root card');
  b += arrow(148, 120, 148, 84, 'signs', { lx: 178, ly: 98 });
  b += note(132, 44, 32, 40, 'cert');
  b += text(178, 120, 'touch', 't t-s t-b', 'm');
  b += person(232, B, [[-1, 190, 146]]);
  b += bubble(172, 22, 96, 42, 232, 232, 76, []) + text(220, 42, DIGEST, 't t-s t-mono t-b', 'm') + text(220, 56, 'first eight', 't t-s t-dim', 'm');
  b += under(232, 'you');
  b += under(63, 'terminal');
  return pnl(4, 'Offline system', b, 'A terminal shows the digest and the key fingerprint, with the question whether it is the one the requester printed. The holder types the digest’s first eight characters in a speech bubble and touches the root card in its reader; an arrow from the card to a certificate sheet shows what the card signs.');
}

function p5() {
  let b = '';
  b += note(8, 40, 76, 44, 'request') + note(96, 40, 76, 44, 'certificate') + plan(184, 38, 86, 50);
  b += poly([[46, 92], [46, 98], [227, 98], [227, 92]], 'ln ln-thin');
  b += check(128, 114, 1.2);
  b += terminal(6, 128, 56, 36) + text(13, 154, '$ run', 't t-s t-mono');
  b += arrow(46, 124, 46, 102, 'verifies', { lx: 82, ly: 116 });
  b += arrow(68, 156, 134, 156, 'writes', { lx: 100, ly: 146 });
  // the stick, with the bundle acme and its history holding the record and the transcript
  b += rect(136, 150, 8, 16, 'paper-t', 2) + rect(144, 122, 130, 92, 'paper', 8) + circle(156, 130, 2, 'fill-ink');
  b += text(166, 134, 'bundle acme', 't t-s t-b');
  b += note(150, 142, 46, 40, 'record', false, false) + note(200, 142, 68, 40, 'transcript', false, false);
  b += rect(150, 178, 118, 30, 'paper', 5) + text(160, 198, 'history', 't t-s t-b');
  return pnl(5, 'Offline system', b, 'A tick sits under the certificate, request and plan sheets, checked together. In the next step the terminal writes the record and the transcript into the history part of the bundle acme on the stick.');
}

function p6() {
  let b = '';
  b += server(14, B, 52);
  b += arrow(72, 86, 112, 86, 'checks', { lx: 92, ly: 78 });
  b += rect(116, 44, 88, 56, 'paper', 5) + text(124, 64, 'chains to', 't t-s t-mono') + text(124, 80, 'root', 't t-s t-mono') + check(158, 76, 1);
  b += arrow(162, 130, 72, 130, 'copies answer', { lx: 117, ly: 122 });
  b += note(100, 138, 46, 30, 'cert');
  b += walker(232, 204, 126, -1);
  b += rect(166, 122, 26, 12, 'paper', 3) + rect(192, 125, 10, 6, 'paper-t', 1.5);
  b += text(232, 52, 'you', 't t-s', 'm');
  b += under(40, 'server card');
  return pnl(6, 'The requester’s server', b, 'You walk back with the stick in your hand. One arrow carries the certificate sheet to the rack, and a second arrow shows its small screen checking that the certificate chains to the root it trusts. The server card is still in its slot.');
}

export default {
  id: 'sign-intermediate',
  kind: 'strip',
  label: 'Six panels: signing an intermediate certificate with a root card',
  caption: 'Signing the intermediate of a requester with a root card. The accent follows the plan, the one sheet that travels.',
  panels: [
    { n: 1, title: 'Ask', caption: 'The requester writes a request, a proof and a fingerprint.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'You copy them into the bundle. ritueel writes the plan.', svg: p2() },
    { n: 3, title: 'Carry', caption: 'You carry the stick. The plan names this ritueel copy.', svg: p3() },
    { n: 4, title: 'Confirm, sign', caption: 'You type the digest’s start, compare the fingerprint, then touch the card.', svg: p4() },
    { n: 5, title: 'Check, record', caption: 'ritueel checks the certificate, then writes the record.', svg: p5() },
    { n: 6, title: 'Return', caption: 'You carry the certificate back. The requester checks it.', svg: p6() },
  ],
};
