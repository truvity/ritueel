// How ritueel helps you sign an intermediate certificate with a root card on your own workstation: six
// panels. The accent is the plan, the one sheet that carries the digest and the numbers of signatures
// and touches. Rests on the hand-off contract (What travels, Messages and files, What the requester
// checks) and on record 0005 (rule 18: a key that cannot be copied may be used on the holder's
// workstation under four conditions: a touch for every signature, the number of signatures stated in
// the plan, no retry of a failed touch, and the result checked against the plan on a second device).
import { acc, arrow, bubble, card, check, circle, laptop, line, person, rect, server, sheet, text } from './draw.mjs';
import { B, DIGEST, FP, bundle, note, plan, pnl, terminal, under } from './parts.mjs';

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
  b += arrow(112, 82, 160, 90, 'copies', { lx: 124, ly: 114 });
  b += terminal(6, 142, 82, 44) + text(14, 170, '$ apply', 't t-s t-mono');
  b += arrow(96, 168, 170, 168, 'writes', { lx: 124, ly: 160, accent: 'plan' });
  return pnl(2, 'Your workstation', b, 'Two sheets, request and proof, are copied into the requests part of the bundle acme. Then the terminal runs apply, which writes the plan sheet, with its digest, into the history part of the same bundle.');
}

function p3() {
  let b = '';
  b += terminal(6, 60, 128, 96);
  b += text(14, 90, 'type to confirm', 't t-s t-dim');
  b += acc('plan', text(14, 109, DIGEST, 't t-d t-mono t-acc t-b') + line(14, 114, 90, 114, 'ln ln-thin ln-acc'));
  b += text(14, 131, `fp ${FP}`, 't t-s t-mono');
  b += text(14, 147, 'same as printed?', 't t-s t-dim');
  b += under(70, 'terminal');
  b += person(232, B, [[-1, 168, 150]]);
  b += bubble(172, 22, 96, 42, 232, 232, 76, []) + text(220, 42, DIGEST, 't t-s t-mono t-b', 'm') + text(220, 56, 'first eight', 't t-s t-dim', 'm');
  b += under(232, 'you');
  return pnl(3, 'Your workstation', b, 'A terminal shows the digest and the key fingerprint, with the question whether it is the one the requester printed. The holder types the digest’s first eight characters, shown in a speech bubble.');
}

function p4() {
  let b = '';
  b += terminal(6, 60, 108, 84);
  b += text(14, 90, 'signature 1/1', 't t-s t-mono');
  b += text(14, 110, 'touch the card', 't t-s t-dim');
  b += text(14, 130, 'no retry', 't t-s t-dim');
  b += under(60, 'terminal');
  b += rect(126, 156, 62, 8, 'paper-t', 2) + card(134, 126, 46, 28);
  b += under(157, 'root card');
  b += arrow(148, 120, 148, 84, 'signs', { lx: 178, ly: 98 });
  b += note(132, 44, 32, 40, 'cert');
  b += text(178, 120, 'touch', 't t-s t-b', 'm');
  b += person(232, B, [[-1, 190, 146]]);
  b += under(232, 'you');
  return pnl(4, 'Your workstation', b, 'The terminal says the signature is 1 of 1, asks for a touch and says there is no retry. The holder touches the root card in its reader; an arrow from the card to a certificate sheet shows what the card signs.');
}

function p5() {
  let b = '';
  b += note(8, 52, 54, 44, 'cert');
  b += laptop(20, 112, 64, 44);
  b += under(52, 'workstation');
  // the second device: a tablet outline with a screen, a button below the screen
  b += rect(146, 36, 128, 132, 'paper', 12) + rect(154, 44, 112, 104, 'paper-t', 4) + circle(210, 158, 3.5, 'fill-ink');
  b += plan(160, 52, 100, 50);
  b += check(160, 128, 1.2) + text(181, 132, 'same as plan', 't t-s t-b');
  b += under(210, 'second device');
  b += arrow(66, 74, 150, 74, 'compares', { lx: 108, ly: 66 });
  return pnl(5, 'Second device', b, 'A certificate sheet next to a laptop, and a second device, drawn as a tablet, with the plan sheet and a tick that says it is the same as the plan on its screen. An arrow shows the certificate being compared.');
}

function p6() {
  let b = '';
  b += server(14, B, 52);
  b += arrow(72, 86, 108, 86, 'checks', { lx: 90, ly: 78 });
  b += rect(112, 44, 74, 56, 'paper', 5) + text(117, 64, 'chains to', 't t-s t-mono') + text(117, 80, 'root', 't t-s t-mono') + check(148, 76, 1);
  // the record that ritueel wrote at the workstation: it says where the ceremony ran
  b += sheet(194, 36, 78, 76, { rows: 0 }) + text(233, 56, 'ceremony', 't t-s t-b', 'm') + text(233, 70, 'record', 't t-s t-b', 'm') + text(233, 88, 'ran on', 't t-s t-dim', 'm') + text(233, 102, 'workstation', 't t-s t-dim', 'm');
  b += arrow(204, 140, 72, 140, 'copies answer', { lx: 140, ly: 132 });
  b += note(100, 146, 46, 30, 'cert');
  b += laptop(206, 120, 52, 34);
  b += under(232, 'workstation');
  b += under(40, 'server card');
  return pnl(6, 'The requester’s server', b, 'A laptop sends the certificate sheet to the rack with one arrow. A second arrow shows the rack’s small screen checking that the certificate chains to the root it trusts. The server card is still in its slot. Above the laptop, a sheet called ceremony record says it ran on the workstation.');
}

export default {
  id: 'sign-intermediate',
  kind: 'strip',
  label: 'Six panels: signing an intermediate certificate with a root card on a workstation',
  caption: 'Signing the intermediate of a requester with a root card, on your workstation. The accent follows the plan.',
  panels: [
    { n: 1, title: 'Ask', caption: 'The requester writes a request, a proof and a fingerprint.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'You copy them into the bundle. The command apply writes the plan: one signature, one touch.', svg: p2() },
    { n: 3, title: 'Confirm', caption: 'You type the digest’s start and compare the fingerprint.', svg: p3() },
    { n: 4, title: 'Touch, sign', caption: 'One touch for each signature. A failed touch ends the ceremony.', svg: p4() },
    { n: 5, title: 'Second check', caption: 'You check the certificate against the plan on a second device.', svg: p5() },
    { n: 6, title: 'Hand over', caption: 'The command apply writes the ceremony record last. You hand the certificate over after the second check.', svg: p6() },
  ],
};
