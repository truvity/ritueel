// How ritueel helps you sign an intermediate certificate: six panels. The accent is the plan, the one
// thing that travels (workstation, stick, offline system) with its digest. Panel viewBox 280 x 224.
import { acc, arrow, arrowq, bubble, card, check, circle, folder, halo, laptop, line, panel, person, rect, server, sheet, stick, stickWithChips, text, wifiOff } from './draw.mjs';

const B = 168; // the ground line of every panel
const under = (x, s, y = 194, cls = 't t-s') => text(x, y, s, cls, 'm');
const DIGEST = '7f3a 91c2';

/** The plan: one sheet, accent, with its digest. It is the same drawing wherever it appears. */
const plan = (x, y, w = 78, h = 50) =>
  acc('plan', sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 8, y + 22, 'plan', 't t-s t-b t-acc') + text(x + 8, y + 40, DIGEST, 't t-s t-mono t-acc t-b'));

function p1() {
  let b = '';
  b += server(8, B, 50);
  b += arrow(62, 128, 92, 128, 'asks', { lx: 77, ly: 100 });
  b += sheet(96, 108, 26, 38);
  b += arrow(126, 128, 152, 128, 'copies', { lx: 139, ly: 100 });
  b += folder(156, B, 52, 44);
  b += person(240, B, [[-1, 212, 150]]);
  b += under(33, 'requester') + under(109, 'request') + under(182, 'bundle acme') + under(240, 'you');
  return panel(1, 'Requester', b, 'A requester with its server card makes a request for a certificate; an arrow from the request sheet into the bundle acme shows you copying it there.');
}

function p2() {
  let b = '';
  b += laptop(10, 104, 102, 58);
  b += text(17, 124, 'ritueel plan', 't t-s t-mono') + text(17, 142, '1 certificate', 't t-s t-dim');
  b += arrow(112, 120, 134, 100, 'makes', { lx: 112, ly: 98 });
  b += plan(136, 70);
  b += arrow(175, 124, 175, 148, 'copies', { accent: 'plan', lx: 142, ly: 142 });
  b += stick(158, 152, 28, 14);
  b += rect(150, 156, 8, 6, 'paper-t', 1.5);
  b += person(240, B, [[-1, 212, 150]]);
  b += under(60, 'your workstation') + under(172, 'stick') + under(240, 'you');
  return panel(2, 'Your workstation', b, 'A laptop makes a plan, drawn as a sheet that carries the digest 7f3a 91c2, and the plan is copied onto a USB stick.');
}

function p3() {
  let b = '';
  b += line(10, B + 1, 270, B + 1, 'ln ln-thin ln-dash ln-dim');
  b += person(38, B, [[1, 76, 120]]);
  b += stickWithChips(80, 90, 76, [{ text: 'ritueel' }, { text: 'bundles' }, { text: 'plan', accent: 'plan' }]);
  b += stick(166, 154, 16, 10, true);
  b += arrowq(100, 82, 150, 52, 206, 92, 'carries', { lx: 156, ly: 58 });
  b += laptop(196, 104, 72, 58);
  b += wifiOff(232, 118);
  b += text(232, 156, 'no network', 't t-s t-dim', 'm');
  b += text(118, 190, 'plan holds the digest', 't t-s t-long', 'm') + text(118, 204, 'of this ritueel copy', 't t-s t-long', 'm');
  b += under(38, 'you') + under(232, 'offline system');
  return panel(3, 'The walk', b, 'You walk with a USB stick that holds a copy of ritueel, the bundles and the plan, towards the offline laptop with no network; a dashed stick shows where it will be plugged in.');
}

function p4() {
  let b = '';
  b += stick(8, 154, 22, 12) + rect(30, 157, 8, 6, 'paper-t', 1.5);
  b += laptop(46, 100, 110, 62);
  b += text(54, 120, 'confirm the plan', 't t-s');
  b += acc('plan', text(54, 138, DIGEST, 't t-d t-mono t-acc t-b') + line(54, 143, 128, 143, 'ln ln-thin ln-acc'));
  b += text(54, 156, 'then PIN, touch', 't t-s t-dim');
  b += rect(164, 150, 8, 6, 'paper-t', 1.5) + card(170, 140, 38, 24);
  b += text(189, 128, 'touch', 't t-s', 'm');
  b += bubble(176, 40, 76, 30, 222, 226, 82, ['PIN'], 't t-s');
  b += person(240, B, [[-1, 212, 142]]);
  b += under(22, 'stick') + under(101, 'offline system') + under(189, 'root card') + under(240, 'you');
  return panel(4, 'Offline system', b, 'At the offline laptop the plan is read from the stick; you type the digest to confirm it, enter the PIN and touch the root card that is plugged in.');
}

function p5() {
  let b = '';
  b += laptop(8, 104, 90, 58);
  b += check(18, 124, 0.9) + text(34, 124, 'signed', 't t-s');
  b += check(18, 142, 0.9) + text(34, 142, 'ok', 't t-s');
  b += arrowq(60, 100, 90, 56, 128, 66, 'verifies', { lx: 100, ly: 48 });
  b += sheet(130, 52, 34, 44, { rows: 0 }) + text(147, 78, 'cert', 't t-s t-b', 'm');
  b += arrow(104, 148, 168, 148, 'writes', { lx: 136, ly: 140 });
  b += sheet(190, 84, 62, 52, { rows: 0 }) + text(221, 100, 'ledger', 't t-s t-b', 'm');
  b += rect(196, 106, 50, 14, 'hl', 2.5) + text(221, 116.5, 'record', 't t-s t-b', 'm');
  b += folder(182, B, 80, 40);
  b += under(53, 'offline system') + under(147, 'certificate', 112 + 0) ;
  b += under(222, 'bundle acme');
  return panel(5, 'Offline system', b, 'The offline laptop checks the signed certificate, then a second arrow writes a record into the ledger sheet that stands in the bundle acme.');
}

function p6() {
  let b = '';
  b += server(8, B, 50);
  b += arrow(152, 150, 66, 150, 'returns', { lx: 109, ly: 142 });
  b += sheet(94, 78, 30, 40, { rows: 0 }) + text(109, 103, 'cert', 't t-s t-b', 'm');
  b += sheet(176, 84, 34, 44, { rows: 0 }) + text(193, 110, 'CA', 't t-s t-b', 'm');
  b += folder(158, B, 52, 44);
  b += halo(193, 74, 'rebuilt', 't t-s', 'm');
  b += person(240, B, [[-1, 212, 150]]);
  b += under(33, 'requester') + under(184, 'bundle acme') + under(240, 'you');
  return panel(6, 'Requester', b, 'The certificate goes back to the requester server; in the bundle acme a CA bundle sheet is rebuilt.');
}

export default {
  id: 'sign-intermediate',
  kind: 'strip',
  label: 'Six panels: signing an intermediate certificate with ritueel',
  caption: 'Signing an intermediate certificate for your PKI, step by step. This is how ritueel is designed to work; the program does not exist yet. The accent follows the plan, the one thing that travels from your workstation to the offline system.',
  panels: [
    { n: 1, title: 'Ask', caption: 'The requester asks for a certificate. You copy its request into the bundle.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'ritueel makes a plan on your workstation. The plan goes onto the stick.', svg: p2() },
    { n: 3, title: 'Carry', caption: 'You carry the stick to the offline system. The plan holds the digest of this ritueel copy.', svg: p3() },
    { n: 4, title: 'Run', caption: 'You type the digest to confirm the plan, give the PIN and touch the root card.', svg: p4() },
    { n: 5, title: 'Record', caption: 'ritueel verifies what was signed, then writes a record in the ledger.', svg: p5() },
    { n: 6, title: 'Return', caption: 'The certificate goes back to the requester, and the CA bundle is rebuilt.', svg: p6() },
  ],
};
