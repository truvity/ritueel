// A sign-in with a passkey, in six panels (the page's section "How a sign-in works"): the site sends a
// challenge, the browser checks the name and hashes, you give the PIN and the touch, the card signs,
// and the site checks. The accent is the challenge and its hash, the one thing that travels and
// changes every time. Rests on that section, on WebAuthn Level 3 (sections 4, 6.1 and 7.2) and on
// Yubico's FIDO page, as the page's Sources say, read 2026-11-11. The domain example.com and the
// challenge are made up. ritueel signs in to no site: the picture shows what the card does.
import { acc, arrow, bubble, check, circle, key, line, person, rect, server, sheet, text } from './draw.mjs';
import { B, pnl, under } from './parts.mjs';
import { AY, LY, browser, cardAt, ground } from './passkey-parts.mjs';

const hashChip = (x, y, w = 56) => acc('challenge', rect(x, y, w, 22, 'acc-f', 6) + text(x + w / 2, y + 15.5, 'hash', 't t-s t-b t-acc', 'm'));

function p1() {
  let b = ground() + server(10, B, 52) + browser(172, 100, 'example.com');
  b += acc('challenge', sheet(86, 56, 70, 44, { accent: true, rows: 0 }) + text(121, 83, 'challenge', 't t-s t-b t-acc', 'm'));
  b += arrow(66, 124, 168, 124, 'sends', { lx: 117, ly: 116 });
  b += under(36, 'site', LY) + under(222, 'browser', LY);
  return pnl(1, '', b, 'A rack with two drawers, the site, on the left and a browser window on the right, on a ground line. An accent sheet marked challenge sits above an arrow that runs from the site to the browser.');
}

function p2() {
  let b = ground() + browser(6, 100, 'example.com', 'name ok') + cardAt(198, 72);
  b += rect(110, 34, 84, 24, 'paper-t', 6) + text(152, 50.5, 'example.com', 't t-s', 'm');
  b += hashChip(110, 64, 84);
  b += arrow(110, 124, 194, 124, 'hands over', { lx: 152, ly: 116 });
  b += under(56, 'browser', LY) + under(234, 'card', LY);
  b += text(140, 210, 'the card never sees the address', 't t-s t-long', 'm');
  return pnl(2, '', b, 'A browser window with a check mark beside its address bar and a card in its reader, on a ground line. Two chips travel above the arrow between them: the site name and, in accent colour, a hash.');
}

function p3() {
  let b = ground() + person(44, B, [[1, 84, 144]]) + browser(80, 80, '••••') + cardAt(192, 80);
  b += bubble(30, 30, 84, 30, 44, 38, 80, ['PIN ••••']);
  b += arrow(164, AY + 6, 190, AY + 6, 'PIN', { lx: 177, ly: AY - 2 });
  b += under(36, 'you', LY) + under(120, 'browser', LY) + under(232, 'card', LY);
  return pnl(3, '', b, 'A person on a ground line types at a browser window; a speech bubble above their head shows a masked PIN. A short arrow runs from the browser to the card in its reader.');
}

function p4() {
  const x = 148;
  let b = ground() + cardAt(x, 124, 2, true) + person(56, B, [[1, x + 34, B - 8 - 60 + 38]]);
  b += under(56, 'you', LY) + under(x + 62, 'card', LY);
  return pnl(4, '', b, 'A person on a ground line reaches an arm to a card in its reader and rests a hand on a round touch spot on the card, which has a dashed ring around it.');
}

function p5() {
  let b = rect(10, 40, 260, 124, 'paper', 10);
  b += hashChip(18, 88, 46);
  b += arrow(66, 99, 108, 99, 'signs', { lx: 87, ly: 91 });
  b += circle(128, 99, 19, 'paper-g') + key(128, 99);
  b += arrow(150, 99, 196, 99, 'makes', { lx: 173, ly: 91 });
  b += sheet(198, 74, 66, 50, { rows: 0 }) + text(231, 103, 'signature', 't t-s', 'm');
  b += text(128, 138, 'passkey', 't t-s', 'm');
  b += text(140, 192, 'the private key stays inside', 't t-s t-long', 'm');
  return pnl(5, '', b, 'A large card outline. Inside it an accent hash chip points to a key in a dashed ring, and from the ring a second arrow leads to a sheet marked signature.');
}

function p6() {
  let b = rect(8, 40, 264, 120, 'paper', 10) + text(20, 60, 'site', 't t-b');
  b += sheet(20, 74, 70, 48, { rows: 0 }) + text(55, 103, 'signature', 't t-s', 'm');
  b += sheet(190, 74, 70, 48, { rows: 0 }) + text(225, 94, 'public key', 't t-s', 'm') + key(232, 110, 'ln ln-key');
  b += circle(140, 98, 20, 'paper') + line(130, 93, 150, 93, 'ln') + line(130, 103, 150, 103, 'ln');
  b += line(92, 98, 118, 98, 'ln ln-thin') + line(162, 98, 188, 98, 'ln ln-thin');
  b += under(55, 'from the card', 142, 't t-s t-dim') + under(225, 'saved earlier', 142, 't t-s t-dim');
  b += check(116, 192) + text(134, 196, 'signed in', 't t-s t-b');
  return pnl(6, '', b, 'Inside a frame marked site, a signature sheet and a public key sheet are joined by lines to a circle with an equals sign. A check mark and the words signed in stand below the frame.');
}

export default {
  id: 'sign-in',
  kind: 'strip',
  label: 'Six panels: a sign-in with a passkey, from the challenge to the site checking the signature',
  caption: 'A sign-in with a passkey. The card signs a challenge after the PIN and the touch, and the site checks the signature.',
  panels: [
    { n: 1, title: 'Challenge', caption: 'The site sends a random challenge to the browser.', svg: p1() },
    { n: 2, title: 'Name check', caption: 'The browser checks the site name against the address. It hands the card the name and a hash.', svg: p2() },
    { n: 3, title: 'PIN', caption: 'You type the PIN, if the site requires it.', svg: p3() },
    { n: 4, title: 'Touch', caption: 'You touch the card.', svg: p4() },
    { n: 5, title: 'Sign', caption: 'The card finds the passkey and signs with its private key. The key stays in the card.', svg: p5() },
    { n: 6, title: 'Check', caption: 'The site checks the signature against the public key it saved, and the hash of its own name.', svg: p6() },
  ],
};
