// How ritueel helps you bind the subkeys of your day-to-day card to your own OpenPGP primary, told in the
// three things of every ceremony, like the figure `ceremony`: what is wanted, the plan, apply. The accent
// is the plan, as in the other strips.
// Rests on the personal reference ("The ceremony of personal subkey add") and on these records:
// - record 0005, rule 7: the plan; record 0005, rules 10 and 12: the attempt first, the ceremony record last;
// - record 0005, rule 22: a key that can be copied is used only in the offline system;
// - record 0008, rule 9: each day-to-day card gets a signing and an authentication subkey, born in one
//   ceremony on the card; the primary, a software key in a key file, binds each;
// - record 0002, rule 19: the key file opens with a passkey on each root card (decided, not yet proven).
// The place of the ceremony, the offline system started from the USB stick, is said in the caption of
// the figure on the page; it is not a panel.
import { acc, arrow, card, key, line, person, sheet, text } from './draw.mjs';
import { B, DIGEST, lock, moments, note, pnl, terminal, under } from './parts.mjs';

function p1() {
  let b = '';
  // the holder edits two plain files: the wanted file of the card, and the delegation called daily
  b += terminal(6, 50, 150, 106);
  b += text(14, 78, 'wanted', 't t-b');
  [['card', 104], ['daily', 124]].forEach(([s, y]) => (b += text(14, y, s, s === 'daily' ? 't t-s t-mono' : 't t-s') + line(62, y - 4, 146, y - 4, 'ln ln-thin')));
  b += under(81, 'two plain files', 182);
  b += person(232, B, [[-1, 166, 122]]);
  b += under(232, 'you edit');
  return pnl(1, 'Your workstation', b, 'A holder at a window edits two plain files, called wanted: a line for the card and a line for the delegation daily. No card is in the picture and nothing is signed.');
}

function p2() {
  let b = '';
  b += person(42, B, [[-1, 15, 156], [1, 73, 150]]);
  // the plan is made first and run later: the command is `apply --plan-only`, on two lines
  b += terminal(73, 118, 86, 52) + text(78, 142, '$ apply', 't t-s t-mono') + text(78, 157, '--plan-only', 't t-s t-mono');
  b += arrow(162, 144, 192, 144, 'plan', { lx: 177, ly: 136 });
  const x = 194, y = 38, w = 80, h = 140;
  let p = sheet(x, y, w, h, { accent: true, rows: 0 }) + text(x + 10, y + 24, 'plan', 't t-b t-acc');
  p += text(x + 10, y + 42, 'card', 't t-s t-acc') + text(x + 10, y + 57, '00000001', 't t-s t-mono t-acc');
  ['slot', 'created', 'touches'].forEach((s, i) => {
    const yy = y + 76 + i * 15;
    p += text(x + 10, yy, s, 't t-s t-acc') + line(x + 58, yy - 4, x + w - 10, yy - 4, 'ln ln-thin ln-acc');
  });
  p += line(x + 10, y + 108, x + w - 10, y + 108, 'ln ln-thin ln-acc') + text(x + 7, y + 128, DIGEST, 't t-mono t-acc t-b');
  b += acc('plan', p);
  b += under(42, 'you');
  return pnl(2, 'Anywhere', b, 'You sit at a terminal that runs apply with the plan-only flag. It writes only the plan. The plan is a sheet. It shows the card’s example number 00000001, a slot, a creation time, the number of touches and the digest 7f3a 91c2.');
}

function p3() {
  // the signing and the authentication subkey, two key glyphs one above the other, drawn around (cx, cy)
  const pair = (cx, cy) => key(cx, cy - 8) + key(cx, cy + 9);
  let b = '';
  b += moments(
    34,
    [
      {
        h: 42,
        icon: (cy) => card(12, cy - 13, 44, 26) + pair(86, cy),
        lines: ['PIN, then your card', 'makes both subkeys'],
      },
      {
        h: 56,
        icon: (cy) => card(10, cy - 13, 40, 26) + arrow(54, cy, 84, cy, 'opens', { lx: 69, ly: cy - 8 }) + sheet(90, cy - 20, 32, 40, { rows: 0 }) + lock(100, cy - 8),
        lines: ['a root card opens', 'the key file', ['decided, not yet proven', 't t-s t-dim t-long']],
      },
      {
        h: 42,
        icon: (cy) => key(26, cy) + arrow(44, cy, 76, cy, 'binds', { lx: 60, ly: cy - 8 }) + pair(98, cy),
        lines: ['your primary binds', 'each subkey'],
      },
      {
        h: 42,
        icon: (cy) => note(12, cy - 17, 58, 34, 'record'),
        lines: ['ceremony record', ['written last', 't t-s t-b']],
      },
    ],
    { textX: 138, chevX: 34 },
  );
  return pnl(3, 'Offline system', b, 'Four moments one under another, with a small chevron between them. A day-to-day card that makes two key glyphs, a signing and an authentication subkey, with the words PIN, then your card makes both subkeys. A root card with an arrow opens to a key file with a padlock, with a note decided, not yet proven. A key glyph for the primary, with an arrow binds to the two subkeys. A sheet called record, with the words ceremony record written last.');
}

export default {
  id: 'bind-subkeys',
  kind: 'strip',
  label: 'Three panels: binding the subkeys of a day-to-day card to your own OpenPGP primary, from the wanted files to apply',
  caption: 'Binding the subkeys of a day-to-day card to your own OpenPGP primary, in the offline system.',
  panels: [
    { n: 1, title: 'Wanted', caption: 'You write the wanted files: your day-to-day card and a delegation called daily. Nothing is born yet.', svg: p1() },
    { n: 2, title: 'Plan', caption: 'The plan names the card, slot, time and touches. It is made on any machine and saved.', svg: p2() },
    { n: 3, title: 'Apply', caption: 'Both subkeys are made after your PIN. A root card opens the key file; your primary binds each.', svg: p3() },
  ],
};
