// Four things (a web page, a signed tag, a release file, a server login) and the root each one ends at.
// The page "What is a root?" shows it under its first sentence. Each panel says in one short note how its
// thing ends at a root; the bar under the panels says that each has its own and how a root is used.
// The words are the page's own and the records':
//   Web page: the page "What is a root?" (a browser follows signatures to a root it already holds);
//     record 0006 rule 23 (the CA bundle holds the certificates of the active X.509 roots).
//   Signed tag: record 0008 rule 9 (a signing subkey on the card, bound by the primary key).
//   Release file: record 0009 rules 12, 24 and 25 (users check a signature with a keyring or a published fingerprint).
//   Server login: record 0006 rules 16, 25 and 27 (a host trusts a signed list of SSH CA keys; the list is
//     signed with an X.509 root key; an SSH CA key is a delegated key) and docs/learn/chain-ssh.md (an SSH CA
//     key signs user certificates). Not the OpenPGP authentication subkey (0008 rule 9): a host that lists
//     that subkey in authorized_keys trusts it on its own and never follows its binding to a root.
//   Bar: the page "What is a root?", "It is used rarely".
// The four things end at several roots, not one: a web page at an X.509 root, the tag and the release file
// at OpenPGP roots, the server login at the X.509 root that signs the SSH CA key list (record 0001 rules 28 to 31:
// a root is of one kind). The figure says "a root", never "one key", and the bar says each has its own.
// The accent marks the bar, which is the one object. Wide (760 units) and narrow (360 units) are made from the same table, so their
// words cannot drift.
import { acc, circle, line, path, poly, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { lock } from './parts.mjs';

const ACC = 'root';
const at = (x, y, s) => `<g transform="translate(${x} ${y})">${s}</g>`;

const THINGS = [
  {
    name: 'A web page',
    tag: 'X.509, TLS',
    lines: ['Your browser follows', 'signatures to a root', 'already on it.'],
  },
  {
    name: 'A signed tag',
    tag: 'OpenPGP, signing',
    lines: ['A signing subkey', 'signed it. The primary', 'key binds the subkey.'],
  },
  {
    name: 'A release file',
    tag: 'OpenPGP, signature',
    lines: ['Its signature is checked', 'against a keyring or a', 'published fingerprint.'],
  },
  {
    name: 'A server login',
    tag: 'SSH CA',
    lines: ['A CA key signs your login.', 'The host trusts it from a', 'list that a root signed.'],
  },
];

// --- icons, about 34 x 28, top left at (x, y) -------------------------------------------------------
const ICONS = [
  // a web page with a padlock
  (x, y) =>
    rect(x, y + 1, 34, 27, 'paper', 4) +
    line(x, y + 9, x + 34, y + 9, 'ln ln-thin') +
    [5, 10.5, 16].map((d) => circle(x + d, y + 5, 1.3, 'fill-ink')).join('') +
    lock(x + 11, y + 12),
  // a tag with a hole and a tick
  (x, y) =>
    path(`M${x + 1} ${y + 3} H${x + 20} L${x + 34} ${y + 14} L${x + 20} ${y + 25} H${x + 1} Z`, 'paper') +
    circle(x + 8, y + 14, 2.4, 'paper-t') +
    poly([[x + 17, y + 15], [x + 20.5, y + 18.5], [x + 26, y + 10]], 'ln'),
  // a file and a badge with its signature
  (x, y) => sheet(x + 1, y, 24, 28, { rows: 3 }) + rect(x + 12, y + 11, 24, 18, 'paper', 5) + text(x + 24, y + 24.5, 'sig', 't t-s t-b', 'm'),
  // two servers and a key
  (x, y) =>
    rect(x, y + 1, 18, 11, 'paper', 3) +
    circle(x + 5, y + 6.5, 1.5, 'fill-ink') +
    rect(x, y + 15, 18, 11, 'paper', 3) +
    circle(x + 5, y + 20.5, 1.5, 'fill-ink') +
    circle(x + 23, y + 13, 3.5, 'ln ln-key') +
    line(x + 26.5, y + 13, x + 34, y + 13, 'ln ln-key') +
    line(x + 30, y + 13, x + 30, y + 17, 'ln ln-key') +
    line(x + 34, y + 13, x + 34, y + 17, 'ln ln-key'),
];

const PH = 114;

// A panel of width w at (0, 0): the icon, the name and the tag, a rule, then the three lines of its note.
function panel(t, i, w) {
  let s = rect(1.25, 1.25, w - 2.5, PH - 2.5, 'p-frame', 9);
  s += ICONS[i](10, 13);
  s += text(51, 25, t.name, 't t-b') + text(51, 43, t.tag, 't t-s t-dim');
  s += line(14, 55, w - 14, 55, 'ln ln-thin ln-dim');
  t.lines.forEach((l, k) => {
    s += text(14, 74 + k * 15, l, 't t-s t-long');
  });
  return s;
}

const BAR_NAME = 'A root';
const BAR_NOTE = 'Each has its own. Used rarely.';

const LABEL =
  'Four small panels and one bar. Each panel has a picture and a short note about how its thing ends at a root. ' +
  'A web page, with a padlock: your browser follows signatures to a root already on it. ' +
  'A signed tag: a signing subkey signed it, and the primary key binds the subkey. ' +
  'A release file with a signature: the signature is checked against a keyring or a published fingerprint. ' +
  'A server login: a CA key signs your login, and the host trusts that CA key from a list that a root signed. ' +
  'A line leads from each panel to one bar below them, in the accent colour, named A root. The bar says each of the four has its own root, and a root is used rarely.';

function wide() {
  const pw = 178;
  const gap = 16;
  const by = PH + 16; // top of the bar
  const bh = 32;
  let s = '';
  THINGS.forEach((t, i) => {
    s += at(i * (pw + gap), 0, panel(t, i, pw));
  });
  let bar = '';
  THINGS.forEach((t, i) => {
    const cx = i * (pw + gap) + pw / 2;
    bar += line(cx, PH - 1, cx, by, 'ln ln-acc');
  });
  bar += rect(1.2, by, 757.6, bh, 'acc-f cell-held', 8) + text(16, by + 20.5, BAR_NAME, 't t-b') + text(80, by + 20.5, BAR_NOTE, 't t-s t-long');
  s += acc(ACC, bar);
  return svgBox(760, by + bh + 2, LABEL, s, 'fig-wide');
}

function narrow() {
  const pw = 172;
  const gap = 16;
  const rowGap = 10;
  const spineX = pw + gap / 2;
  const by = 2 * PH + rowGap + 16;
  const bh = 32;
  let s = '';
  THINGS.forEach((t, i) => {
    s += at((i % 2) * (pw + gap), Math.floor(i / 2) * (PH + rowGap), panel(t, i, pw));
  });
  let bar = '';
  // a short stub from each panel to one line down the middle, and that line down to the bar
  [0, 1].forEach((r) => {
    const y = r * (PH + rowGap) + PH / 2;
    bar += line(pw - 1, y, spineX, y, 'ln ln-acc') + line(pw + gap + 1, y, spineX, y, 'ln ln-acc');
  });
  bar += line(spineX, PH / 2, spineX, by, 'ln ln-acc');
  bar += rect(1.2, by, 357.6, bh, 'acc-f cell-held', 8) + text(14, by + 20.5, BAR_NAME, 't t-b') + text(72, by + 20.5, BAR_NOTE, 't t-s t-long');
  s += acc(ACC, bar);
  return svgBox(360, by + bh + 2, LABEL, s, 'fig-narrow');
}

export default {
  id: 'everyday',
  kind: 'layout',
  label: 'Four things and the root each one ends at',
  caption: 'All four end at a root. If a root is lost or stolen, what is below it is at risk.',
  wide: wide(),
  narrow: narrow(),
};
