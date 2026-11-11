// What a bundle holds: one directory of plain files for one trust domain, drawn as a tree of labelled
// parts, one entry to a line, with a small tag saying who writes it ("you", "ritueel", or both).
// A name of a directory or a file is printed only where it is settled (ritueel.yaml, cards/, roots/A
// and roots/B, requests/). The history of ceremonies and the trust files have plain labels and no
// name, because the names are being changed. The accent marks the history, which is never changed afterwards. Key
// files are not in the bundle: a dashed box outside it says so, and the stick figure shows where they sit.
import { acc, circle, f, line, path, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';

const LABEL =
  'A bundle drawn as an open directory named acme, holding six labelled parts in a tree: the file ritueel.yaml, the directories cards and roots, ' +
  'the requests directory with its answers beside them, the history of ceremonies in the accent colour, and the trust files. A small tag on each part says who writes it. ' +
  'Under the bundle sits a second, closed bundle named personal, and a dashed box that says key files stay outside the bundle.';

const W = 376;

/** A small directory icon, (x,y) its top left, 22 wide. */
const dir = (x, y, cls = 'paper') =>
  path(`M${f(x)} ${f(y)} H${f(x + 8)} L${f(x + 11)} ${f(y + 3.5)} H${f(x + 22)} V${f(y + 16)} H${f(x)} Z`, cls);

/** The tag at the right of a name: who writes the part. */
function tag(y, word, inset = 0) {
  const w = word === 'you' ? 42 : word === 'ritueel' ? 60 : 84;
  const x = W - 22 - inset - w;
  return rect(x, y, w, 19, 'paper-t', 9.5) + text(x + w / 2, y + 13.5, word, 't t-s' + (word === 'you' ? ' t-b' : ''), 'm');
}

// The parts of a bundle, top to bottom. `name` is printed in mono only where it is settled.
const PARTS = [
  { icon: 'sheet', name: 'ritueel.yaml', mono: true, tag: 'you', desc: ['the one file you write'] },
  { icon: 'dir', name: 'cards/', mono: true, tag: 'ritueel', desc: ['each card’s map and this bundle’s', 'own sealed copy of its secrets'] },
  { icon: 'dir', name: 'roots/A, roots/B', mono: true, tag: 'ritueel', desc: ['the public facts of each root'] },
  { icon: 'dir', name: 'requests/', mono: true, tag: 'you, ritueel', desc: ['each request, with its answer beside it'] },
  { icon: 'dir', name: 'History of ceremonies', accent: true, tag: 'ritueel', desc: ['one directory per ceremony: plan,', 'attempt, record, transcript', 'Never changed; each links to the one before.'] },
  { icon: 'sheet', name: 'Trust files', tag: 'ritueel', desc: ['one numbered set each time they change;', 'the CA bundle is one of them'] },
];

const rowH = (p) => 24 + p.desc.length * 16 + 8 + (p.accent ? 12 : 0);

function drawing() {
  const x0 = 14;
  const top = 46;
  let y = top + 12;
  // title
  let s = '';
  const rows = [];
  for (const p of PARTS) {
    if (p.accent) y += 6;
    rows.push({ p, y });
    y += rowH(p);
  }
  const bottom = y + 2;
  s += dir(x0 + 4, 12) + text(x0 + 34, 26, 'acme/', 't t-b t-mono') + text(x0 + 88, 26, 'one bundle, one trust domain', 't t-s t-long');
  s += rect(x0, top, W - 2 * x0, bottom - top, 'paper', 8);
  const trunk = x0 + 18;
  s += line(trunk, top + 2, trunk, rows[rows.length - 1].y + 12, 'ln ln-thin ln-dim');
  for (const { p, y: ry } of rows) {
    const nx = x0 + 68;
    s += line(trunk, ry + 12, trunk + 12, ry + 12, 'ln ln-thin ln-dim');
    const body =
      (p.accent ? rect(x0 + 8, ry - 6, W - 2 * x0 - 16, rowH(p) - 2, 'acc-f', 7) : '') +
      (p.icon === 'sheet' ? sheet(trunk + 16, ry + 1, 17, 22, { rows: 0, accent: !!p.accent }) : dir(trunk + 14, ry + 5, p.accent ? 'acc-f' : 'paper')) +
      text(nx, ry + 15, p.name, 't t-b' + (p.mono ? ' t-mono' : '') + (p.accent ? ' t-acc' : '')) +
      tag(ry + 2, p.tag, p.accent ? 10 : 0) +
      p.desc.map((d, i) => text(nx, ry + 34 + i * 16, d, 't t-s t-long' + (p.accent ? ' t-acc' : ''))).join('');
    s += p.accent ? acc('history', body) : body;
  }
  // a second bundle, closed
  const y2 = bottom + 18;
  s += dir(x0 + 4, y2, 'paper') + text(x0 + 34, y2 + 13, 'personal/', 't t-b t-mono') + text(x0 + 114, y2 + 13, 'another trust domain, another bundle', 't t-s t-long');
  // key files: outside
  const y3 = y2 + 40;
  s += rect(x0, y3, W - 2 * x0, 56, 'cell-empty', 8);
  s += rect(x0 + 14, y3 + 22, 12, 9, 'paper-t', 2) + path(`M${f(x0 + 16.5)} ${f(y3 + 22)} V${f(y3 + 19.5)} A3.5 3.5 0 0 1 ${f(x0 + 23.5)} ${f(y3 + 19.5)} V${f(y3 + 22)}`, 'ln ln-thin');
  s += text(x0 + 38, y3 + 22, 'Key files stay outside the bundle', 't t-b t-long') + text(x0 + 38, y3 + 41, 'They sit beside it on the stick, below.', 't t-s t-long');
  const H = y3 + 56 + 14;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-small');
}

export default {
  id: 'bundle-folder',
  kind: 'single',
  label: 'The parts of a bundle and who writes them',
  caption:
    'A bundle is one directory of plain files for one trust domain. You write two places and ritueel writes the rest. The history of ceremonies is never changed afterwards. Key files are never inside.',
  svg: drawing(),
};
