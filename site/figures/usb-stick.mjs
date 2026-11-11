// The USB stick of the offline system: vanilla AirgapOS, unchanged, and ONE extra partition whose
// layout ritueel defines. The partition holds ritueel's binaries (one directory per version, then per
// system and architecture), the bundles (each exactly as on your workstation) and the encrypted key
// files, beside the bundles and not inside them. The directory names are PROPOSED: the figure says so
// on the partition itself. That AirgapOS boots from such a stick and uses the partition is not yet
// proven on hardware, and a dotted badge says so. The accent marks the one thing the figure is about:
// the plan, which holds the digest of the copy of ritueel that made it. The wide and the narrow
// drawing are both made from the one table ROWS, so they cannot drift.
import { acc, arrow, circle, f, line, path, poly, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { lock } from './parts.mjs';

const LABEL =
  'A USB stick drawn as a box with a connector and a hole, in two parts: a part for AirgapOS, vanilla and unchanged, and one extra partition marked Proposed. ' +
  'The partition shows a tree of three directories: ritueel with one directory per version and per system, bundles with acme and personal, and keys with one encrypted key file beside the bundles. ' +
  'In the accent colour, an arrow runs from a plan inside acme to the ritueel binary of the version that made it. ' +
  'A dotted badge with a question mark says that booting AirgapOS from such a stick is still to be proven on hardware.';

// The tree, top to bottom. d is the depth, k the kind of entry, g the group a head row opens.
const ROWS = [
  { d: 0, k: 'dir', n: 'ritueel/', g: 'bin' },
  { d: 1, k: 'dir', n: '0.1.0/' },
  { d: 2, k: 'bin', n: 'linux-amd64/ritueel' },
  { d: 2, k: 'file', n: 'linux-arm64/ritueel' },
  { d: 1, k: 'dir', n: '0.2.0/ …' },
  { d: 0, k: 'dir', n: 'bundles/', g: 'bun' },
  { d: 1, k: 'dir', n: 'acme/' },
  { d: 2, k: 'more', n: 'ritueel.yaml, roots/, …' },
  { d: 2, k: 'plan', n: 'a plan' },
  { d: 1, k: 'dir', n: 'personal/' },
  { d: 0, k: 'dir', n: 'keys/', g: 'key' },
  { d: 1, k: 'dir', n: 'personal/' },
  { d: 2, k: 'key', n: 'A.openpgp.key.age' },
];

// The margin notes of the groups: wide lines (beside the stick) and narrow lines (under the head row).
const NOTES = {
  bin: {
    wide: ['binaries: several versions,', 'several architectures.', 'The run uses the version', 'that made the plan.'],
    narrow: ['binaries: several versions and', 'architectures. The run uses the', 'version that made the plan.'],
  },
  bun: { wide: ['several bundles, each', 'as on your workstation'], narrow: ['several bundles, each as on', 'your workstation'] },
  key: { wide: ['encrypted key files,', 'beside the bundles'], narrow: ['encrypted key files,', 'beside the bundles'] },
};

const R = 24; // row height
const IND = { wide: 20, narrow: 17 };

/** A small directory icon (18 wide), (x,y) its top left. */
const dirIcon = (x, y) => path(`M${f(x)} ${f(y)} H${f(x + 7)} L${f(x + 9.5)} ${f(y + 3)} H${f(x + 18)} V${f(y + 13)} H${f(x)} Z`, 'paper');

/** The icon of a row, (x,y) its top left; returns the markup. */
function icon(r, x, y) {
  if (r.k === 'dir') return dirIcon(x, y);
  if (r.k === 'plan') return sheet(x + 2, y - 3, 13, 18, { accent: true, rows: 0 });
  if (r.k === 'more') return '';
  return sheet(x + 2, y - 3, 13, 18, { rows: 0 });
}

/**
 * Lays the tree out from (bx,by): returns the placed rows {r, y, x (the name), tx (the icon)} and the
 * y below the last one. In the narrow drawing the note of a group follows its head row.
 */
function place(mode, bx, by) {
  const out = [];
  let y = by;
  for (const r of ROWS) {
    const tx = bx + r.d * IND[mode];
    out.push({ r, y, tx, x: tx + 24 });
    y += R;
    if (mode === 'narrow' && r.g) y += NOTES[r.g].narrow.length * 15 + 3;
  }
  return { out, end: y };
}

/** The text and icon of every row, and the trunks that join a row to its parent. */
function tree(placed, mode) {
  let s = '';
  placed.forEach((p, i) => {
    const { r } = p;
    if (r.d > 0) {
      const par = [...placed.slice(0, i)].reverse().find((q) => q.r.d === r.d - 1);
      const tx = par.tx + 8;
      s += line(tx, par.y + 18, tx, p.y + 9, 'ln ln-thin ln-dim') + line(tx, p.y + 9, p.tx - 2, p.y + 9, 'ln ln-thin ln-dim');
    }
    const body =
      icon(r, p.tx, p.y + 2) +
      (r.k === 'key' ? lock(p.tx + 3, p.y + 1) : '') +
      text(p.x, p.y + 13.5, r.n, 't t-mono' + (r.d === 0 ? ' t-b' : '') + (r.k === 'more' ? ' t-dim' : '') + (r.k === 'plan' ? ' t-acc t-b' : ''));
    s += r.k === 'plan' ? acc('plan', body) : body;
    if (mode === 'narrow' && r.g) {
      NOTES[r.g].narrow.forEach((l, j) => {
        s += text(p.x, p.y + R + 10 + j * 15, l, 't t-s t-long');
      });
    }
  });
  return s;
}

/** The accent arrow from the plan to the binary of the version that made it: an elbow, then the labelled head. */
function planArrow(placed, mode, xv) {
  const plan = placed.find((p) => p.r.k === 'plan');
  const bin = placed.find((p) => p.r.k === 'bin');
  const startX = plan.x + 52;
  const tipX = bin.x + 19 * 7.3 + 14;
  const yp = plan.y + 9;
  const yb = bin.y + 9;
  return (
    acc('plan', poly([[startX, yp], [xv, yp], [xv, yb]], 'ln ln-acc')) +
    arrow(xv, yb, tipX, yb, 'digest', { accent: 'plan', lx: (xv + tipX) / 2, ly: yb - 6 })
  );
}

/** The line that explains the arrow, with a swatch of the plan. */
const note = (x, y) => acc('plan', sheet(x, y - 14, 12, 16, { accent: true, rows: 0 })) + text(x + 20, y, 'The plan holds the digest of this copy.', 't t-s t-long t-acc');

/** The badge of what is not yet proven. */
function badge(x, y, w, lines) {
  const h = 20 + lines.length * 16;
  let s = rect(x, y, w, h, 'cell-free', 10) + circle(x + 24, y + h / 2, 11, 'paper');
  s += text(x + 24, y + h / 2 + 4.5, "?", "t t-b", "m");
  lines.forEach((l, i) => {
    s += text(x + 46, y + 22 + i * 16, l, 't t-s t-long' + (i === 0 ? ' t-b' : ''));
  });
  return { s, h };
}

/** The pill "Proposed" and the header of the partition. */
function head(x, y, w) {
  return (
    text(x + 14, y + 23, 'Extra partition', 't t-b') +
    rect(x + w - 82, y + 8, 68, 22, 'paper', 11) +
    text(x + w - 48, y + 23, 'Proposed', 't t-s t-b', 'm') +
    text(x + 14, y + 42, 'ritueel’s layout, one partition', 't t-s t-long')
  );
}

function wide() {
  const W = 760;
  const px = 158;
  const pw = 336;
  const py = 46;
  const placed = place('wide', px + 16, py + 62);
  let s = text(22, 22, 'The USB stick', 't t-b');
  // the stick: connector, body, AirgapOS part, partition, hole
  const bodyY = py - 8;
  const bodyH = placed.end + 52 - bodyY + 6;
  s += rect(14, bodyY + bodyH / 2 - 17, 26, 34, 'paper-t', 3) + rect(20, bodyY + bodyH / 2 - 8, 5, 5, 'fill-ink', 1) + rect(20, bodyY + bodyH / 2 + 4, 5, 5, 'fill-ink', 1);
  s += rect(38, bodyY, 480, bodyH, 'paper', 14);
  s += rect(48, py, 100, bodyH - 20, 'paper-t', 8);
  s += text(98, py + 34, 'AirgapOS', 't t-b', 'm') + text(98, py + 54, 'vanilla,', 't t-s', 'm') + text(98, py + 70, 'unchanged', 't t-s', 'm');
  s += rect(px, py, pw, bodyH - 20, 'paper-t', 8) + head(px, py, pw);
  s += circle(506, bodyY + bodyH / 2, 4.5, 'paper');
  s += tree(placed.out, 'wide');
  s += planArrow(placed.out, 'wide', px + pw - 28);
  s += note(px + 14, placed.end + 22);
  // the margin notes: a rule that spans the group, the note at its top
  const gs = {};
  placed.out.forEach((p) => {
    if (p.r.g) gs[p.r.g] = { top: p.y, bottom: p.y + R };
    const g = [...placed.out.slice(0, placed.out.indexOf(p) + 1)].reverse().find((q) => q.r.g);
    if (g) gs[g.r.g].bottom = p.y + R;
  });
  for (const [g, b] of Object.entries(gs)) {
    s += line(534, b.top + 3, 534, b.bottom - 4, 'ln');
    NOTES[g].wide.forEach((l, i) => {
      s += text(546, b.top + 15 + i * 16, l, 't t-s t-long');
    });
  }
  const by = bodyY + bodyH + 14;
  const b = badge(38, by, 480, ['To be proven on hardware:', 'AirgapOS boots from such a stick and uses the partition.']);
  s += b.s;
  const H = by + b.h + 14;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const px = 24;
  const pw = 312;
  const sy = 34;
  const py = sy + 46 + 8;
  const placed = place('narrow', px + 14, py + 58);
  let s = text(16, 24, 'The USB stick', 't t-b');
  s += rect(W / 2 - 18, 28, 36, 8, 'paper-t', 2) + rect(W / 2 - 8, 29, 5, 5, 'fill-ink', 1) + rect(W / 2 + 3, 29, 5, 5, 'fill-ink', 1);
  const bodyY = sy;
  const bodyH = placed.end + 36 - bodyY + 6;
  s += rect(14, bodyY, 332, bodyH, 'paper', 14);
  s += rect(px, sy + 8, pw, 38, 'paper-t', 8) + text(px + 14, sy + 32, 'AirgapOS', 't t-b') + text(px + 100, sy + 32, 'vanilla, unchanged', 't t-s');
  s += circle(318, sy + 27, 4.5, 'paper');
  s += rect(px, py, pw, bodyH - (py - bodyY) - 8, 'paper-t', 8) + head(px, py, pw);
  s += tree(placed.out, 'narrow');
  s += planArrow(placed.out, 'narrow', px + pw - 14);
  s += note(px + 14, placed.end + 14);
  const by = bodyY + bodyH + 14;
  const b = badge(14, by, 332, ['To be proven on hardware:', 'AirgapOS boots from such a stick', 'and uses the partition.']);
  s += b.s;
  const H = by + b.h + 14;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-narrow');
}

export default {
  id: 'usb-stick',
  kind: 'layout',
  label: 'The USB stick: AirgapOS and one extra partition for ritueel',
  caption:
    'The stick holds vanilla AirgapOS and one extra partition. Key files sit beside the bundles, not inside: a bundle is made to be copied and shared; a key file is the root itself, even though it is encrypted.',
  wide: wide(),
  narrow: narrow(),
};
