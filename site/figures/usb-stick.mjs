// The USB stick of the offline system: vanilla AirgapOS, unchanged, and ONE extended partition that
// holds two parts (record 0005, rules 29 and 36). The trace area comes first: a small partition with no
// file system, which only ritueel writes, one trace record in each sector, written once; while a ceremony
// runs it holds the attempt and the journals. The files partition is exFAT and holds ritueel's binaries
// (one directory per version, then per system and architecture), the bundles (without their wanted files:
// record 0005, rule 30) and the encrypted key files, beside the bundles and not inside them. When the
// ceremony ends ritueel makes the three files from the trace area into the bundle (record 0005, rule 39): one arrow.
// The way back is a join (record 0005, rule 28): an arrow from the bundles to the workstation says it adds
// the missing files. The directory names are PROPOSED: the figure says so on the files partition. What is
// not yet proven on real hardware (the boot, the layout on desktop systems, a trace record after a cut) is
// said by a dotted badge. The accent marks the one thing the figure is about: the plan, which holds the
// digest of the copy of ritueel that made it. No size, spacing or distance of the trace area is drawn: the
// records list them as starting values. The wide and the narrow drawing are both made from the one table
// ROWS, so they cannot drift.
import { acc, arrow, circle, f, laptop, line, path, poly, rect, sheet, text } from './draw.mjs';
import { svgBox } from './svg.mjs';
import { lock } from './parts.mjs';

const LABEL =
  'A USB stick drawn as a box with a connector, in two parts: a part for AirgapOS, vanilla and unchanged, and one extended partition. ' +
  'The extended partition holds two parts side by side. The first is the trace area, a small partition with no file system. It shows a short strip of single sectors, three written and two free, and says it holds the attempt and the journals, one record in each sector, written once. ' +
  'The second is the files partition, marked Proposed for its directory names. It shows a tree of three directories. The first is ritueel, with one directory for each version and each system. The second is bundles, with acme and personal. They hold roots and requests and no wanted files. The third is keys, with one encrypted key file beside the bundles. ' +
  'In the accent colour, an arrow runs from a plan inside acme to the ritueel binary of the version that made it. Dashed leader lines join the notes at the right to the three directories. ' +
  'An arrow runs from the trace area to the bundles directory and says that three files are made at the end. ' +
  'An arrow runs back from the bundles to a laptop named workstation and says it adds missing files. ' +
  'A dotted badge with a question mark says that booting AirgapOS from such a stick, the layout on desktop systems and a trace record surviving a cut are not yet proven on real hardware.';

// The tree, top to bottom. d is the depth, k the kind of entry, g the group a head row opens.
const ROWS = [
  { d: 0, k: 'dir', n: 'ritueel/', g: 'bin' },
  { d: 1, k: 'dir', n: '0.1.0/' },
  { d: 2, k: 'bin', n: 'linux-amd64/ritueel' },
  { d: 2, k: 'file', n: 'linux-arm64/ritueel' },
  { d: 1, k: 'dir', n: '0.2.0/ …' },
  { d: 0, k: 'dir', n: 'bundles/', g: 'bun' },
  { d: 1, k: 'dir', n: 'acme/' },
  { d: 2, k: 'more', n: 'roots/, requests/, …' },
  { d: 2, k: 'plan', n: 'a plan' },
  { d: 1, k: 'dir', n: 'personal/' },
  { d: 0, k: 'dir', n: 'keys/', g: 'key' },
  { d: 1, k: 'dir', n: 'personal/' },
  { d: 2, k: 'key', n: 'A.openpgp.key.age' },
];

// The margin notes of the groups: wide lines (beside the stick) and narrow lines (under the head row).
const NOTES = {
  bin: {
    wide: ['binaries: several', 'versions and', 'architectures. The run', 'uses the version', 'that made the plan.'],
    narrow: ['binaries: several versions and', 'architectures. The run uses the', 'version that made the plan.'],
  },
  bun: {
    wide: ['bundles without their', 'wanted files. A plan', 'carries copies of the', 'wanted files it used.'],
    narrow: ['bundles without their wanted', 'files. A plan carries copies of', 'the wanted files it used.'],
  },
  key: { wide: ['encrypted keys,', 'beside the bundles'], narrow: ['encrypted key files,', 'beside the bundles'] },
};

const RH = { wide: 23, narrow: 24 }; // row height
const IND = { wide: 18, narrow: 17 };

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
    y += RH[mode];
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
        s += text(p.x, p.y + RH[mode] + 10 + j * 15, l, 't t-s t-long');
      });
    }
  });
  return s;
}

/** The accent arrow from the plan to the binary of the version that made it: an elbow, then the labelled head. */
function planArrow(placed, xv) {
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

/** The badge of what is not yet proven; the first line is its title. */
function badge(x, y, w, lines) {
  const h = 20 + lines.length * 16;
  let s = rect(x, y, w, h, 'cell-free', 10) + circle(x + 24, y + h / 2, 11, 'paper');
  s += text(x + 24, y + h / 2 + 4.5, "?", "t t-b", "m");
  lines.forEach((l, i) => {
    s += text(x + 46, y + 22 + i * 16, l, 't t-s t-long' + (i === 0 ? ' t-b' : ''));
  });
  return { s, h };
}

/** The pill "Proposed" and the title of the files partition. */
function filesHead(x, y, w) {
  return text(x + 14, y + 21, 'Files partition', 't t-b') + rect(x + w - 82, y + 6, 68, 22, 'paper', 11) + text(x + w - 48, y + 21, 'Proposed', 't t-s t-b', 'm');
}

/** A strip of single sectors: n squares from (x,y), the first `written` of them drawn, the rest free. */
function sectors(x, y, n, written, size, pitch) {
  let s = '';
  for (let i = 0; i < n; i++) s += rect(x + i * pitch, y, size, size, i < written ? 'paper' : 'paper-g', 2);
  return s;
}

function wide() {
  const W = 760;
  const py = 46; // top of the extended partition
  const tx = 140; // the trace area
  const tw = 116;
  const fx = 264; // the files partition
  const fw = 296;
  const placed = place('wide', fx + 16, py + 62);
  const o = placed.out;
  const end = placed.end;
  const filesBottom = end + 30;
  const extBottom = filesBottom + 8;
  const bodyY = py - 8;
  const bodyBottom = extBottom + 10;
  const bodyH = bodyBottom - bodyY;
  const ruleX = 590;
  let s = text(22, 22, 'The USB stick', 't t-b');
  // the stick: connector, body, AirgapOS part, extended partition, its two parts
  s += rect(14, bodyY + bodyH / 2 - 17, 26, 34, 'paper-t', 3) + rect(20, bodyY + bodyH / 2 - 8, 5, 5, 'fill-ink', 1) + rect(20, bodyY + bodyH / 2 + 4, 5, 5, 'fill-ink', 1);
  s += rect(38, bodyY, 540, bodyH, 'paper', 14);
  s += rect(48, py, 76, extBottom - py, 'paper-t', 8);
  s += text(86, py + 34, 'AirgapOS', 't t-b', 'm') + text(86, py + 54, 'vanilla,', 't t-s', 'm') + text(86, py + 70, 'unchanged', 't t-s', 'm');
  s += rect(132, py, 436, extBottom - py, 'paper-t', 8) + text(146, py + 19, 'Extended partition', 't t-b');
  // the trace area: a small partition, shorter than the files partition
  const ty = py + 28;
  const bun = o.find((p) => p.r.n === 'bundles/');
  const yb = bun.y + 9; // the row the arrow ends at
  s += rect(tx, ty, tw, yb + 38 - ty, 'paper', 8);
  s += text(tx + 12, ty + 21, 'Trace area', 't t-b') + text(tx + 12, ty + 37, 'no file system', 't t-s');
  s += sectors(tx + 12, ty + 48, 5, 3, 12, 18);
  ['holds the attempt', 'and journals: one', 'record per sector,', 'written once'].forEach((l, i) => {
    s += text(tx + 12, ty + 78 + i * 16, l, 't t-s t-long');
  });
  // the files partition
  s += rect(fx, ty, fw, filesBottom - ty, 'paper', 8) + filesHead(fx, ty, fw);
  s += tree(o, 'wide');
  s += planArrow(o, fx + fw - 26);
  s += note(fx + 14, end + 20);
  // the arrow from the trace area to the bundles: three files are made at the end
  s += arrow(tx + 8, yb, bun.tx - 3, yb, 'three files', { lx: tx + 62, ly: yb - 6 }) + text(tx + 62, yb + 17, 'at the end', 't t-s', 'm');
  // the margin notes: a rule that spans the group, the note at its top
  const gs = {};
  o.forEach((p) => {
    if (p.r.g) gs[p.r.g] = { top: p.y, bottom: p.y + RH.wide };
    const g = [...o.slice(0, o.indexOf(p) + 1)].reverse().find((q) => q.r.g);
    if (g) gs[g.r.g].bottom = p.y + RH.wide;
  });
  for (const [g, b] of Object.entries(gs)) {
    // a leader from the end of the directory's name to the rule of its note
    const head = o.find((p) => p.r.g === g);
    s += line(head.x + head.r.n.length * 7.6 + 8, head.y + 9, ruleX, head.y + 9, 'ln ln-thin ln-dim ln-dash');
    s += line(ruleX, b.top + 3, ruleX, b.bottom - 4, 'ln');
    NOTES[g].wide.forEach((l, i) => {
      s += text(ruleX + 12, b.top + 15 + i * 16, l, 't t-s t-long');
    });
  }
  const by = bodyBottom + 14;
  const b = badge(38, by, 540, [
    'Not yet proven:',
    'AirgapOS boots from such a stick and mounts the files partition;',
    'desktop systems accept the layout; a trace record survives a cut.',
  ]);
  s += b.s;
  const H = by + b.h + 12; // not taller than the drawing it replaces (558)
  // the way back: a join adds the files the stick's bundles lack to the workstation's bundle
  const wx = 716;
  const y1 = gs.bun.top + 80;
  s += poly([[ruleX, y1], [wx, y1], [wx, y1 + 40]], 'ln') + arrow(wx, y1 + 40, wx, by + 4, 'adds missing files', { lx: wx - 58, ly: y1 + 140 });
  s += laptop(wx - 32, by + 4, 64, 30) + text(wx, by + 54, 'workstation', 't t-s', 'm');
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-wide');
}

function narrow() {
  const W = 360;
  const sy = 34;
  const py = sy + 54; // top of the extended partition
  const placedAt = (fy) => place('narrow', 32 + 38, fy + 34);
  // the trace area: x 32, 296 wide, 90 high; the gap below it holds the two words of the arrow
  const ty = py + 28;
  const th = 90;
  const fy = ty + th + 40;
  const placed = placedAt(fy);
  const o = placed.out;
  const end = placed.end;
  const filesBottom = end + 28;
  const extBottom = filesBottom + 8;
  const bodyBottom = extBottom + 10;
  const bodyH = bodyBottom - sy;
  let s = text(16, 24, 'The USB stick', 't t-b');
  s += rect(W / 2 - 18, 28, 36, 8, 'paper-t', 2) + rect(W / 2 - 8, 29, 5, 5, 'fill-ink', 1) + rect(W / 2 + 3, 29, 5, 5, 'fill-ink', 1);
  s += rect(14, sy, 332, bodyH, 'paper', 14);
  s += rect(24, sy + 8, 312, 38, 'paper-t', 8) + text(38, sy + 32, 'AirgapOS', 't t-b') + text(124, sy + 32, 'vanilla, unchanged', 't t-s');
  s += circle(318, sy + 27, 4.5, 'paper');
  s += rect(24, py, 312, extBottom - py, 'paper-t', 8) + text(38, py + 19, 'Extended partition', 't t-b');
  // the trace area
  s += rect(32, ty, 296, th, 'paper', 8);
  s += text(44, ty + 21, 'Trace area', 't t-b') + text(132, ty + 21, 'no file system', 't t-s');
  s += sectors(44, ty + 32, 8, 5, 12, 18);
  s += text(44, ty + 64, 'holds the attempt and journals:', 't t-s t-long') + text(44, ty + 79, 'one record per sector, written once.', 't t-s t-long');
  // the files partition
  s += rect(32, fy, 296, filesBottom - fy, 'paper', 8) + filesHead(32, fy, 296);
  s += tree(o, 'narrow');
  s += planArrow(o, 32 + 296 - 12);
  s += note(46, end + 14);
  // the arrow from the trace area, down the left side, to the bundles directory
  const bun = o.find((p) => p.r.n === 'bundles/');
  const yb = bun.y + 9;
  const x0 = 46;
  s += poly([[x0, ty + th], [x0, yb]], 'ln') + arrow(x0, yb, bun.tx - 3, yb, 'three files', { lx: x0 + 38, ly: ty + th + 17 }) + text(x0 + 8, ty + th + 33, 'at the end', 't t-s');
  // the way back: a join adds the files the stick's bundles lack to the workstation's bundle
  const wx = 300;
  const back = o.find((p) => p.r.n === 'personal/' && p.r.d === 1);
  const by0 = back.y + 9;
  s += poly([[back.x + 9 * 7.6 + 10, by0], [wx, by0], [wx, bodyBottom - 6]], 'ln');
  s += arrow(wx, bodyBottom - 6, wx, bodyBottom + 44, 'adds missing files', { lx: wx - 30, ly: bodyBottom + 24 });
  s += laptop(wx - 28, bodyBottom + 46, 56, 26) + text(wx - 40, bodyBottom + 62, 'workstation', 't t-s', 'e');
  const by = bodyBottom + 96;
  const b = badge(14, by, 332, [
    'Not yet proven:',
    'AirgapOS boots from such a stick',
    'and mounts the files partition;',
    'desktop systems accept the layout;',
    'a trace record survives a cut.',
  ]);
  s += b.s;
  const H = by + b.h + 14;
  return svgBox(W, H, LABEL, rect(2, 2, W - 4, H - 4, 'p-frame', 10) + s, 'fig-narrow');
}

export default {
  id: 'usb-stick',
  kind: 'layout',
  label: 'The USB stick: AirgapOS, then one extended partition with the trace area and the files partition',
  caption:
    'Key files sit beside the bundles, not inside: a key file is the root itself, even though it is encrypted. The way back is a join: it adds the files the bundle lacks.',
  wide: wide(),
  narrow: narrow(),
};
