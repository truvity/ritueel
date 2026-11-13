// Shared by tools/checks/record-refs.mjs and tools/records-renumber.mjs: how a citation of a rule
// of a decision record is found in a file and bound to a record. No dependency beyond Node.
//
// A citation is a clause such as `rule 5`, `rules 12 and 29`, `rules 5 to 9`, `rules 3, 4 and 7`.
// It names its record in one of these ways, tried in this order:
//   1. the record number stands directly before it: `record 0004, rule 2`, `[record 0006](…), rule 1`,
//      `0006 rules 12 and 29`, `record 0005 (rules 17 and 18)`, `records 0002 (rule 24) and 0003 (rule 3)`;
//   2. the record follows it: `rule 28 of [0007](…)`, `rules 7, 8 and 12 of record 0010`;
//   3. it is the next clause of a run: `record 0003, rule 16 and rule 14` (the second clause);
//   4. the file is the record itself: `(rule 33)` inside docs/decisions/0005-….md;
//   5. the page declares one default: the sentence "Rule numbers without a record name are those of
//      record NNNN." anywhere in the file.
// A clause directly after `proto/README.md,` cites the numbered rules of that file, not a record.
// Anything else cannot be resolved and is an error: no guess from a record named farther back.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const RECORD_FILE = /^docs\/decisions\/(00(?:0[1-9]|[1-9]\d))-[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;
export const DEFAULT_SENTENCE = /Rule numbers without a record name are those of record (00\d\d)\./;

const CLAUSE = /\b([Rr]ules?)(\s+)(\d{1,2}(?!\d)(?:(?:,\s*|\s+and\s+|,\s+and\s+|\s+to\s+|–|-)\d{1,2}(?!\d))*)/g;
const BEFORE = /(\bADRs?\s+)?(?:\brecords?\s+)?\[?(?:\brecords?\s+)?(00\d\d)\]?(?:\([^)]*\))?\s*[,;:]?\s*\(?\s*$/i;
const AFTER = /^\)?,?\s+(?:of|in)\s+(?:the\s+)?\[?(?:records?\s+)?\[?(00\d\d)/i;
const RUN = /^\s*(?:,\s*and|,|;|and)\s+$/;
const FOREIGN = /\bproto\/README\.md,?\s*$/;

const CODE = /\.(proto|ts|tsx|mjs|js)$/;

// The text of a file with a map from a character to its line and column. A block of comment lines
// in a source file is joined into one paragraph, so that a citation which a comment wraps can be read.
export function flatten(path, text) {
  const lines = text.split('\n');
  const starts = []; // [offset in flat, line, columns cut off the front of the line]
  if (!CODE.test(path)) {
    let at = 0;
    lines.forEach((l, k) => { starts.push([at, k + 1, 0]); at += l.length + 1; });
    return { flat: text, pos: at0(starts) };
  }
  let flat = '';
  let inBlock = false;
  lines.forEach((l, k) => {
    const m = /^\s*(?:\/\/+|\/\*+!?|\*(?!\/))\s?(.*?)(?:\s*\*\/)?\s*$/d.exec(l);
    if (m) {
      if (inBlock) flat += ' ';
      starts.push([flat.length, k + 1, m.indices[1][0]]);
      flat += m[1];
      inBlock = true;
    } else {
      if (inBlock) flat += '\n\n';
      inBlock = false;
      starts.push([flat.length, k + 1, 0]);
      flat += l + '\n';
    }
  });
  return { flat, pos: at0(starts) };
}
// pos(i) is { line, col }: the 1-based line of the file and the 0-based column of flat[i] in it.
function at0(starts) {
  return (i) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid][0] <= i) lo = mid; else hi = mid - 1;
    }
    return { line: starts[lo][1], col: i - starts[lo][0] + starts[lo][2] };
  };
}

// The numbers a clause lists, ranges expanded. `bad` is set for a range that runs backwards.
export function numbersOf(list) {
  const parts = list.split(/(,\s*and\s+|\s+and\s+|,\s*|\s+to\s+|–|-)/).filter((x) => x !== '');
  const nums = [];
  let range = false;
  let bad = false;
  for (const p of parts) {
    if (/^\d+$/.test(p)) {
      const n = Number(p);
      if (range) {
        const a = nums[nums.length - 1];
        if (n <= a) bad = true;
        else for (let x = a + 1; x <= n; x++) nums.push(x);
        range = false;
      } else nums.push(n);
    } else if (/^(\s+to\s+|–|-)$/.test(p)) range = true;
  }
  return { nums, bad };
}

// Every clause of a file, with how its record was found: how is one of
// 'before', 'after', 'run', 'own', 'default', 'foreign', 'none'; 'oldAdr' for `ADR 0007 rule 3`.
// `list` is the text of the numbers; `listAt` and `clauseAt` are flat offsets; `rec` is the span of
// the four digits of the record number in the text (for 'before', 'after' and 'run').
export function citationsIn(path, text) {
  const { flat, pos } = flatten(path, text);
  const own = RECORD_FILE.exec(path)?.[1] ?? null;
  const def = DEFAULT_SENTENCE.exec(text)?.[1] ?? null;
  const code = CODE.test(path);
  const out = [];
  let prev = null;
  for (const m of flat.matchAll(CLAUSE)) {
    const start = m.index;
    const end = start + m[0].length;
    const para = flat.lastIndexOf('\n\n', start);
    const lineStart = flat.lastIndexOf('\n', start);
    // In Markdown a table row stands alone; any other text may wrap onto the next line.
    const row = flat[lineStart + 1] === '|';
    const from = Math.max(para < 0 ? 0 : para + 2, row || code ? lineStart + 1 : 0, start - 160);
    const before = flat.slice(from, start);
    const after = flat.slice(end, end + 80);
    let record = null;
    let how = 'none';
    let rec = null;
    let b;
    if (FOREIGN.test(before)) how = 'foreign';
    else if ((b = BEFORE.exec(before))) {
      record = b[2];
      how = b[1] ? 'oldAdr' : 'before';
      const at = from + b.index + b[0].indexOf(b[2], (b[1] ?? '').length);
      rec = { start: at, end: at + 4 };
    } else if ((b = AFTER.exec(after))) {
      record = b[1];
      how = 'after';
      const at = end + b[0].lastIndexOf(b[1]);
      rec = { start: at, end: at + 4 };
    } else if (prev && prev.record && prev.how !== 'foreign' && prev.how !== 'none' && RUN.test(flat.slice(prev.end, start))) {
      record = prev.record;
      how = 'run';
      rec = prev.rec;
    } else if (own) { record = own; how = 'own'; }
    else if (def) { record = def; how = 'default'; }
    const { nums, bad } = numbersOf(m[3]);
    const listAt = start + m[1].length + m[2].length;
    const where = pos(start);
    const c = {
      start, end, listAt, line: where.line, col: where.col, text: m[0], word: m[1], list: m[3], nums, bad, record, how, rec,
      // The clause, and for 'before' and 'after' the record number, must each be on one line of a source file.
      split: code && (pos(end - 1).line !== where.line || (rec && how !== 'run' && pos(rec.start).line !== where.line)),
    };
    out.push(c);
    prev = c;
  }
  return { citations: out, pos, flat };
}

// The rule count of each record: the highest number in its "Decision" list.
export function readRecords(root, files) {
  const records = new Map();
  for (const f of files) {
    const m = RECORD_FILE.exec(f);
    if (!m) continue;
    const text = readFileSync(join(root, f), 'utf8');
    const at = text.search(/^## Decision\s*$/m);
    let n = 0;
    if (at >= 0) {
      const rest = text.slice(at).split('\n').slice(1);
      for (const l of rest) {
        if (/^## /.test(l)) break;
        const d = /^(\d+)\. \S/.exec(l);
        if (d) n = Math.max(n, Number(d[1]));
      }
    }
    records.set(m[1], { file: f, rules: n });
  }
  return records;
}

// The files a citation can be in: Markdown anywhere except the copied skills, and the source files
// of proto/, ui/src (not the generated code) and site/figures.
export function scanned(f) {
  if (f.startsWith('.claude/skills/') || f.includes('node_modules/')) return false;
  if (/\.mdx?$/.test(f)) return true;
  if (/\.(proto)$/.test(f) && f.startsWith('proto/')) return true;
  if (/\.(ts|tsx)$/.test(f) && f.startsWith('ui/src/') && !f.startsWith('ui/src/gen/')) return true;
  if (/\.mjs$/.test(f) && f.startsWith('site/figures/')) return true;
  return false;
}
