#!/usr/bin/env node
// Rewrites every citation of a rule of a decision record from the old record and rule to the new,
// after the records were rewritten and their rules renumbered, merged, split or moved.
//
// usage: tools/records-renumber.mjs [repo-root] --map FILE|DIR... [--dry-run] [--out refs-diff.tsv]
//                                   [--records] [--all]
//
// --map     a mapping table, or a folder of them. One table for each old record, named
//           map-NNNN.tsv (NNNN is the number of the old record). Tab separated; lines that start
//           with # and empty lines are ignored; the first other line is the header:
//
//             part  old_id  action  new_ref  issue  reason  old_text_start
//
//           part is title, rule, why, cost, road or nyp (this tool reads only the rule rows).
//           old_id is the old rule's number. action is keep, merge, split, moved, to-nyp,
//           to-research or dropped. new_ref is `NNNN.N` for a rule of a new record, several of them
//           separated by commas for a split, `page:PATH` for a move out of the records, and empty
//           for a rule that was dropped. reason is required for dropped, moved and to-research.
//           old_text_start is the first words of the old rule, for the table below.
//
// A citation is found and bound to its record as tools/checks/record-refs.mjs does (see
// tools/checks/lib-refs.mjs). Every cited old rule needs a row. The tool refuses to write when
//   - a citation cannot be resolved, or is split by a line break;
//   - a cited rule has no row, or its record has no table;
//   - a cited rule was dropped, or went to a proposed line, a research page or another page: a
//     person decides what the sentence says now (todo.tsv-style lines are printed);
//   - a row points at a rule that the new records do not have.
// Nothing is written then, and the exit code is 1.
//
// A citation whose set of (record, rule) pairs does not change is left as it is, in the words
// the author wrote. A citation that changes is written again: the numbers of one record sorted
// and joined as `rule 5`, `rules 5 and 9`, `rules 5, 6 and 9`; three or more consecutive numbers
// become a range, `rules 5 to 7`, so a range whose rules no longer sit together becomes a list.
// When a rule moves to another record, the record number in the text is replaced (and the file
// name of a link to it); when one citation then names two records, `and record NNNN, rule N`
// follows; a citation that named its record only by context (inside its own record, in a run, by
// the page's declared default) gets `record NNNN,` in front when the new record differs.
//
// The records themselves are not read as targets unless --records is given: the new records are
// written with their new numbers already. Run it once, in the pull request that changes the
// records; it is not idempotent, because the table maps old to new.
//
// --dry-run prints the changes as a table (columns: file, line, old citation, new citation, first
// words of the old rule, first words of the new rule) and writes nothing. --out writes the same
// table to a file, in a dry run or not. --all lists unchanged citations too.
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { repoRoot, trackedFiles } from './checks/lib.mjs';
import { RECORD_FILE, citationsIn, readRecords, scanned } from './checks/lib-refs.mjs';

const COLUMNS = ['part', 'old_id', 'action', 'new_ref', 'issue', 'reason', 'old_text_start'];
const PARTS = new Set(['title', 'rule', 'why', 'cost', 'road', 'nyp']);
const ACTIONS = new Set(['keep', 'merge', 'split', 'moved', 'to-nyp', 'to-research', 'dropped']);
const NEEDS_REASON = new Set(['dropped', 'moved', 'to-research']);

// ---- arguments
const argv = process.argv.slice(2);
const opt = { dry: false, all: false, records: false, out: null, maps: [], root: null };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--dry-run') opt.dry = true;
  else if (a === '--all') opt.all = true;
  else if (a === '--records') opt.records = true;
  else if (a === '--out') opt.out = argv[++i];
  else if (a === '--map') opt.maps.push(argv[++i]);
  else if (a.startsWith('--')) die(`unknown option ${a}`);
  else if (opt.root === null) opt.root = resolve(a);
  else die(`unexpected argument ${a}`);
}
if (!opt.maps.length) die('no mapping table: pass --map FILE|DIR');
const root = opt.root ?? repoRoot([]);
const problems = [];
const todo = [];
function die(m) { console.error(`records-renumber: ${m}`); process.exit(2); }

// ---- the mapping tables
const tables = new Map(); // old record number -> Map(old rule number -> row)
function loadTable(path) {
  const m = /(?:^|\/)map-(00\d\d)\.tsv$/.exec(path);
  if (!m) { problems.push(`${path}: a mapping table is named map-NNNN.tsv`); return; }
  const rec = m[1];
  if (tables.has(rec)) { problems.push(`${path}: a second table for record ${rec}`); return; }
  const rows = new Map();
  tables.set(rec, rows);
  let header = false;
  readFileSync(path, 'utf8').split('\n').forEach((line, i) => {
    if (!line.trim() || line.startsWith('#')) return;
    const cells = line.replace(/\r$/, '').split('\t');
    if (!header) {
      header = true;
      if (cells.join('\t') !== COLUMNS.join('\t')) problems.push(`${path}:${i + 1}: the header is ${COLUMNS.join(' ')}, separated by tabs`);
      return;
    }
    const where = `${path}:${i + 1}`;
    if (cells.length !== COLUMNS.length) { problems.push(`${where}: ${cells.length} columns, expected ${COLUMNS.length}`); return; }
    const row = Object.fromEntries(COLUMNS.map((c, k) => [c, cells[k]]));
    if (!PARTS.has(row.part)) problems.push(`${where}: part "${row.part}" is not one of ${[...PARTS].join(', ')}`);
    if (!ACTIONS.has(row.action)) problems.push(`${where}: action "${row.action}" is not one of ${[...ACTIONS].join(', ')}`);
    if (NEEDS_REASON.has(row.action) && !row.reason) problems.push(`${where}: a ${row.action} row needs a reason`);
    if (row.part !== 'rule') return;
    if (!/^\d+$/.test(row.old_id)) { problems.push(`${where}: old_id "${row.old_id}" is not a rule number`); return; }
    const n = Number(row.old_id);
    if (rows.has(n)) problems.push(`${where}: rule ${n} has a second row`);
    if (row.action === 'dropped' ? row.new_ref : !row.new_ref) problems.push(`${where}: ${row.action === 'dropped' ? 'a dropped rule has no new_ref' : 'new_ref is empty'}`);
    rows.set(n, { ...row, where });
  });
  if (!header) problems.push(`${path}: no header`);
}
for (const p of opt.maps) {
  if (!existsSync(p)) { problems.push(`${p}: no such file`); continue; }
  if (statSync(p).isDirectory()) {
    for (const f of readdirSync(p).sort()) if (/^map-00\d\d\.tsv$/.test(f)) loadTable(join(p, f));
  } else loadTable(p);
}
if (!tables.size && !problems.length) problems.push('the --map arguments hold no table');

// ---- the new records: how many rules, and what they say
const files = trackedFiles(root);
const records = readRecords(root, files);
const ruleText = (rec, n) => {
  const info = records.get(rec);
  if (!info) return '';
  const text = readFileSync(join(root, info.file), 'utf8');
  const at = text.search(/^## Decision\s*$/m);
  for (const l of text.slice(at).split('\n').slice(1)) {
    if (/^## /.test(l)) break;
    const m = /^(\d+)\. (.*)$/.exec(l);
    if (m && Number(m[1]) === n) return m[2].split(/\s+/).slice(0, 8).join(' ');
  }
  return '';
};

// ---- text of a group of rule numbers of one record
function fmt(nums) {
  const s = [...new Set(nums)].sort((a, b) => a - b);
  const parts = [];
  for (let i = 0; i < s.length;) {
    let j = i;
    while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++;
    if (j - i >= 2) parts.push(`${s[i]} to ${s[j]}`);
    else for (let k = i; k <= j; k++) parts.push(String(s[k]));
    i = j + 1;
  }
  return parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
}
const wordFor = (nums) => (new Set(nums).size > 1 ? 'rules' : 'rule');
const sameSet = (a, b) => a.length === b.length && a.every((x, i) => x[0] === b[i][0] && x[1] === b[i][1]);

// ---- the citations
const diff = [];
const edits = new Map(); // file -> [{ at, end, text }] in characters of the file
let changed = 0;
let seen = 0;
if (!problems.length) {
  for (const f of files.filter(scanned).sort()) {
    if (!opt.records && RECORD_FILE.test(f)) continue;
    const text = readFileSync(join(root, f), 'utf8');
    const lines = text.split('\n');
    const lineStart = [];
    let at = 0;
    for (const l of lines) { lineStart.push(at); at += l.length + 1; }
    const { citations, pos } = citationsIn(f, text);
    const abs = (i) => { const p = pos(i); return lineStart[p.line - 1] + p.col; };
    const absEnd = (i) => abs(i - 1) + 1;
    let prevNew = null; // the one record that the previous clause now names, for a run
    for (const c of citations) {
      if (c.how === 'foreign') { prevNew = null; continue; }
      const where = `${f}:${c.line}`;
      seen++;
      if (c.how === 'none' || c.how === 'oldAdr') { problems.push(`${where}: "${c.text}" cannot be resolved to a record (run tools/checks/record-refs.mjs)`); prevNew = null; continue; }
      if (c.split) { problems.push(`${where}: "${c.text}" is split by a line break`); prevNew = null; continue; }
      const tbl = tables.get(c.record);
      const old = [];
      const next = [];
      let ok = true;
      for (const n of c.nums) {
        if (!tbl) { problems.push(`${where}: record ${c.record} has no mapping table (cited: ${c.text})`); ok = false; break; }
        const row = tbl.get(n);
        if (!row) { problems.push(`${where}: no mapping row for record ${c.record}, rule ${n}`); ok = false; continue; }
        old.push(row.old_text_start);
        const dest = row.new_ref.split(',').map((x) => /^(00\d\d)\.(\d+)$/.exec(x.trim()));
        if (row.action === 'dropped' || row.action === 'to-nyp' || row.action === 'to-research' || dest.some((d) => !d)) {
          todo.push(`${where}\t${c.text}\trecord ${c.record}, rule ${n}\t${row.action}\t${row.new_ref}\t${row.reason}`);
          ok = false;
          continue;
        }
        for (const d of dest) {
          const rec = records.get(d[1]);
          if (!rec) { problems.push(`${row.where}: record ${d[1]} does not exist`); ok = false; } else if (Number(d[2]) < 1 || Number(d[2]) > rec.rules) { problems.push(`${row.where}: record ${d[1]} has no rule ${d[2]} (it has rules 1 to ${rec.rules})`); ok = false; } else next.push([d[1], Number(d[2])]);
        }
      }
      if (!ok) { prevNew = null; continue; }
      const before = c.nums.map((n) => [c.record, n]);
      const same = sameSet(before, next);
      // the new groups, one for each record, in order of first appearance
      const groups = [];
      for (const [rec, n] of next) {
        let g = groups.find((x) => x.rec === rec);
        if (!g) groups.push((g = { rec, nums: [] }));
        g.nums.push(n);
      }
      const ctx = c.how === 'run' ? prevNew : c.how === 'own' || c.how === 'default' ? c.record : null;
      const explicit = (c.how === 'run' || c.how === 'own' || c.how === 'default') && !(groups.length === 1 && groups[0].rec === ctx);
      const cap = /^R/.test(c.word);
      const newText = groups
        .map((g, k) => {
          const w = wordFor(g.nums);
          if (k === 0 && !explicit) return `${cap ? 'R' : 'r'}${w.slice(1)} ${fmt(g.nums)}`;
          return `${k === 0 && cap ? 'Record' : 'record'} ${g.rec}, rule${w === 'rules' ? 's' : ''} ${fmt(g.nums)}`;
        })
        .join(' and ');
      prevNew = groups.length === 1 ? groups[0].rec : null;
      const oldCit = `record ${c.record}, ${c.text}`;
      const newCit = groups.map((g) => `record ${g.rec}, ${wordFor(g.nums)} ${fmt(g.nums)}`).join(' and ');
      const oldWords = old.join(' / ');
      const newWords = next.map(([rec, n]) => ruleText(rec, n)).join(' / ');
      if (same) {
        if (opt.all) diff.push([f, c.line, oldCit, newCit, oldWords, newWords]);
        continue;
      }
      changed++;
      diff.push([f, c.line, oldCit, newCit, oldWords, newWords]);
      const list = edits.get(f) ?? [];
      edits.set(f, list);
      list.push({ at: abs(c.start), end: absEnd(c.end), text: newText });
      if (!explicit && c.rec && c.how !== 'run' && groups[0].rec !== c.record) {
        const tail = text.slice(absEnd(c.rec.end), absEnd(c.rec.end) + 200);
        list.push({ at: abs(c.rec.start), end: absEnd(c.rec.end), text: groups[0].rec });
        const link = /^\]\(([^)\s]*?)(00\d\d)-[a-z0-9-]+\.md/.exec(tail);
        if (link && link[2] === c.record) {
          const from = absEnd(c.rec.end) + 2 + link[1].length;
          const info = records.get(groups[0].rec);
          list.push({ at: from, end: from + link[0].length - 2 - link[1].length, text: info.file.replace(/^docs\/decisions\//, '') });
        }
      }
    }
  }
}

// ---- report
const diffText = ['file\tline\told citation\tnew citation\told rule\tnew rule', ...diff.map((r) => r.join('\t'))].join('\n') + '\n';
if (opt.out) writeFileSync(opt.out, diffText);
if (opt.dry && !opt.out) process.stdout.write(diffText);
if (todo.length) {
  console.error('a person decides these (the rule was dropped, or is now a proposed line, a research page or another page):');
  console.error('file:line\tcitation\told rule\taction\tnew_ref\treason');
  for (const t of todo) console.error(t);
}
if (problems.length || todo.length) {
  for (const m of problems) console.error(`error: ${m}`);
  console.error(`records-renumber: ${problems.length} errors, ${todo.length} citations to decide; nothing written`);
  process.exit(1);
}
if (opt.dry) {
  console.error(`records-renumber: dry run, ${changed} of ${seen} citations would change in ${edits.size} files`);
  process.exit(0);
}
for (const [f, list] of edits) {
  let text = readFileSync(join(root, f), 'utf8');
  list.sort((a, b) => b.at - a.at);
  for (let i = 1; i < list.length; i++) if (list[i].end > list[i - 1].at) { console.error(`error: ${f}: two edits overlap`); process.exit(1); }
  for (const e of list) text = text.slice(0, e.at) + e.text + text.slice(e.end);
  writeFileSync(join(root, f), text);
}
console.log(`records-renumber: ${changed} of ${seen} citations changed in ${edits.size} files; run tools/checks/record-refs.mjs`);
