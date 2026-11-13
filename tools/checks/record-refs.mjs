#!/usr/bin/env node
// Citations of a decision record's rules: every `rule N` that cites a rule of a record names a
// record that exists and a rule that it has.
//
// The records are docs/decisions/NNNN-*.md; a record has as many rules as the numbered sentences
// of its "Decision" section. The citations are searched in the Markdown files, in the comments of
// proto/ and of the page's sources (ui/src, not the generated ui/src/gen) and in site/figures.
// How a citation names its record is in tools/checks/lib-refs.mjs: the record number before it
// (`record 0004, rule 2`, `0006 rules 12 and 29`), "rule 28 of record 0007", the next clause of a
// run (`record 0003, rule 16 and rule 14`), the record itself, or the one default that a page
// declares with the sentence "Rule numbers without a record name are those of record NNNN."
// A clause after `proto/README.md,` cites that file's own numbered rules and is not checked.
//
// It fails when a cited record does not exist, when a cited rule is not one of its rules, when a
// range runs backwards, when a citation names an old `ADR NNNN`, and when a citation cannot be
// resolved to a record: it does not guess from a record named farther back. It proves that a
// citation points at something, not that it points at the same meaning as before.
//
// usage: tools/checks/record-refs.mjs [repo-root]
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { reporter, repoRoot, trackedFiles } from './lib.mjs';
import { citationsIn, readRecords, scanned } from './lib-refs.mjs';

const root = repoRoot();
const r = reporter('check-record-refs');
const files = trackedFiles(root);
const records = readRecords(root, files);
if (!records.size) r.finish(0, 'decision records');
for (const [n, rec] of records) if (!rec.rules) r.error(`${rec.file}: record ${n} has no numbered rule in its "Decision" section`);

const forms = {};
let clauses = 0;
let numbers = 0;
let lists = 0;
let ranges = 0;
for (const f of files.filter(scanned).sort()) {
  const text = readFileSync(join(root, f), 'utf8');
  for (const c of citationsIn(f, text).citations) {
    const where = `${f}:${c.line}`;
    if (c.how === 'foreign') { forms.foreign = (forms.foreign ?? 0) + 1; continue; }
    clauses++;
    numbers += c.nums.length;
    if (/\bto\b|–|-/.test(c.list)) ranges++;
    else if (c.nums.length > 1) lists++;
    if (c.split) { r.error(`${where}: "${c.text}" and its record are split by a line break; keep them on one line`); continue; }
    if (c.how === 'none') { r.error(`${where}: "${c.text}" names no record; write "record NNNN, ${c.word.toLowerCase()} ${c.list}"`); continue; }
    if (c.how === 'oldAdr') { r.error(`${where}: "${c.text}" cites record ${c.record} as an ADR; the records have their own numbers`); continue; }
    forms[c.how] = (forms[c.how] ?? 0) + 1;
    const rec = records.get(c.record);
    if (!rec) { r.error(`${where}: "${c.text}" cites record ${c.record}, which does not exist`); continue; }
    if (c.bad) { r.error(`${where}: "${c.text}" is a range that runs backwards`); continue; }
    for (const n of c.nums) {
      if (n < 1 || n > rec.rules) r.error(`${where}: record ${c.record} has no rule ${n} (it has rules 1 to ${rec.rules})`);
    }
  }
}
const form = Object.entries(forms).sort().map(([k, v]) => `${k} ${v}`).join(', ');
console.log(`check-record-refs: ${clauses} clauses, ${numbers} rule numbers (${lists} lists, ${ranges} ranges); how the record is named: ${form}`);
r.finish(clauses, `citations of ${records.size} records`);
