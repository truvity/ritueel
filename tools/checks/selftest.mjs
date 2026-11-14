#!/usr/bin/env node
// Self-test for the checks in tools/checks/: each check runs against scratch repositories that
// must pass or must fail. A check that passes everything is not a check.
//
// The fixtures are built here at run time, so no token-shaped string or deny-listed term is
// committed; the names are invented (examplecorp).
//
// usage: tools/checks/selftest.mjs
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');
const scratch = mkdtempSync(join(tmpdir(), 'ritueel-checks-'));
let failures = 0;
let cases = 0;

// A git repository holding `files` (path -> content), and the `commits` (messages) made on top
// of a first commit on the branch `base`. Scratch commits are unsigned: they never leave this machine.
function fixture(files, commits = []) {
  const dir = mkdtempSync(join(scratch, 'repo-'));
  for (const [path, text] of Object.entries(files)) {
    if (text === undefined) continue;
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  execFileSync('git', ['init', '-q', dir]);
  execFileSync('git', ['-C', dir, 'add', '-A']);
  if (commits.length) {
    const git = (...a) => execFileSync('git', ['-C', dir, '-c', 'user.name=Example', '-c', 'user.email=dev@example.com', '-c', 'commit.gpgsign=false', ...a]);
    git('commit', '-q', '--allow-empty', '-m', 'base');
    git('branch', 'base');
    for (const m of commits) git('commit', '-q', '--allow-empty', '-m', m);
  }
  return dir;
}

// Run `check` on `files`; `want` is 'pass' or 'fail'; `has`/`lacks` are strings the output must
// or must not contain (case-insensitive).
function expect(name, check, files, want, { env = {}, has = [], lacks = [], commits = [], script = join(here, `${check}.mjs`), target = '' } = {}) {
  cases++;
  const dir = fixture(files, commits);
  const res = spawnSync(process.execPath, [script, join(dir, target)], {
    encoding: 'utf8',
    env: { ...process.env, PUBLIC_CONTENT_DENYLIST: '', REQUIRE_DENYLIST: '', PR_TITLE: '', PR_BODY: '', BASE: 'base', ...env },
  });
  const out = `${res.stdout}${res.stderr}`;
  const got = res.status === 0 ? 'pass' : 'fail';
  const problems = [];
  if (got !== want) problems.push(`expected ${want}, got ${got}`);
  for (const s of has) if (!out.toLowerCase().includes(s.toLowerCase())) problems.push(`output lacks "${s}"`);
  for (const s of lacks) if (out.toLowerCase().includes(s.toLowerCase())) problems.push(`output contains "${s}"`);
  if (problems.length) {
    failures++;
    console.error(`FAIL ${check}: ${name}: ${problems.join('; ')}\n${out.replace(/^/gm, '  | ')}`);
  } else console.log(`ok   ${check}: ${name}`);
}

// ---- decisions: the real template and README, with an index of one record
const template = readFileSync(join(repo, 'docs/decisions/0000-template.md'), 'utf8');
const readme = readFileSync(join(repo, 'docs/decisions/README.md'), 'utf8')
  .replace(/(## Index\n)[\s\S]*$/, '$1\n| ADR | Decision | Status |\n|-----|----------|--------|\n');
const row = (n, slug, status) => `| [${n}](${n}-${slug}.md) | A decision | ${status} |\n`;
const GOOD = ['- **Another way.** It would be simpler, and it lost because it breaks the example.'];
const FOLLOW = ['- **Not yet proven.** Test it at a card ([#11](https://github.com/truvity/ritueel/issues/11)).'];
const record = ({ num = '0001', status = 'Accepted', date = '2026-10-31', drop = '', roads = GOOD, follow = FOLLOW, extra = [], decision = ['1. We use the example.'], replaces = null, why = ['Text.'] } = {}) =>
  [
    `# ${num} — We use the example`, '', `**Status:** ${status}`, `**Date:** ${date}`, '', ...extra,
    ...['Decision', 'Why', 'What it costs'].filter((s) => s !== drop).flatMap((s) => [`## ${s}`, '', ...(s === 'Decision' ? decision : s === 'Why' ? why : ['Text.']), '']),
    '## Roads not taken', '', ...roads, '',
    ...(drop === 'Not yet proven or only proposed' ? [] : ['## Not yet proven or only proposed', '', ...follow, '']),
    ...(replaces ? ['## Replaces', '', ...replaces, ''] : []),
  ].join('\n');
const adr = (extra = {}, idx = row('0001', 'we-use-the-example', 'Accepted')) => ({
  'docs/decisions/0000-template.md': template,
  'docs/decisions/README.md': readme + idx,
  'docs/decisions/0001-we-use-the-example.md': record(),
  ...extra,
});
const one = (opts) => ({ 'docs/decisions/0001-we-use-the-example.md': record(opts) });
expect('a good record', 'decisions', adr(), 'pass', { has: ['1 records'] });
expect('nothing unproven, said as None.', 'decisions', adr(one({ follow: ['None.'] })), 'pass');
expect('a road with a colon after the name', 'decisions', adr(one({ roads: ['- **Another way**: simpler, and it lost because it breaks the example.'] })), 'pass');
expect('a road with no reason', 'decisions', adr(one({ roads: ['- **Another way.**'] })), 'fail', { has: ['a road not taken is one line'] });
expect('a road in the old three-bullet form', 'decisions', adr(one({ roads: ['### Another way', '', '- Pros: one.', '- Cons: two.', '- Why not: three.'] })), 'fail', { has: ['a road not taken is one line'] });
expect('no road at all', 'decisions', adr(one({ roads: [] })), 'fail', { has: ['lists no option'] });
expect('an unproven line without its issue', 'decisions', adr(one({ follow: ['- **Not yet proven.** Test it at a card.'] })), 'fail', { has: ['links its issue'] });
expect('an unproven line without its label', 'decisions', adr(one({ follow: ['- Test it at a card ([#11](https://github.com/truvity/ritueel/issues/11)).'] })), 'fail', { has: ['**Not yet proven.**'] });
expect('a proposed line', 'decisions', adr(one({ follow: ['- **Proposed.** The port is open ([#17](https://github.com/truvity/ritueel/issues/17)).'] })), 'pass');
expect('an empty unproven section', 'decisions', adr(one({ follow: [] })), 'fail', { has: ['"## Not yet proven or only proposed" is empty'] });
expect('no unproven section', 'decisions', adr(one({ drop: 'Not yet proven or only proposed' })), 'fail', { has: ['## Not yet proven or only proposed'] });
expect('a clean record has no Replaces section', 'decisions', adr(), 'pass', { lacks: ['Replaces'] });
expect('a record with a Replaces section', 'decisions', adr(one({ replaces: ['Nothing; new in the rewrite.'] })), 'fail', { has: ['"## Replaces" is not a section of a record'] });
expect('a record with an empty Replaces section', 'decisions', adr(one({ replaces: [] })), 'fail', { has: ['"## Replaces" is not a section of a record'] });
expect('a template with a Replaces section', 'decisions', adr({ 'docs/decisions/0000-template.md': `${template}\n## Replaces\n\nNothing.\n` }), 'fail', { has: ['0000-template.md: "## Replaces" is not a section of a record'] });
expect('a removed rule keeps its number', 'decisions', adr(one({ decision: ['1. One.', '2. Removed.', '3. Three.'] })), 'pass');
expect('a proposed line with a second link', 'decisions', adr(one({ follow: ['- **Proposed.** The stick may tear a sector ([note](../research/stick.md), [#181](https://github.com/truvity/ritueel/issues/181)).'] })), 'pass');
expect('a proposed line with a second link and no issue', 'decisions', adr(one({ follow: ['- **Proposed.** The stick may tear a sector ([note](../research/stick.md)).'] })), 'fail', { has: ['links its issue'] });
expect('a Decision that is not numbered', 'decisions', adr(one({ decision: ['We use the example.'] })), 'fail', { has: ['numbered list'] });
expect('a Decision numbered out of order', 'decisions', adr(one({ decision: ['1. One.', '3. Three.'] })), 'fail', { has: ['where 2 is expected'] });
expect('a Decision with a wrapped line', 'decisions', adr(one({ decision: ['1. One', '   and more.', '2. Two.'] })), 'pass');
expect('a Decision with a table', 'decisions', adr(one({ decision: ['1. One.', '', '| a | b |', '|---|---|', '| 1 | 2 |'] })), 'fail', { has: ['no heading or table'] });
expect('a Decision with a sub-heading', 'decisions', adr(one({ decision: ['1. One.', '', '### Slots', '', '2. Two.'] })), 'fail', { has: ['no heading or table'] });
expect('a Decision with a code block', 'decisions', adr(one({ decision: ['1. One.', '', '```', 'x', '```'] })), 'fail', { has: ['no code block'] });
const long = (n) => Array.from({ length: n }, () => 'word').join(' ');
expect('an over-long record is a warning', 'decisions', adr(one({ why: [long(1200)] })), 'pass', { has: ['warning', 'limit 1100'] });
expect('an over-long record in strict mode', 'decisions', adr(one({ why: [long(1200)] })), 'fail', { env: { RECORD_SIZE_STRICT: '1' }, has: ['limit 1100'] });
expect('an Accepted record with an open part', 'decisions', adr(one({ decision: ['1. Text.', '', '### Open', '', '- A question.'] })), 'fail', { has: ['no open part'] });
expect('a Proposed record', 'decisions', adr(one({ status: 'Proposed' }), row('0001', 'we-use-the-example', 'Proposed')), 'pass');
expect('a line of the template comment left in', 'decisions', adr(one({ extra: [template.split('\n').find((l) => /^Keep the text public/.test(l)), ''] })), 'fail', { has: ["template's instructions comment"] });
expect('no records', 'decisions', { ...adr({}, ''), 'docs/decisions/0001-we-use-the-example.md': undefined }, 'fail', { has: ['empty sweep'] });
expect('a missing section', 'decisions', adr(one({ drop: 'What it costs' })), 'fail', { has: ['## What it costs'] });
expect('an unknown status', 'decisions', adr(one({ status: 'Maybe' })), 'fail', { has: ['not one of'] });
expect('superseded by a missing record', 'decisions', adr(one({ status: 'Superseded by 0099' }), row('0001', 'we-use-the-example', 'Superseded by 0099')), 'fail', { has: ['0099'] });
expect('a date that is no day', 'decisions', adr(one({ date: '2026-02-30' })), 'fail', { has: ['YYYY-MM-DD'] });
expect('a title with another number', 'decisions', adr(one({ num: '0002' })), 'fail', { has: ['number 0002'] });
expect('an index status that differs', 'decisions', adr({}, row('0001', 'we-use-the-example', 'Proposed')), 'fail', { has: ['says "Proposed"'] });
expect('a record not in the index', 'decisions', adr({}, ''), 'fail', { has: ['no row in the README index'] });
expect('an index row without a file', 'decisions', adr({}, row('0001', 'we-use-the-example', 'Accepted') + row('0003', 'gone', 'Accepted')), 'fail', { has: ['0003 has no record'] });
expect('a file name that is not kebab-case', 'decisions', adr({ 'docs/decisions/0004_Bad.md': record({ num: '0004' }) }), 'fail', { has: ['0004_Bad.md'] });
expect('two records with one number', 'decisions', adr({ 'docs/decisions/0001-again.md': record() }), 'fail', { has: ['also used by'] });

// ---- citations of a record's rules: two small records (0005 has three rules, 0006 has five)
const rec = (n, rules, extra = '') => `# ${n} — A decision\n\n**Status:** Accepted\n**Date:** 2026-11-13\n\n## Decision\n\n${Array.from({ length: rules }, (_, i) => `${i + 1}. We decide the matter numbered ${i + 1}.`).join('\n')}${extra}\n\n## Why\n\nText.\n`;
const refs = (files) => ({
  'docs/decisions/0005-a-ceremony.md': rec('0005', 3),
  'docs/decisions/0006-a-bundle.md': rec('0006', 5),
  'docs/decisions/0000-template.md': '# NNNN — Title\n\n## Decision\n\n1. A rule.\n',
  'docs/decisions/README.md': '# Decisions\n',
  ...files,
});
const page = (text) => refs({ 'docs/a.md': `${text}\n` });
expect('a record named before the rule', 'record-refs', page('See record 0005, rule 2.'), 'pass', { has: ['1 citations of 2 records', 'before 1'] });
expect('a linked record, a list and a range', 'record-refs', page('See [record 0006](decisions/0006-a-bundle.md), rules 1 and 3, and 0005 (rules 1 to 3).'), 'pass', { has: ['2 clauses', '1 lists, 1 ranges'] });
expect('a table cell with the number first', 'record-refs', page('| Wanted | 0006 rules 2, 4 and 5 |'), 'pass');
expect('the rule before its record', 'record-refs', page('It is decided in rule 2 of [record 0006](decisions/0006-a-bundle.md).'), 'pass', { has: ['after 1'] });
expect('the next clause of a run', 'record-refs', page('See record 0006, rule 5 and rule 2, and 0005 rule 3, rule 1.'), 'pass', { has: ['run 2'] });
expect('a rule cited inside its own record', 'record-refs', refs({ 'docs/decisions/0006-a-bundle.md': rec('0006', 5, '\nSee also (rule 2).') }), 'pass', { has: ['own 1'] });
expect('a record that wraps onto the next line of a page', 'record-refs', page('Decided in [record 0005](decisions/0005-a-ceremony.md),\nrules 1 to 3, in plain words.'), 'pass');
expect('the default a page declares', 'record-refs', page('Rule numbers without a record name are those of record 0006.\n\nSee rule 4 and record 0005, rule 2.'), 'pass', { has: ['default 1'] });
expect('the numbered rules of another file', 'record-refs', page('A command is exact (proto/README.md, rule 7), as record 0005, rule 1, says.'), 'pass', { has: ['foreign 1'] });
expect('a comment that wraps before the record number', 'record-refs', refs({ 'proto/x/v1/a.proto': '// Nearest decided text: record\n// 0006, rule 2 (a card)]\nmessage A {}\n' }), 'pass');
expect('the generated code is not read', 'record-refs', refs({ 'docs/a.md': 'See record 0005, rule 2.\n', 'ui/src/gen/a_pb.ts': '// record 0099, rule 77\n' }), 'pass');
expect('a record that does not exist', 'record-refs', page('See record 0099, rule 1.'), 'fail', { has: ['docs/a.md:1', 'record 0099, which does not exist'] });
expect('a rule the record does not have', 'record-refs', page('See record 0005, rule 4.'), 'fail', { has: ['docs/a.md:1', 'record 0005 has no rule 4', 'rules 1 to 3'] });
expect('rule 0', 'record-refs', page('See record 0005, rule 0.'), 'fail', { has: ['no rule 0'] });
expect('one bad number in a list', 'record-refs', page('See record 0006, rules 1 and 6.'), 'fail', { has: ['no rule 6'] });
expect('a range that runs backwards', 'record-refs', page('See record 0006, rules 4 to 2.'), 'fail', { has: ['runs backwards'] });
expect('a bare rule in a page', 'record-refs', page('The wanted file decides (rule 2).'), 'fail', { has: ['docs/a.md:1', 'names no record'] });
expect('a record named farther back is no guess', 'record-refs', page('Record 0005 decides the plan. A saved plan is run later, as the next sentence says (rule 2).'), 'fail', { has: ['names no record'] });
expect('a record number after a full stop', 'record-refs', page('It is in 0006. Rule 2 says more.'), 'fail', { has: ['names no record'] });
expect('an old ADR number', 'record-refs', page('As ADR 0005 rule 2 said.'), 'fail', { has: ['as an ADR'] });
expect('a rule too high inside its own record', 'record-refs', refs({ 'docs/decisions/0005-a-ceremony.md': rec('0005', 3, '\nSee (rule 9).') }), 'fail', { has: ['record 0005 has no rule 9'] });
expect('a citation split by a comment line break', 'record-refs', refs({ 'proto/x/v1/a.proto': '// Nearest decided text: 0006 rule\n// 2 (a card)]\nmessage A {}\n' }), 'fail', { has: ['proto/x/v1/a.proto:1', 'split by a line break'] });
expect('the rule on the line after the record number', 'record-refs', refs({ 'ui/src/a.ts': '// See record 0006,\n// rule 2.\nexport {};\n' }), 'fail', { has: ['split by a line break'] });
expect('a default that names a missing record', 'record-refs', page('Rule numbers without a record name are those of record 0042.\n\nSee rule 1.'), 'fail', { has: ['record 0042, which does not exist'] });
expect('no citation at all', 'record-refs', page('No rule is cited here.'), 'fail', { has: ['empty sweep'] });
expect('no records', 'record-refs', { 'docs/a.md': 'See record 0005, rule 2.\n' }, 'fail', { has: ['empty sweep'] });

// ---- tools/records-renumber.mjs: new records 0005 (4 rules) and 0006 (6 rules), and the tables that
// say where the old rules went. Old 0005 had 6 rules: 1, 2 stay; 3 is dropped; 4 is now rule 3;
// 5 moved to 0006 rule 6; 6 was split into 0005 rules 3 and 4. Old 0006 had 6 rules: 1 to 3 stay,
// 4 is now rule 6, 5 is rule 4, 6 is rule 5.
const tsv = (...rows) => `# map\n${['part', 'old_id', 'action', 'new_ref', 'issue', 'reason', 'old_text_start'].join('\t')}\n${rows.map((r) => r.join('\t')).join('\n')}\n`;
const R = (id, action, ref, reason = '', start = `Old rule ${id} of the plan`) => ['rule', String(id), action, ref, '', reason, start];
const MAP5 = tsv(R(1, 'keep', '0005.1'), R(2, 'keep', '0005.2'), R(3, 'dropped', '', 'six-steps'), R(4, 'keep', '0005.3'), R(5, 'moved', '0006.6', 'now a rule of the bundle'), R(6, 'split', '0005.3,0005.4'));
const MAP6 = tsv(R(1, 'keep', '0006.1'), R(2, 'keep', '0006.2'), R(3, 'keep', '0006.3'), R(4, 'keep', '0006.6'), R(5, 'keep', '0006.4'), R(6, 'keep', '0006.5'));
const renumberFiles = (files, maps = { 'map-0005.tsv': MAP5, 'map-0006.tsv': MAP6 }) => refs({
  'docs/decisions/0005-a-ceremony.md': rec('0005', 4),
  'docs/decisions/0006-a-bundle.md': rec('0006', 6),
  ...Object.fromEntries(Object.entries(maps).map(([n, c]) => [`maps/${n}`, c])),
  ...files,
});
function renumber(name, files, want, { args = [], has = [], lacks = [], after = {}, same = [], maps } = {}) {
  cases++;
  const dir = fixture(renumberFiles(files, maps));
  const before = Object.fromEntries(Object.keys(files).map((k) => [k, readFileSync(join(dir, k), 'utf8')]));
  const res = spawnSync(process.execPath, [join(here, '..', 'records-renumber.mjs'), dir, '--map', join(dir, 'maps'), ...args], { encoding: 'utf8' });
  const out = `${res.stdout}${res.stderr}`;
  const problems = [];
  if ((res.status === 0 ? 'pass' : 'fail') !== want) problems.push(`expected ${want}, got ${res.status === 0 ? 'pass' : 'fail'}`);
  for (const s of has) if (!out.toLowerCase().includes(s.toLowerCase())) problems.push(`output lacks "${s}"`);
  for (const s of lacks) if (out.toLowerCase().includes(s.toLowerCase())) problems.push(`output contains "${s}"`);
  for (const [path, text] of Object.entries(after)) {
    const got = readFileSync(join(dir, path), 'utf8');
    if (got !== text) problems.push(`${path} is ${JSON.stringify(got)}, expected ${JSON.stringify(text)}`);
  }
  for (const path of same) if (readFileSync(join(dir, path), 'utf8') !== before[path]) problems.push(`${path} was changed`);
  if (problems.length) {
    failures++;
    console.error(`FAIL records-renumber: ${name}: ${problems.join('; ')}\n${out.replace(/^/gm, '  | ')}`);
  } else console.log(`ok   records-renumber: ${name}`);
}
const aPage = (text, path = 'docs/a.md') => ({ [path]: `${text}\n` });
renumber('a rule that is renumbered', aPage('See record 0005, rule 4.'), 'pass', { after: aPage('See record 0005, rule 3.'), has: ['1 of 1 citations changed in 1 files'] });
renumber('a rule that moved to another record, and its link', aPage('See [record 0005](decisions/0005-a-ceremony.md), rule 5.'), 'pass', { after: aPage('See [record 0006](decisions/0006-a-bundle.md), rule 6.') });
renumber('the rule before its record', aPage('Decided by rule 5 of [0005](0005-a-ceremony.md).'), 'pass', { after: aPage('Decided by rule 6 of [0006](0006-a-bundle.md).') });
renumber('a split rule', aPage('See record 0005, rule 6.'), 'pass', { after: aPage('See record 0005, rules 3 and 4.') });
renumber('a list that spreads over two records', aPage('See record 0005, rules 4 and 5.'), 'pass', { after: aPage('See record 0005, rule 3 and record 0006, rule 6.') });
renumber('a range that still sits together', aPage('See record 0006, rules 4 to 6.'), 'pass', { after: aPage('See record 0006, rules 4 to 6.'), same: ['docs/a.md'] });
renumber('a range whose rules no longer sit together becomes a list', aPage('See 0006 rules 3 to 5.'), 'pass', { after: aPage('See 0006 rules 3, 4 and 6.') });
renumber('a list is sorted when it is written again', aPage('See record 0006, rules 5, 2 and 6.'), 'pass', { after: aPage('See record 0006, rules 2, 4 and 5.') });
renumber('a list whose rules now sit together becomes a range', aPage('See record 0006, rules 6, 4 and 5.'), 'pass', { after: aPage('See record 0006, rules 4 to 6.') });
renumber('a citation that does not change is left as written', aPage('See record 0006, rules 2 and 1.'), 'pass', { same: ['docs/a.md'], has: ['0 of 1 citations changed'] });
renumber('the next clause of a run', aPage('See record 0005, rule 4 and rule 5.'), 'pass', { after: aPage('See record 0005, rule 3 and record 0006, rule 6.') });
renumber('the default a page declares', aPage('Rule numbers without a record name are those of record 0005.\n\nSee rule 4 and rule 5.'), 'pass', { after: aPage('Rule numbers without a record name are those of record 0005.\n\nSee rule 3 and record 0006, rule 6.') });
renumber('a comment of a source file', { 'proto/x/v1/a.proto': '// Decided: record 0005, rule 4]\nmessage A {}\n' }, 'pass', { after: { 'proto/x/v1/a.proto': '// Decided: record 0005, rule 3]\nmessage A {}\n' } });
renumber('the rules of another file are not touched', aPage('A command is exact (proto/README.md, rule 7), as record 0005, rule 4, says.'), 'pass', { after: aPage('A command is exact (proto/README.md, rule 7), as record 0005, rule 3, says.') });
renumber('a record is not a target unless asked', { 'docs/decisions/0006-a-bundle.md': `${rec('0006', 6)}\nSee (rule 5).\n` }, 'pass', { has: ['0 of 0 citations'] });
renumber('a rule cited inside its own record, with --records', { 'docs/decisions/0006-a-bundle.md': `${rec('0006', 6)}\nSee (rule 5).\n` }, 'pass', { args: ['--records'], after: { 'docs/decisions/0006-a-bundle.md': `${rec('0006', 6)}\nSee (rule 4).\n` } });
renumber('a rule cited inside its own record that moved', { 'docs/decisions/0005-a-ceremony.md': `${rec('0005', 4)}\nSee (rule 5).\n` }, 'pass', { args: ['--records'], after: { 'docs/decisions/0005-a-ceremony.md': `${rec('0005', 4)}\nSee (record 0006, rule 6).\n` } });
renumber('a dry run writes nothing and prints the table', aPage('See record 0005, rule 4.'), 'pass', { args: ['--dry-run'], same: ['docs/a.md'], has: ['file\tline\told citation\tnew citation\told rule\tnew rule', 'docs/a.md\t1\trecord 0005, rule 4\trecord 0005, rule 3\tOld rule 4 of the plan\tWe decide the matter numbered 3.'] });
renumber('the table in a file', aPage('See record 0005, rule 5.'), 'pass', { args: ['--out', join(scratch, 'refs-diff.tsv')], after: aPage('See record 0006, rule 6.') });
renumber('a rule that was dropped', aPage('See record 0005, rule 3.'), 'fail', { same: ['docs/a.md'], has: ['a person decides', 'docs/a.md:1', 'dropped', 'six-steps', 'nothing written'] });
renumber('a dropped rule in a list stops the whole run', { ...aPage('See record 0005, rule 4.', 'docs/a.md'), ...aPage('See record 0005, rules 1 and 3.', 'docs/b.md') }, 'fail', { same: ['docs/a.md', 'docs/b.md'], has: ['nothing written'] });
renumber('a cited rule with no row', aPage('See record 0005, rule 9.'), 'fail', { same: ['docs/a.md'], has: ['no mapping row for record 0005, rule 9'] });
renumber('a cited record with no table', aPage('See record 0006, rule 1.'), 'fail', { maps: { 'map-0005.tsv': MAP5 }, has: ['record 0006 has no mapping table'] });
renumber('a row that points at a rule the new record does not have', aPage('See record 0005, rule 1.'), 'fail', { maps: { 'map-0005.tsv': tsv(R(1, 'keep', '0005.9')), 'map-0006.tsv': MAP6 }, has: ['record 0005 has no rule 9'] });
renumber('a row that points at a record that does not exist', aPage('See record 0005, rule 1.'), 'fail', { maps: { 'map-0005.tsv': tsv(R(1, 'moved', '0042.1', 'moved')), 'map-0006.tsv': MAP6 }, has: ['record 0042 does not exist'] });
renumber('a rule that became a proposed line', aPage('See record 0005, rule 1.'), 'fail', { maps: { 'map-0005.tsv': tsv(R(1, 'to-nyp', '0005.nyp.2', '')), 'map-0006.tsv': MAP6 }, has: ['a person decides'] });
renumber('a dropped row without a reason', aPage('See record 0005, rule 1.'), 'fail', { maps: { 'map-0005.tsv': tsv(R(1, 'dropped', '', '')), 'map-0006.tsv': MAP6 }, has: ['a dropped row needs a reason'] });
renumber('a table with the wrong header', aPage('See record 0005, rule 1.'), 'fail', { maps: { 'map-0005.tsv': 'part\told\n', 'map-0006.tsv': MAP6 }, has: ['the header is'] });
renumber('a citation that names no record', aPage('See rule 4.'), 'fail', { same: ['docs/a.md'], has: ['cannot be resolved to a record'] });
renumber('a citation split by a line break', { 'proto/x/v1/a.proto': '// See record 0005, rule\n// 4.\nmessage A {}\n' }, 'fail', { has: ['split by a line break'] });

// ---- public content. The token-shaped strings are assembled here, not written out.
const pub = (text) => ({ 'README.md': `# Example\n\n${text}\n` });
const pem = `${'-'.repeat(5)}BEGIN EC PRIVATE KEY${'-'.repeat(5)}`;
expect('clean text', 'public-content', pub('Use sluis.example.com and account 123456789012.'), 'pass', { has: ['private deny-list not available, skipped'] });
expect('an account-id-shaped number', 'public-content', pub(`arn:aws:iam::${'48392017'}${'4655'}:role/x`), 'fail', { has: ['README.md:3', 'account-id-shaped'], lacks: ['4655'] });
expect('a private key block', 'public-content', pub(pem), 'fail', { has: ['private key block'] });
expect('a GitHub token', 'public-content', pub(`token ${'ghp'}_${'a1B2'.repeat(9)}`), 'fail', { has: ['GitHub token'], lacks: ['a1B2'] });
expect('an AWS access key id', 'public-content', pub(`${'AK'}IA${'Q'.repeat(16)}`), 'fail', { has: ['AWS access key id'] });
expect('an sk- key', 'public-content', pub(`${'sk'}-proj-${'x9'.repeat(12)}`), 'fail', { has: ['sk- secret key'] });
expect('an sk- word with no digit', 'public-content', pub(`${'sk'}-${'abcdefghij'.repeat(3)}`), 'pass');
expect('a dashed account id', 'public-content', pub(`account ${'4839'}-${'2017'}-${'4655'}`), 'fail', { has: ['dashed account-id-shaped'], lacks: ['4655'] });
expect('a dashed placeholder', 'public-content', pub('account 1234-5678-9012'), 'pass');
expect('a UUID whose last group is digits', 'public-content', pub(`id 9f1c2d3e-4b5a-4c6d-8e7f-${'48392017'}${'4655'}`), 'pass');
expect('digits inside a base64 run', 'public-content', pub(`sha512-Qx7Lm2${'48392017'}${'4655'}Zp9KdR3tWv0Ys==`), 'pass');
expect('a Stripe live key', 'public-content', pub(`${'sk'}_live_${'a1'.repeat(12)}`), 'fail', { has: ['Stripe live key'] });
expect('an npm token', 'public-content', pub(`${'npm'}_${'a1B2'.repeat(9)}`), 'fail', { has: ['npm token'] });
expect('an age secret key', 'public-content', pub(`${'AGE-SECRET'}-KEY-1${'QZ'.repeat(29)}`), 'fail', { has: ['age secret key'] });
expect('a Vault token', 'public-content', pub(`${'hvs'}.${'a1B2'.repeat(7)}`), 'fail', { has: ['Vault token'] });
expect('FIDO SSH key types are not tokens', 'public-content', pub('sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256-cert-v01@openssh.com'), 'pass');
expect('a deny-listed term', 'public-content', pub('Deployed at ExampleCorp in 2026.'), 'fail',
  { env: { PUBLIC_CONTENT_DENYLIST: '# comment\n\nexamplecorp\nglobexample\n' }, has: ['README.md:3: matches a deny-listed term'], lacks: ['examplecorp', 'globexample', 'Deployed'] });
expect('a deny-listed term in a path', 'public-content', { 'README.md': 'x\n', 'docs/examplecorp/notes.md': `${'4839'}-${'2017'}-${'4655'}\n` }, 'fail',
  { env: { PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, has: ['a tracked path matches a deny-listed term (file #2)', 'file #2:1:1'], lacks: ['examplecorp', 'notes.md'] });
expect('a term inside a longer word is no match', 'public-content', pub('The examplecorpus is fine.'), 'pass',
  { env: { PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, has: ['private deny-list loaded'], lacks: ['examplecorpus'] });
expect('a required deny-list that is empty', 'public-content', pub('Text.'), 'fail', { env: { REQUIRE_DENYLIST: 'true' }, has: ['required here'] });
expect('a required deny-list that is set', 'public-content', pub('Text.'), 'pass', { env: { REQUIRE_DENYLIST: 'true', PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, lacks: ['examplecorp'] });
expect('a deny-list that is not required', 'public-content', pub('Text.'), 'pass', { env: { REQUIRE_DENYLIST: 'false' }, has: ['skipped'] });

// ---- public text: commit messages and the pull request text
const msgs = { 'README.md': 'x\n' };
const term = { PUBLIC_CONTENT_DENYLIST: 'examplecorp' };
expect('clean messages', 'public-messages', msgs, 'pass', { commits: ['docs: a change', 'ci: another'], env: { ...term, PR_TITLE: 'docs: a change' }, has: ['3 commit messages'] });
expect('a term in a commit message', 'public-messages', msgs, 'fail', { commits: ['docs: a change', 'docs: for ExampleCorp\n\nBody.'], env: term, has: ['line 1: matches a deny-listed term'], lacks: ['examplecorp', 'Body.'] });
expect('a term in the pull request body', 'public-messages', msgs, 'fail', { commits: ['docs: a change'], env: { ...term, PR_TITLE: 'docs: a change', PR_BODY: 'Intro.\nSee examplecorp.' }, has: ['pull request body, line 2: matches a deny-listed term'], lacks: ['examplecorp'] });
expect('a token in a commit message', 'public-messages', msgs, 'fail', { commits: [`ci: ${'ghp'}_${'a1B2'.repeat(9)}`], has: ['GitHub token'], lacks: ['a1B2'] });
expect('no commits and no pull request text', 'public-messages', msgs, 'fail', { commits: ['docs: one'], env: { BASE: 'HEAD' }, has: ['empty sweep'] });
expect('nothing to scan', 'public-content', {}, 'fail', { has: ['empty sweep'] });

// ---- YAML extension
expect('.yaml files', 'yaml-ext', { 'a.yaml': 'a: 1\n' }, 'pass');
expect('the files tools require', 'yaml-ext', { '.github/ISSUE_TEMPLATE/config.yml': 'blank_issues_enabled: false\n', 'site/.yarnrc.yml': 'nodeLinker: node-modules\n' }, 'pass');
expect('a .yml file', 'yaml-ext', { 'a.yaml': 'a: 1\n', 'deploy/values.yml': 'a: 1\n' }, 'fail', { has: ['deploy/values.yml'] });
expect('no YAML at all', 'yaml-ext', { 'README.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- MDX only for pages that place components
const MDX_HOME = "---\ntitle: Home\n---\nimport '../site/home.css';\nimport Cloud from '../site/Cloud.astro';\nimport { Pair as Twin, helper } from '../site/Pair.astro';\n\n<div>\n  <Cloud />\n</div>\n";
expect('an .mdx page that places a component', 'mdx-pages', { 'docs/index.mdx': MDX_HOME }, 'pass');
expect('an .mdx page that places a renamed named import', 'mdx-pages', { 'docs/a/b.mdx': "import { Pair as Twin } from '../x.astro';\n\n<Twin part=\"a\" />\n" }, 'pass');
expect('an .mdx page with plain Markdown', 'mdx-pages', { 'docs/index.mdx': MDX_HOME, 'docs/learn/x.mdx': '# Title\n\nText.\n' }, 'fail', { has: ['docs/learn/x.mdx: use .md: MDX only for pages that place components'] });
expect('an .mdx page that imports a component and never places it', 'mdx-pages', { 'docs/x.mdx': "import Cloud from '../Cloud.astro';\n\nText.\n" }, 'fail', { has: ['docs/x.mdx: use .md'] });
expect('an .mdx page that imports only a stylesheet', 'mdx-pages', { 'docs/x.mdx': "import '../home.css';\n\n<div>Text.</div>\n" }, 'fail', { has: ['docs/x.mdx: use .md'] });
expect('no .mdx file at all', 'mdx-pages', { 'docs/index.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- agent links
const docs = { 'docs/contributing/index.md': 'x\n', Justfile: 'default:\n', 'CLAUDE.md': '@AGENTS.md\n' };
expect('no agent files at all', 'agent-links', { 'docs/contributing/index.md': 'x\n' }, 'fail', { has: ['AGENTS.md is missing', 'CLAUDE.md is missing'] });
expect('AGENTS.md is missing', 'agent-links', { ...docs, '.claude/skills/example/SKILL.md': 'See `docs/contributing/`.\n' }, 'fail', { has: ['AGENTS.md is missing'] });
expect('CLAUDE.md is missing', 'agent-links', { 'docs/contributing/index.md': 'x\n', 'AGENTS.md': 'Read `docs/contributing/`.\n' }, 'fail', { has: ['CLAUDE.md is missing'] });
expect('CLAUDE.md does not import AGENTS.md', 'agent-links', { ...docs, 'CLAUDE.md': 'Read AGENTS.md.\n', 'AGENTS.md': 'Read `docs/contributing/`.\n' }, 'fail', { has: ['CLAUDE.md does not import AGENTS.md'] });
expect('every pointer exists', 'agent-links', {
  ...docs,
  'AGENTS.md': 'Read [the guide](docs/contributing/index.md#start), run `just site-check` from the `Justfile`.\nPush `origin/main`, see `docs/requirements/<area>.yaml` and https://example.com/x.\n```\n[not a link](docs/missing.md)\n```\n',
  'CLAUDE.md': '@AGENTS.md\n',
  '.claude/skills/example/SKILL.md': 'See [the guide](../../../docs/contributing/index.md) and `docs/contributing/`.\n',
}, 'pass', { has: ['5 pointers in 3 agent files'] });
expect('a link to a missing file', 'agent-links', { ...docs, 'AGENTS.md': 'Read [this](docs/contributing/gone.md).\n' }, 'fail', { has: ['AGENTS.md:1: docs/contributing/gone.md does not exist'] });
expect('a code path to a missing file', 'agent-links', { ...docs, '.claude/skills/example/SKILL.md': 'Edit `docs/contributing/gone.md`.\n' }, 'fail', { has: ['gone.md does not exist'] });
expect('a subagent file with a missing path', 'agent-links', { ...docs, '.claude/agents/docs.md': 'Edit `docs/contributing/gone.md`.\n' }, 'fail', { has: ['.claude/agents/docs.md:1: docs/contributing/gone.md does not exist'] });
expect('the AGENTS.md of a copied skill names upstream paths', 'agent-links', {
  ...docs,
  'AGENTS.md': 'Read `docs/contributing/`.\n',
  '.claude/skills/upstream/SKILL.md': 'See `docs/contributing/`.\n',
  '.claude/skills/upstream/AGENTS.md': 'Upstream docs: `docs/data/material/gone.md`.\n',
}, 'pass', { has: ['3 pointers in 3 agent files'] });
expect('an agent file with no pointer', 'agent-links', { ...docs, 'AGENTS.md': 'Be careful.\n' }, 'fail', { has: ['empty sweep'] });

// ---- test vectors: a manifest with one request and one answer
const hex = (s) => createHash('sha256').update(s).digest('hex');
const vec = ({ drop = '', extra = {}, digest = hex('subkey'), artifact = hex('bound'), reason } = {}) => {
  const m = {
    handoff: 1, pinned: { root_list: { openpgp: ['pki/root.pgp'] } },
    requests: [{ id: 'ok', type: 'openpgp-subkey', files: ['requests/ok.subkey.pgp', 'requests/ok.proof.json'], expect: 'accept', ...(reason ? { reason } : {}) }],
    responses: [{ id: 'ok', request: 'ok', files: ['responses/ok.bound.pgp', 'responses/ok.result.json'], expect: 'install' }],
  };
  const files = {
    'testdata/set/v1/manifest.json': JSON.stringify(m),
    'testdata/set/v1/pki/root.pgp': 'root',
    'testdata/set/v1/requests/ok.subkey.pgp': 'subkey',
    'testdata/set/v1/requests/ok.proof.json': JSON.stringify({ request_sha256: digest }),
    'testdata/set/v1/responses/ok.bound.pgp': 'bound',
    'testdata/set/v1/responses/ok.result.json': JSON.stringify({ artifacts: [{ name: 'ok.bound.pgp', sha256: artifact }] }),
    ...extra,
  };
  if (drop) delete files[drop];
  return files;
};
expect('vectors that match their manifest', 'vectors', vec(), 'pass', { has: ['5 vector files'] });
expect('a named file that is not tracked', 'vectors', vec({ drop: 'testdata/set/v1/pki/root.pgp' }), 'fail', { has: ['names pki/root.pgp, which git does not track'] });
expect('a file no manifest names', 'vectors', vec({ extra: { 'testdata/set/v1/requests/stray.csr.pem': 'x' } }), 'fail', { has: ['stray.csr.pem: not named'] });
expect('a proof for another request', 'vectors', vec({ digest: hex('other') }), 'fail', { has: ['request_sha256 is not the digest'] });
expect('an artifact digest that differs', 'vectors', vec({ artifact: hex('other') }), 'fail', { has: ['the SHA-256 of ok.bound.pgp'] });
expect('an accepted case with a reason', 'vectors', vec({ reason: 'policy' }), 'fail', { has: ['expects accept with a reason'] });
expect('no vectors at all', 'vectors', { 'README.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- root list vectors: the committed set, copied, then broken one way at a time
const rlDir = join(repo, 'testdata', 'root-list', 'v1');
const rl = Object.fromEntries(execFileSync('git', ['-C', rlDir, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean)
  .map((p) => [`testdata/set/v1/${p}`, readFileSync(join(rlDir, p))]));
const rlWith = (path, edit) => ({ ...rl, [`testdata/set/v1/${path}`]: edit(rl[`testdata/set/v1/${path}`].toString('utf8')) });
expect('a root list set that matches its manifest', 'vectors', rl, 'pass', { has: ['vector files, no errors'] });
expect('a root list changed after signing', 'vectors', rlWith('lists/seq7-a.json', (t) => t.replace('"sequence":7', '"sequence":8')), 'fail', { has: ['list seq7-a: the signature does not verify'] });
expect('a CA bundle with another trust sequence', 'vectors', rlWith('bundles/ca-bundle-7.pem', (t) => t.replace('trust-sequence: 7', 'trust-sequence: 6')), 'fail', { has: ['bundle ca-bundle-7: the first line'] });
expect('a root pin that is not the certificate\'s key', 'vectors', rlWith('manifest.json', (t) => t.replace(/"x509_spki_sha256": "[0-9a-f]{64}"/, `"x509_spki_sha256": "${hex('other')}"`)), 'fail', { has: ['root A: x509_spki_sha256 is not the SPKI hash'] });
expect('a removal authorisation by another root', 'vectors', rlWith('removals/test-root-a.removal.jws', () => rl['testdata/set/v1/removals/test-root-b.removal.jws'].toString('utf8')), 'fail', { has: ['removal A: not a valid removal authorisation of root A'] });
expect('a list whose signers are not the manifest\'s', 'vectors', rlWith('manifest.json', (t) => t.replace('"signers": [\n        "A",\n        "B",\n        "C"\n      ]', '"signers": [\n        "A",\n        "C",\n        "B"\n      ]')), 'fail', { has: ['list seq8-abc: signature 2 is not by its signer C'] });

expect('a list with a date flaw the manifest does not name', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "signed_at-after-clock"', '"flaw": "expires_at-not-13-months"')), 'fail', { has: ['seq7-a-signed-in-the-future: expires_at', 'but the manifest names the flaw expires_at-not-13-months'] });
expect('a case whose list is signed after its clock, with no flaw named', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "signed_at-after-clock"', '"flaw": "expires_at-not-13-months"')), 'fail', { has: ['is signed after the clock of the case'] });
expect('a CA bundle with a flaw it does not have', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "not-a-ca"', '"flaw": "not-signed-by-its-own-key"')), 'fail', { has: ['bundle ca-bundle-7-not-a-ca: every certificate verifies with its own key, but the manifest names the flaw'] });
expect('a lowest sequence that the case does not bear out', 'vectors', rlWith('manifest.json', (t) => t.replace('"min_sequence": 8', '"min_sequence": 7')), 'fail', { has: ['min_sequence 7 against sequence 7'] });
expect('a list whose content has a fault the manifest does not name', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "label-twice"', '"flaw": "pin-twice"')), 'fail', { has: ['its content has the faults [label-twice], and the manifest names [pin-twice]'] });
expect('an empty authorisation the manifest does not name', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "empty-authorisation"', '"flaw": "pin-twice-in-removals"')), 'fail', { has: ['its content has the faults [empty-authorisation]'] });
expect('a flaw the manifest names and no check knows', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "sequence-0"', '"flaw": "sequence-zero"')), 'fail', { has: ['unknown flaw sequence-zero'] });
expect('a list accepted at the held sequence with other bytes', 'vectors', rlWith('manifest.json', (t) => t.replace('"candidate": "seq7-a-and-z"', '"candidate": "seq7-a-without-b"')), 'fail', { has: ["accepted at the held list's sequence"] });
expect('a CA bundle whose flaw its sequence does not bear out', 'vectors', rlWith('manifest.json', (t) => t.replace('"flaw": "extra-certificate"', '"flaw": "wrong-sequence"')), 'fail', { has: ['which the flaw wrong-sequence needs to differ'] });

// ---- SSH CA key list and CRL vectors: the committed sets, copied, then broken one way at a time
const copyOf = (set) => {
  const dir = join(repo, 'testdata', set, 'v1');
  return Object.fromEntries(execFileSync('git', ['-C', dir, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean)
    .map((p) => [`testdata/set/v1/${p}`, readFileSync(join(dir, p))]));
};
const edited = (set, path, edit) => ({ ...set, [`testdata/set/v1/${path}`]: edit(set[`testdata/set/v1/${path}`].toString('utf8')) });
// the hand-off set names lists of the SSH CA key list set, so that set comes along under its own name
const handoff = { ...copyOf('hand-off'), ...Object.fromEntries(Object.entries(copyOf('ssh-ca-keys')).map(([p, v]) => [p.replace('testdata/set/', 'testdata/ssh-ca-keys/'), v])) };
expect('a hand-off set that matches its manifest', 'vectors', handoff, 'pass', { has: ['vector files, no errors'] });
expect('a floor answer from a CA that is not installed', 'vectors', edited(handoff, 'manifest.json', (t) => t.replace('"floor_anchors": [\n      "pki/test-foreign-root.pem"', '"floor_anchors": [\n      "pki/test-root-a.pem"')), 'fail', { has: ['floor response x509-floor-valid: not signed by an anchor of floor_anchors'] });
expect('a case with a configuration the manifest does not have', 'vectors', edited(handoff, 'manifest.json', (t) => t.replace('"config": "development-listed-names"', '"config": "development-listed-name"')), 'fail', { has: ['is no configuration of the manifest'] });
const ssh = copyOf('ssh-ca-keys');
expect('an SSH CA key list set that matches its manifest', 'vectors', ssh, 'pass', { has: ['vector files, no errors'] });
expect('an SSH CA key list changed after signing', 'vectors', edited(ssh, 'lists/seq7-a.json', (t) => t.replace('"sequence":7', '"sequence":8')), 'fail', { has: ['list seq7-a: the signature does not verify'] });
expect('a user keys file that is not the list\'s', 'vectors', edited(ssh, 'files/ssh-user-ca-keys-7.pub', (t) => t.replace('trust-sequence: 7', 'trust-sequence: 6')), 'fail', { has: ['is not the user keys of seq7-a'] });
expect('an SSH CA key list signed after the clock of its case, with no flaw named', 'vectors', edited(ssh, 'manifest.json', (t) => t.replace('"flaw": "signed_at-after-clock"', '"flaw": "expires_at-not-13-months"')), 'fail', { has: ['is signed after the clock of the case', 'but the manifest names the flaw expires_at-not-13-months'] });
const crl = copyOf('crl');
expect('a CRL set that matches its manifest', 'vectors', crl, 'pass', { has: ['vector files, no errors'] });
expect('a CRL whose number is not the manifest\'s', 'vectors', edited(crl, 'manifest.json', (t) => t.replace('"number": 7,', '"number": 9,')), 'fail', { has: ['the CRL number is 7, not 9'] });
expect('a revocation case the CRL does not bear out', 'vectors', edited(crl, 'manifest.json', (t) => t.replace('"expect": "revoked"', '"expect": "good"')), 'fail', { has: ['lists ca-a-1, but the case expects good'] });

// ---- shared terms: the file shared with sluis, its pinned copy and the pages its links name
const termsReal = readFileSync(join(repo, 'docs', 'shared-terms.yaml'), 'utf8');
const termsRealPin = readFileSync(join(repo, 'third_party', 'sluis', 'PIN'), 'utf8');
const termsPublished = readFileSync(join(repo, 'site', 'published.txt'), 'utf8');
const sha = (t) => createHash('sha256').update(t).digest('hex');
const termsFiles = ({ mine = termsReal, copy = mine, pinned = copy, commit = 'pending', pin } = {}) => ({
  'docs/shared-terms.yaml': mine,
  'third_party/sluis/shared-terms.yaml': copy,
  'third_party/sluis/PIN': pin ?? `source: truvity/sluis\ncommit: ${commit}\nsha256: ${sha(pinned)}\n`,
  'site/published.txt': termsPublished,
});
// a changed copy that is also pinned, so that only the shape or the link is judged
const termsShape = (from, to) => {
  const text = termsReal.replace(from, to);
  if (text === termsReal) throw new Error(`selftest: ${JSON.stringify(from)} is not in docs/shared-terms.yaml`);
  return termsFiles({ mine: text });
};
const TERM_FIRST = '  - term: root key\n';
expect('the real shared file, its pinned copy and its pin', 'shared-terms', termsFiles(), 'pass', { has: ['shared terms, no errors'] });
expect('the pin as committed', 'shared-terms', { ...termsFiles(), 'third_party/sluis/PIN': termsRealPin }, 'pass');
expect('a commit id in the pin', 'shared-terms', termsFiles({ commit: 'a'.repeat(40) }), 'pass');
expect('one byte of the file changed, the copy not', 'shared-terms', termsFiles({ mine: termsReal.replace('One key of a root.', 'One kay of a root.'), copy: termsReal, pinned: termsReal }), 'fail', { has: ['differs from the pinned copy', 'first difference at line 32'] });
expect('one byte of the copy changed, the pin not', 'shared-terms', termsFiles({ mine: termsReal, copy: `${termsReal}\n`, pinned: termsReal }), 'fail', { has: ['differs from the pinned copy', 'pins'] });
expect('both files changed, the pin not', 'shared-terms', termsFiles({ mine: `${termsReal}# x\n`, copy: `${termsReal}# x\n`, pinned: termsReal }), 'fail', { has: ['its sha256 is', 'pins'] });
expect('a wrong sha256 in the pin', 'shared-terms', termsFiles({ pin: `source: truvity/sluis\ncommit: pending\nsha256: ${'0'.repeat(64)}\n` }), 'fail', { has: ['its sha256 is', 'pins'] });
expect('a commit that is not a commit id', 'shared-terms', termsFiles({ commit: 'main' }), 'fail', { has: ['commit must be'] });
expect('a pin that names this repository', 'shared-terms', termsFiles({ pin: termsRealPin.replace('truvity/sluis', 'truvity/ritueel') }), 'fail', { has: ['source must be truvity/sluis'] });
expect('a pin with a fourth key', 'shared-terms', termsFiles({ pin: `${termsRealPin}branch: main\n` }), 'fail', { has: ['unknown key branch'] });
expect('a pin without its sha256', 'shared-terms', termsFiles({ pin: 'source: truvity/sluis\ncommit: pending\n' }), 'fail', { has: ['sha256 is missing'] });
expect('no pin', 'shared-terms', { ...termsFiles(), 'third_party/sluis/PIN': undefined }, 'fail', { has: ['PIN is missing'] });
expect('no pinned copy', 'shared-terms', { ...termsFiles(), 'third_party/sluis/shared-terms.yaml': undefined }, 'fail', { has: ['shared-terms.yaml is missing'] });
expect('a term listed twice', 'shared-terms', termsFiles({ mine: `${termsReal}\n  - term: root key\n    definition: "Again."\n    owner: ritueel\n    status: decided\n` }), 'fail', { has: ['the term is listed twice'] });
expect('an owner that is neither product', 'shared-terms', termsShape('owner: sluis', 'owner: acme'), 'fail', { has: ['owner must be one of'] });
expect('a status that is neither decided nor proposed', 'shared-terms', termsShape('status: proposed', 'status: maybe'), 'fail', { has: ['status must be one of'] });
expect('a field that is not known', 'shared-terms', termsShape(TERM_FIRST, `${TERM_FIRST}    mood: calm\n`), 'fail', { has: ['unknown field mood'] });
expect('a not that is a string, not a list', 'shared-terms', termsShape('    not:\n      - "a root, which is built from one or more root keys"\n', '    not: "a root"\n'), 'fail', { has: ['not must be a non-empty list of strings'] });
expect('a see that is a repository path', 'shared-terms', termsShape('see: ["https://ritueel.id/learn/revoke/"]', 'see: ["docs/learn/revoke.md"]'), 'fail', { has: ['must be an absolute URL', 'not a repository path'] });
expect('a see on a site that is not one of the two', 'shared-terms', termsShape('see: ["https://ritueel.id/learn/revoke/"]', 'see: ["https://example.com/learn/revoke/"]'), 'fail', { has: ['must be an absolute URL'] });
expect('a see that names a page the site does not publish', 'shared-terms', termsShape('https://ritueel.id/learn/revoke/', 'https://ritueel.id/learn/no-such-page/'), 'fail', { has: ['is not a page that site/published.txt publishes'] });
expect('a see to a page that is a record, not published', 'shared-terms', termsShape('https://ritueel.id/learn/revoke/', 'https://ritueel.id/decisions/0005-a-ceremony/'), 'fail', { has: ['is not a page that site/published.txt publishes'] });
expect('a published page without the trailing slash', 'shared-terms', termsShape('https://ritueel.id/learn/revoke/', 'https://ritueel.id/learn/revoke'), 'fail', { has: ['trailing slash'] });
expect('a published page with an anchor', 'shared-terms', termsShape('https://ritueel.id/learn/revoke/', 'https://ritueel.id/learn/revoke/#anything'), 'pass');
expect('a page of sluis.id is not looked up here', 'shared-terms', termsShape('https://sluis.id/decisions/0027-the-console/', 'https://sluis.id/decisions/9999-anything/'), 'pass');
expect('a schema that is not 1', 'shared-terms', termsShape('schema: 1', 'schema: 2'), 'fail', { has: ['schema must be 1'] });
expect('a line the reader does not know', 'shared-terms', termsShape(TERM_FIRST, `${TERM_FIRST}    definition: [a, b]\n`), 'fail', { has: ['double-quoted strings only'] });

rmSync(scratch, { recursive: true, force: true });
if (failures) {
  console.error(`selftest: ${failures} of ${cases} cases failed`);
  process.exit(1);
}
console.log(`selftest: ${cases} cases, all as expected`);
