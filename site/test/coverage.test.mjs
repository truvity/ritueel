import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { coverageProblems } from '../lib/coverage.mjs';

const legend = {
  kind: 'legend',
  id: 'states',
  advice: [{ id: 'recommended' }, { id: 'not-recommended' }],
  states: [{ id: 'built' }, { id: 'planned' }, { id: 'tool-planned' }, { id: 'rejected' }],
};
const aCase = (extra = {}) => ({
  kind: 'case',
  id: 'case-1',
  number: 1,
  rows: [{ way: 'A', state: 'built' }, { way: 'B', state: 'planned', milestone: 'M4' }],
  ...extra,
});
const problems = (rows, extra = {}) => coverageProblems([legend, aCase({ rows, ...extra })]).join('\n');

test('a good file has no problem', () => {
  assert.deepEqual(coverageProblems([legend, aCase()]), []);
});

test('a state or an advice that the legend lacks is a problem', () => {
  assert.match(problems([{ way: 'A', state: 'done' }]), /state "done"/);
  assert.match(problems([{ way: 'A', state: 'built', advice: 'good' }]), /advice "good"/);
});

test('a way that is not recommended shows advice only, and every other way has a state', () => {
  assert.deepEqual(coverageProblems([legend, aCase({ rows: [{ way: 'A', advice: 'not-recommended' }] })]), []);
  assert.match(problems([{ way: 'A', advice: 'not-recommended', state: 'built' }]), /not recommended and must have no state/);
  assert.match(problems([{ way: 'A' }]), /has no state/);
  assert.match(problems([{ way: 'A', advice: 'recommended' }]), /has no state/);
});

test('a way that is planned, or explained with a tool planned, names a milestone', () => {
  assert.match(problems([{ way: 'A', state: 'planned' }]), /must name a milestone/);
  assert.match(problems([{ way: 'A', state: 'tool-planned' }]), /must name a milestone/);
  assert.deepEqual(coverageProblems([legend, aCase({ rows: [{ way: 'A', state: 'tool-planned', milestone: 'M4, M5' }, { way: 'B', state: 'planned', milestone: 'after the first version (proposed)' }] })]), []);
});

test('a milestone is M0 to M7 or "after the first version", and only a planned way has one', () => {
  assert.match(problems([{ way: 'A', state: 'planned', milestone: 'soon' }]), /milestone "soon"/);
  assert.match(problems([{ way: 'A', state: 'planned', milestone: 'M8' }]), /milestone "M8"/);
  assert.match(problems([{ way: 'A', state: 'built', milestone: 'M4' }]), /neither planned nor explained/);
});

test('a way twice in one table, an empty table and a wrong id are problems', () => {
  assert.match(problems([{ way: 'A', state: 'built' }, { way: 'A', state: 'built' }]), /twice/);
  assert.match(problems([]), /no row/);
  assert.match(coverageProblems([legend, aCase({ id: 'case-9' })]).join(), /anchor/);
});

test('a page of a case, when named, is a line of site/published.txt', () => {
  assert.match(coverageProblems([legend, aCase({ page: '/pki/' })], { published: [] }).join(), /published\.txt/);
  assert.deepEqual(coverageProblems([legend, aCase({ page: '/pki/' })], { published: ['pki.md'] }), []);
});

test('a file with no legend, two legends or no case is a problem', () => {
  assert.match(coverageProblems([aCase()]).join(), /exactly one legend/);
  assert.match(coverageProblems([legend, legend, aCase()]).join(), /exactly one legend/);
  assert.match(coverageProblems([legend]).join(), /no case/);
});

test('docs/coverage.yaml: the real file, read as plain text, holds the legend and five tables that follow the rules', () => {
  // The YAML package is only a transitive dependency of the site, so this test reads the file as
  // text: the build (src/pages/status.astro) parses it and runs coverageProblems on it.
  const text = readFileSync(new URL('../../docs/coverage.yaml', import.meta.url), 'utf8');
  assert.equal((text.match(/^  kind: case$/gm) ?? []).length, 5);
  const stateIds = new Set([...text.split(/^  advice:$/m)[1].split(/^  states:$/m)[1].split(/^- id: case-1$/m)[0].matchAll(/^    - id: ([a-z-]+)$/gm)].map((m) => m[1]));
  assert.equal(stateIds.size, 6, 'the legend has six states');
  const adviceIds = new Set([...text.split(/^  advice:$/m)[1].split(/^  states:$/m)[0].matchAll(/^    - id: ([a-z-]+)$/gm)].map((m) => m[1]));
  assert.equal(adviceIds.size, 4, 'the legend has four advice words');
  // The rows of the cases, as blocks of lines.
  const rows = text.split(/^    - way: /m).slice(1).map((b) => ({
    way: b.split('\n')[0],
    state: /^      state: (\S+)$/m.exec(b)?.[1],
    advice: /^      advice: (\S+)$/m.exec(b)?.[1],
    milestone: /^      milestone: (.+)$/m.exec(b)?.[1],
    why: /^      why: (.*)$/m.exec(b)?.[1],
  }));
  assert.ok(rows.length >= 35);
  for (const r of rows) {
    assert.ok(r.why && r.why !== '""', `${r.way}: no reason`);
    if (r.advice) assert.ok(adviceIds.has(r.advice), `${r.way}: the advice ${r.advice} is not in the legend`);
    if (r.advice === 'not-recommended') assert.equal(r.state, undefined, `${r.way}: not recommended, so no state`);
    else assert.ok(r.state && stateIds.has(r.state), `${r.way}: a state of the legend is needed`);
    if (r.state === 'planned' || r.state === 'tool-planned') assert.ok(r.milestone, `${r.way}: a planned way names its milestone`);
  }
  assert.doesNotMatch(text, /^\s+shape:/m, 'the field shape is dropped');
});
