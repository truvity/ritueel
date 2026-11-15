// The cross-checks of docs/coverage.yaml, the one data file behind the tables of the status page.
// A plain function with no dependency (like lib/published.mjs), so that `node --test` runs it
// with no install. src/content.config.ts checks the shape of each entry; this checks what only
// the whole file can show. src/pages/status.astro calls it at the build and throws on a problem.

// The states of a way that ritueel plans to build: such a way names the milestone that builds it.
export const PLANNED_STATES = ['planned', 'tool-planned'];

// "M4", "M4, M5", "after the first version", "after the first version (proposed)".
const MILESTONE = /^(M[0-7](, M[0-7])*|after the first version( \(proposed\))?)$/;

/** The problems of a list of entries: the legend and the cases, as the loader gives them. */
export function coverageProblems(entries, { published = [] } = {}) {
  const problems = [];
  const legends = entries.filter((e) => e.kind === 'legend');
  const cases = entries.filter((e) => e.kind === 'case');
  if (legends.length !== 1) problems.push(`the file needs exactly one legend, it has ${legends.length}`);
  if (cases.length === 0) problems.push('the file holds no case');
  const states = new Set((legends[0]?.states ?? []).map((s) => s.id));
  const advice = new Set((legends[0]?.advice ?? []).map((a) => a.id));
  const seen = new Set();
  for (const c of cases) {
    if (seen.has(c.number)) problems.push(`${c.id}: the number ${c.number} is used twice`);
    seen.add(c.number);
    if (c.id !== `case-${c.number}`) problems.push(`${c.id}: the id must be case-${c.number}, which is the anchor /status/#case-${c.number}`);
    if (c.rows.length === 0) problems.push(`${c.id}: no row`);
    const ways = new Set();
    for (const r of c.rows) {
      if (r.state !== undefined && !states.has(r.state)) problems.push(`${c.id}: the way "${r.way}" has the state "${r.state}", which the legend does not have`);
      if (r.advice !== undefined && !advice.has(r.advice)) problems.push(`${c.id}: the way "${r.way}" has the advice "${r.advice}", which the legend does not have`);
      // A way that is not recommended shows advice only: a state mark beside it would read as "good".
      if (r.advice === 'not-recommended' && r.state !== undefined) problems.push(`${c.id}: the way "${r.way}" is not recommended and must have no state`);
      // Every other way has one state.
      if (r.advice !== 'not-recommended' && r.state === undefined) problems.push(`${c.id}: the way "${r.way}" has no state`);
      // A way that is planned, or explained with a tool planned, names its milestone.
      if (PLANNED_STATES.includes(r.state) && r.milestone === undefined) problems.push(`${c.id}: the way "${r.way}" is ${r.state} and must name a milestone`);
      if (r.milestone !== undefined && !PLANNED_STATES.includes(r.state)) problems.push(`${c.id}: the way "${r.way}" names a milestone but is neither planned nor explained with a tool planned`);
      if (r.milestone !== undefined && !MILESTONE.test(r.milestone)) problems.push(`${c.id}: the way "${r.way}" has the milestone "${r.milestone}", which is not M0 to M7 or "after the first version"`);
      if (ways.has(r.way)) problems.push(`${c.id}: the way "${r.way}" is in the table twice`);
      ways.add(r.way);
    }
    // The page of a case is optional until the case pages exist; when it is named, it is published.
    if (c.page !== undefined) {
      const file = c.page.replace(/^\/|\/$/g, '') + '.md';
      if (!published.includes(file)) problems.push(`${c.id}: the page ${c.page} is not a line of site/published.txt (${file})`);
    }
  }
  return problems;
}
