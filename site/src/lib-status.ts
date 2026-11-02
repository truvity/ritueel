// The facts of the home page's status line and of the project status page (/status/), both
// counted from the repository at build time so that they cannot drift apart:
//
// - decision records are docs/decisions/NNNN-*.md without the template, read through the same
//   collection as the decisions index (src/lib-decisions.ts), with the status each record states;
// - reference pages are docs/reference/*.md without the index;
// - code is the lines of every Go file outside site/ and node_modules (the product is Go; the
//   scripts under tools/ are repository checks and are not counted). Zero Go files is zero
//   lines, and the line says so;
// - the milestones are the rows of the table in docs/roadmap.md, which names M1 to M4, what
//   each delivers and, for the page, the order. GitHub (src/lib-github.ts) adds the issues.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { decisionFacts, listDecisions } from './lib-decisions';
import type { GhIssue, Github } from './lib-github';

// The build runs in site/; the repository root is the first directory above it that has docs/.
let root = process.cwd();
while (!existsSync(join(root, 'docs', 'decisions')) && join(root, '..') !== root) root = join(root, '..');

export const BUILT_AT = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

const countFiles = (dir: string, keep: (name: string) => boolean): number =>
  readdirSync(join(root, dir)).filter((name) => name.endsWith('.md') && keep(name)).length;

const SKIP = new Set(['.git', 'node_modules', 'site', 'dist']);
const goLines = (dir: string): number =>
  readdirSync(dir).reduce((sum, name) => {
    if (SKIP.has(name)) return sum;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sum + goLines(path);
    return name.endsWith('.go') ? sum + readFileSync(path, 'utf8').split('\n').length : sum;
  }, 0);

export interface DesignFacts {
  records: number;
  accepted: number;
  // Accepted records that a later record amended; they are part of `accepted`.
  amended: number;
  proposed: number;
  // Any other status a record states (Rejected, Superseded by NNNN), by text.
  other: { status: string; count: number }[];
  reference: number;
  code: number;
}

export async function designFacts(): Promise<DesignFacts> {
  const records = (await listDecisions()).map(decisionFacts);
  const other = new Map<string, number>();
  for (const r of records) {
    if (!r.status.startsWith('Accepted') && r.status !== 'Proposed') other.set(r.status, (other.get(r.status) ?? 0) + 1);
  }
  return {
    records: records.length,
    accepted: records.filter((r) => r.status.startsWith('Accepted')).length,
    amended: records.filter((r) => r.status.startsWith('Accepted') && r.status.includes('amended by')).length,
    proposed: records.filter((r) => r.status === 'Proposed').length,
    other: [...other].map(([status, count]) => ({ status, count })),
    reference: countFiles('docs/reference', (name) => name !== 'index.md'),
    code: goLines(root),
  };
}

// The line the home page and the status page both show.
export const designLine = (f: DesignFacts): string =>
  `Design: ${f.records} decision records, ${f.reference} reference pages. Code: ${f.code} lines.`;

export interface RoadmapMilestone {
  // "M1", "M2", ...
  key: string;
  name: string;
  delivers: string;
}

// Markup out of a table cell: [text](url) becomes text, and bold and code marks go.
const plain = (cell: string): string =>
  cell.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/\*\*|`/g, '').replace(/\s+/g, ' ').trim();

// The rows `| **M1: name** | delivers | work items |` of docs/roadmap.md. A roadmap with no such
// row fails the build: an empty sweep is not a pass.
export function roadmapMilestones(): RoadmapMilestone[] {
  const text = readFileSync(join(root, 'docs', 'roadmap.md'), 'utf8');
  const rows: RoadmapMilestone[] = [];
  for (const line of text.split('\n')) {
    const m = /^\|\s*\*\*(M\d+):\s*([^*]+?)\*\*\s*\|([^|]*)\|/.exec(line);
    if (m) rows.push({ key: m[1], name: m[2].trim(), delivers: plain(m[3]) });
  }
  if (rows.length === 0) throw new Error('docs/roadmap.md has no milestone row "| **M1: name** | ..."');
  return rows;
}

export interface MilestoneRow {
  key: string;
  name: string;
  delivers: string;
  // The issues of the milestone, in number order; null when GitHub was not read.
  issues: GhIssue[] | null;
  open: number | null;
  closed: number | null;
  current: boolean;
  // Not a row of the roadmap: the issues with no milestone.
  roadmap: boolean;
}

const keyOf = (title: string): string => /^(M\d+)\b/.exec(title)?.[1] ?? title;
export const NO_MILESTONE = 'No milestone';

// One row per roadmap milestone in the roadmap's order, then the GitHub milestones the roadmap
// does not name, then the issues that have none. A pure function of its inputs. The current
// milestone is the first one with an open issue.
export function milestoneRows(roadmap: RoadmapMilestone[], github: Github): MilestoneRow[] {
  const rows: MilestoneRow[] = roadmap.map((m) => ({ ...m, issues: null, open: null, closed: null, current: false, roadmap: true }));
  if (github.available) {
    for (const m of github.milestones) {
      if (!rows.some((r) => r.key === keyOf(m.title))) {
        rows.push({ key: keyOf(m.title), name: m.title, delivers: m.description ?? '', issues: null, open: null, closed: null, current: false, roadmap: false });
      }
    }
    rows.push({ key: NO_MILESTONE, name: NO_MILESTONE, delivers: '', issues: null, open: null, closed: null, current: false, roadmap: false });
    for (const r of rows) r.issues = [];
    for (const issue of github.issues) {
      const key = issue.milestone === null ? NO_MILESTONE : keyOf(issue.milestone);
      (rows.find((r) => r.key === key) ?? rows[rows.length - 1]).issues!.push(issue);
    }
    for (const r of rows) {
      r.open = r.issues!.filter((i) => i.open).length;
      r.closed = r.issues!.length - r.open;
    }
    // A catch-all row with nothing in it is not shown.
    const last = rows[rows.length - 1];
    if (last.issues!.length === 0) rows.pop();
    const current = rows.find((r) => r.roadmap && (r.open ?? 0) > 0);
    if (current) current.current = true;
  }
  return rows;
}

// The names the roadmap and GitHub give the same milestone, when they differ. Logged at build
// so that the bookkeeping pass can fix one of them ("the roadmap matches the board").
export function milestoneNameDrift(roadmap: RoadmapMilestone[], github: Github): string[] {
  if (!github.available) return [];
  return roadmap.flatMap((m) => {
    const gh = github.milestones.find((g) => keyOf(g.title) === m.key);
    return !gh ? [`${m.key} has no GitHub milestone`] : gh.title !== `${m.key}: ${m.name}` ? [`${m.key}: the roadmap says "${m.name}", GitHub says "${gh.title}"`] : [];
  });
}
