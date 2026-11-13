// The facts of the project status page (/status/), both counted from the repository at build time
// so that they cannot drift apart:
//
// - decision records are docs/decisions/NNNN-*.md without the template, read through the same
//   collection as src/lib-decisions.ts, with the status each record states (the records have no page);
// - reference pages are docs/reference/*.md without the index;
// - code is the lines of every Go file outside site/ and node_modules (the product is Go; the
//   small programs under tools/, such as tools/elfcheck, are counted). Zero Go files is zero
//   lines, and the line says so;
// - the milestones are the rows of the table in docs/roadmap.md, which names M0 to M7, what
//   each delivers and, for the page, the order. GitHub (src/lib-github.ts) adds the issues.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decisionFacts, listDecisions } from './lib-decisions';
import type { RoadmapMilestone } from './lib-milestones.ts';

// The build runs in site/; the repository root is the first directory above it that has docs/.
let root = process.cwd();
while (!existsSync(join(root, 'docs', 'decisions')) && join(root, '..') !== root) root = join(root, '..');

export const BUILT_AT = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

const countFiles = (dir: string, keep: (name: string) => boolean): number =>
  readdirSync(join(root, dir)).filter((name) => name.endsWith('.md') && keep(name)).length;

const SKIP = new Set(['.git', 'node_modules', 'site', 'dist']);
// Directory entries carry their own type, so no file is checked and then read.
const goLines = (dir: string): number =>
  readdirSync(dir, { withFileTypes: true }).reduce((sum, entry) => {
    if (SKIP.has(entry.name)) return sum;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sum + goLines(path);
    return entry.isFile() && entry.name.endsWith('.go') ? sum + readFileSync(path, 'utf8').split('\n').length : sum;
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
