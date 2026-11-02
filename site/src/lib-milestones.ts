// The milestones of the project status page as pure data: the roadmap's rows joined with the
// issues of GitHub. No file is read here, so the build (src/lib-status.ts reads the roadmap) and
// the Worker (src/worker/status.ts reads the roadmap as the build published it, /data/status.json)
// place the issues with the same code.
import type { GhIssue, Github } from './lib-github-rest.ts';

export interface RoadmapMilestone {
  // "M1", "M2", ...
  key: string;
  name: string;
  delivers: string;
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
