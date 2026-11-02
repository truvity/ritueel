// The issues and milestones of this repository over the GitHub REST API, as plain data. One
// reader for the two places that need them: the build (src/lib-github.ts, with the build's own
// token) and the Worker's refresh (src/worker/status.ts, with an installation token). REST rather
// than GraphQL, because the GraphQL budget is shared by everyone who uses the organisation's token.
//
// It imports nothing and touches no environment: the caller brings the token. It runs in Node
// (the build, site/scripts/check-worker.mjs) and in the Worker alike.
export const REPO = 'truvity/ritueel';

export interface GhIssue {
  number: number;
  title: string;
  open: boolean;
  // The title of the issue's GitHub milestone, or null.
  milestone: string | null;
}

export interface GhMilestone {
  title: string;
  description: string | null;
}

export type Github =
  | { available: true; milestones: GhMilestone[]; issues: GhIssue[] }
  | { available: false; reason: string };

// At most this many pages of 100 items (issues and pull requests share the list); more than
// that fails closed with a reason instead of a silently short count.
export const MAX_PAGES = 10;

async function pages(path: string, token: string, userAgent: string): Promise<any[]> {
  const out: any[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await fetch(`https://api.github.com/repos/${REPO}/${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': userAgent,
        'x-github-api-version': '2022-11-28',
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) throw new Error(`GitHub answered HTTP ${res.status} for ${path.split('?')[0]}`);
    const items = (await res.json()) as any[];
    out.push(...items);
    if (items.length < 100) return out;
  }
  throw new Error(`more than ${MAX_PAGES * 100} items in ${path.split('?')[0]}`);
}

// The milestones and the issues, or a thrown error whose message names no token. Pull requests
// come back in the same list, marked by `pull_request`; bots (the dependency dashboard) are not
// project work. Both stay out of the counts.
export async function readIssues(token: string, userAgent: string): Promise<{ milestones: GhMilestone[]; issues: GhIssue[] }> {
  const milestones = (await pages('milestones?state=all', token, userAgent)).map((m) => ({
    title: String(m.title),
    description: typeof m.description === 'string' && m.description ? m.description : null,
  }));
  const issues = (await pages('issues?state=all&sort=created&direction=asc', token, userAgent))
    .filter((i) => !i.pull_request && i.user?.type !== 'Bot')
    .map((i): GhIssue => ({
      number: Number(i.number),
      title: String(i.title),
      open: i.state === 'open',
      milestone: i.milestone?.title ?? null,
    }))
    .sort((a, b) => a.number - b.number);
  return { milestones, issues };
}
