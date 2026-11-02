// The issues and milestones of this repository, read at build time over the GitHub REST API for
// the project status page (src/pages/status.astro). REST rather than GraphQL, because the
// GraphQL budget is shared by everyone who uses the organisation's token.
//
// The token is the build's own, in GITHUB_TOKEN (or GH_TOKEN). CI hands the build the
// workflow's read-only token; a local build has none unless the person sets one. Without a
// token, or when GitHub does not answer, the result says so (`available: false` with a reason)
// and the page still builds from the repository alone. The reason names no token.
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
const MAX_PAGES = 10;
const USER_AGENT = 'ritueel-site-build';

async function pages(path: string, token: string): Promise<any[]> {
  const out: any[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await fetch(`https://api.github.com/repos/${REPO}/${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': USER_AGENT,
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

let cached: Promise<Github> | undefined;

// Read once per build; the home page and the status page share the answer.
export function readGithub(): Promise<Github> {
  cached ??= read();
  return cached;
}

async function read(): Promise<Github> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.log('status: no GITHUB_TOKEN in this build; the status page shows no issue figures');
    return { available: false, reason: 'this build has no GitHub token' };
  }
  try {
    const milestones = (await pages('milestones?state=all', token)).map((m) => ({
      title: String(m.title),
      description: typeof m.description === 'string' && m.description ? m.description : null,
    }));
    // Pull requests come back in the same list, marked by `pull_request`; bots (the dependency
    // dashboard) are not project work. Both stay out of the counts.
    const issues = (await pages('issues?state=all&sort=created&direction=asc', token))
      .filter((i) => !i.pull_request && i.user?.type !== 'Bot')
      .map((i): GhIssue => ({
        number: Number(i.number),
        title: String(i.title),
        open: i.state === 'open',
        milestone: i.milestone?.title ?? null,
      }))
      .sort((a, b) => a.number - b.number);
    console.log(`status: read ${issues.length} issues and ${milestones.length} milestones from GitHub`);
    return { available: true, milestones, issues };
  } catch (e) {
    const reason = e instanceof Error ? e.message : 'GitHub could not be read';
    console.log(`status: GitHub could not be read (${reason}); the status page shows no issue figures`);
    return { available: false, reason };
  }
}
