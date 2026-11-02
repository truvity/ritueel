// The issues and milestones of this repository, read at build time for the snapshot of the
// project status page (src/pages/status.astro). The reading itself is src/lib-github-rest.ts, which the
// Worker's live refresh uses too.
//
// The token is the build's own, in GITHUB_TOKEN (or GH_TOKEN). CI hands the build the
// workflow's read-only token; a local build has none unless the person sets one. Without a
// token, or when GitHub does not answer, the result says so (`available: false` with a reason)
// and the page still builds from the repository alone. The reason names no token.
import { readIssues, type Github } from './lib-github-rest.ts';

export { REPO } from './lib-github-rest.ts';
export type { GhIssue, GhMilestone, Github } from './lib-github-rest.ts';

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
    const { milestones, issues } = await readIssues(token, 'ritueel-site-build');
    console.log(`status: read ${issues.length} issues and ${milestones.length} milestones from GitHub`);
    return { available: true, milestones, issues };
  } catch (e) {
    const reason = e instanceof Error ? e.message : 'GitHub could not be read';
    console.log(`status: GitHub could not be read (${reason}); the status page shows no issue figures`);
    return { available: false, reason };
  }
}
