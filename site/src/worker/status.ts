// The live status document in KV, and the view the status API and the status page's live
// blocks make of it.
//
// One document, `board`: the issues and milestones of the repository and the latest workflow
// run of each workflow on `main`, refreshed by the cron every 15 minutes (there is no webhook:
// the refresh is the only writer). The design figures stay build-time facts; the Worker reads the
// roadmap's rows from /data/status.json of its own deployment, written by the build.
//
// The Free plan allows 1,000 KV writes a day for the whole account. A refresh writes only when the
// content changed, or when the stored copy is more than an hour old (so its "as of" time stays
// honest), and the document stops writing for the rest of the UTC day at its cap. The cron runs 96
// times a day, so the cap is a guard and not a limit that is reached.
import { readIssues, type GhIssue, type GhMilestone } from '../lib-github-rest.ts';
import { milestoneRows, type RoadmapMilestone } from '../lib-milestones.ts';
import { liveFragment, type Run } from '../lib-status-html.ts';
import { installationToken, mainRuns, USER_AGENT, type AppSecrets } from './github.ts';

// The part of a KV namespace binding the Worker uses.
export interface KV {
  get<T>(key: string, type: 'json'): Promise<T | null>;
  put(key: string, value: string): Promise<void>;
}

export interface Env extends AppSecrets {
  STATUS: KV;
  ASSETS: { fetch(request: Request | string): Promise<Response> };
}

export const BOARD_KEY = 'board';
export const BOARD_WRITE_CAP = 100;
const HEARTBEAT_MS = 60 * 60_000;

interface Writes { day: string; n: number }
export interface BoardDoc {
  schema: 1;
  checkedAt: string;
  changedAt: string;
  hash: string;
  writes: Writes;
  runsEtag: string | null;
  milestones: GhMilestone[];
  issues: GhIssue[];
  runs: Run[] | null;
}

const isoNow = (now: number) => new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z');
const dayOf = (now: number) => new Date(now).toISOString().slice(0, 10);
const writesToday = (w: Writes | undefined, now: number) => (w && w.day === dayOf(now) ? w.n : 0);

export async function sha256(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Whether a refresh that produced `hash` must write, and why. Pure, for the tests.
export function writeDecision(prev: Pick<BoardDoc, 'hash' | 'checkedAt' | 'writes'> | null, hash: string, now: number):
  'first' | 'changed' | 'heartbeat' | 'unchanged' | 'over budget' {
  const why = !prev ? 'first' : prev.hash !== hash ? 'changed' : now - Date.parse(prev.checkedAt) > HEARTBEAT_MS ? 'heartbeat' : 'unchanged';
  if (why === 'unchanged') return why;
  return writesToday(prev?.writes, now) >= BOARD_WRITE_CAP ? 'over budget' : why;
}

// Read the issues and the runs on `main` from GitHub, and write the document if it must.
// Returns one line for the log; never throws, and never logs a secret.
export async function refresh(env: Env, cause: string, now = Date.now()): Promise<string> {
  try {
    const prev = await env.STATUS.get<BoardDoc>(BOARD_KEY, 'json');
    const token = await installationToken(env);
    const { milestones, issues } = await readIssues(token, USER_AGENT);
    let runs = prev?.runs ?? null;
    let runsEtag = prev?.runsEtag ?? null;
    try {
      const r = await mainRuns(token, prev?.runs ? runsEtag : null);
      if (r.runs) {
        runs = r.runs;
        runsEtag = r.etag;
      }
    } catch (e) {
      console.log(`status refresh (${cause}): workflow runs not read: ${e instanceof Error ? e.message : e}`);
    }
    const hash = await sha256(JSON.stringify({ milestones, issues, runs }));
    const decision = writeDecision(prev, hash, now);
    if (decision === 'unchanged' || decision === 'over budget') return `status refresh (${cause}): ${decision}`;
    const doc: BoardDoc = {
      schema: 1,
      checkedAt: isoNow(now),
      changedAt: decision === 'heartbeat' && prev ? prev.changedAt : isoNow(now),
      hash,
      writes: { day: dayOf(now), n: writesToday(prev?.writes, now) + 1 },
      runsEtag,
      milestones,
      issues,
      runs,
    };
    await env.STATUS.put(BOARD_KEY, JSON.stringify(doc));
    return `status refresh (${cause}): wrote (${decision}, ${issues.length} issues, write ${doc.writes.n} today)`;
  } catch (e) {
    return `status refresh (${cause}): failed: ${e instanceof Error ? e.message : e}`;
  }
}

export interface Live {
  asOf: string;
  changedAt: string;
  repoBuiltAt: string;
  rows: ReturnType<typeof milestoneRows>;
  runs: Run[] | null;
}

// The live view: the document in KV joined with the /data/status.json of this deployment, read
// from the static assets (no Worker request, no KV read). Null when KV holds no document yet.
export async function liveStatus(env: Env, origin: string): Promise<Live | null> {
  const doc = await env.STATUS.get<BoardDoc>(BOARD_KEY, 'json');
  if (!doc) return null;
  const res = await env.ASSETS.fetch(new Request(new URL('/data/status.json', origin)));
  if (!res.ok) throw new Error(`the static assets answered HTTP ${res.status} for /data/status.json`);
  const built = (await res.json()) as { builtAt: string; roadmap: RoadmapMilestone[] };
  return {
    asOf: doc.checkedAt,
    changedAt: doc.changedAt,
    repoBuiltAt: built.builtAt,
    rows: milestoneRows(built.roadmap, { available: true, milestones: doc.milestones, issues: doc.issues }),
    runs: doc.runs,
  };
}

// The HTML of /api/status/live/.
export const liveHtml = (live: Live) => liveFragment({ rows: live.rows, mode: 'live', asOf: live.asOf, available: true, runs: live.runs });

// The JSON of /api/status: per milestone the issue figures and the open issues, and the latest
// run of each workflow on `main`.
export function statusJson(live: Live) {
  return {
    schema: 1,
    asOf: live.asOf,
    changedAt: live.changedAt,
    repoBuiltAt: live.repoBuiltAt,
    source: { repository: 'https://github.com/truvity/ritueel', milestones: '/data/status.json' },
    milestones: live.rows.map((r) => ({
      key: r.key,
      name: r.name,
      roadmap: r.roadmap,
      current: r.current,
      open: r.open,
      closed: r.closed,
      openIssues: (r.issues ?? []).filter((i) => i.open).map(({ number, title }) => ({ number, title })),
    })),
    ci: { main: live.runs },
  };
}
