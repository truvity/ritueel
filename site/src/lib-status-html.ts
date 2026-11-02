// The live parts of the project status page as HTML: the milestone cards, the issues by
// milestone and the checks on `main`. One renderer for both places they are drawn:
// - at build time, src/pages/status.astro puts the snapshot into the page;
// - in the Worker, /api/status/live/ draws the same from the data in KV, and the page's script
//   (src/scripts/status-live.ts) swaps each part in for its snapshot.
// The Worker is a plain module bundled by Wrangler, not an Astro server, so this is a function
// of its inputs with no Astro component in it. It imports nothing at run time:
// site/scripts/check-worker.mjs runs it in Node. The styles are src/styles/status.css.
import type { MilestoneRow } from './lib-milestones.ts';

export const PARTS = ['cards', 'issues', 'checks'] as const;
export type Part = (typeof PARTS)[number];

export interface Run {
  workflow: string;
  status: string;
  conclusion: string | null;
  url: string;
  sha: string;
  at: string;
}

export interface PartsInput {
  rows: MilestoneRow[];
  mode: 'snapshot' | 'live';
  // When the data is as of, ISO 8601 UTC.
  asOf: string;
  // Whether the issues were read; the snapshot of a build without a token has none.
  available: boolean;
  // The latest run of each workflow on `main`; only the live block has them.
  runs?: Run[] | null;
}

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (v: unknown) => String(v).replace(/[&<>"']/g, (c) => ESC[c]);
const cls = (...names: (string | false | null | undefined)[]) => names.filter(Boolean).join(' ');

export const utc = (iso: string) => iso.replace('T', ' ').replace(/:\d{2}(\.\d+)?Z$/, ' UTC');
const REPO_URL = 'https://github.com/truvity/ritueel';
const shortSha = (sha: string) => (/^[0-9a-f]{7,40}$/.test(sha) ? sha.slice(0, 7) : '');
// A link GitHub gave: only an address of this repository is drawn as a link.
const ownUrl = (url: string) => (url.startsWith(`${REPO_URL}/`) ? url : '#');
const percent = (a: number, b: number) => (b ? Math.round((100 * a) / b) : 0);
const runState = (r: Run) => (r.status === 'completed' ? (r.conclusion ?? 'completed') : r.status.replace(/_/g, ' '));
const runFailed = (r: Run) => r.status === 'completed' && !['success', 'skipped', 'neutral'].includes(r.conclusion ?? '');

const when = (input: PartsInput) =>
  `<p class="ps-asof-line"><span class="ps-tag ps-tag-${input.mode === 'live' ? 'live' : 'build'}">${input.mode === 'live' ? 'live' : 'snapshot'}</span> `
  + `as of ${esc(utc(input.asOf))}</p>`;

function cards(input: PartsInput): string {
  const items = input.rows.filter((r) => r.roadmap).map((r) => {
    const body = r.issues
      ? `<div class="ps-bar" aria-hidden="true"><span style="width: ${percent(r.closed!, r.issues.length)}%"></span></div>`
        + `<p class="ps-v">${r.closed} of ${r.issues.length} issues closed</p>`
      : '<p class="ps-v ps-na" title="Not available in this build">— issues closed</p>';
    return `<article class="${cls('ps-card', r.current && 'ps-current')}" data-milestone="${esc(r.key)}" aria-labelledby="card-${esc(r.key)}">`
      + `<p class="ps-card-k">${esc(r.key)}${r.current ? ' · <strong>current</strong>' : ''}</p>`
      + `<p class="ps-card-n" id="card-${esc(r.key)}">${esc(r.name)}</p>`
      + `<p class="ps-delivers">${esc(r.delivers)}</p>${body}</article>`;
  });
  return `${when(input)}<div class="ps-cards not-content" data-count="${items.length}">${items.join('')}</div>`;
}

function issues(input: PartsInput): string {
  if (!input.available) return '<p class="ps-none">Not available in this build.</p>';
  const chips = (label: string, list: MilestoneRow['issues'] & {}) =>
    `<p class="ps-chips-k">${label} (${list.length})</p>`
    + (list.length === 0
      ? '<p class="ps-none">None.</p>'
      : `<ul class="ps-chips">${list.map((i) => `<li><a class="ps-chip" href="${REPO_URL}/issues/${i.number}"><span class="ps-no">#${i.number}</span> ${esc(i.title)}</a></li>`).join('')}</ul>`);
  const details = input.rows.map((r) => {
    const list = r.issues ?? [];
    return `<details class="${cls('ps-detail', r.current && 'ps-current')}"${r.current ? ' open' : ''} data-group="${esc(r.key)}">`
      + `<summary><strong>${esc(r.roadmap ? `${r.key}: ${r.name}` : r.name)}</strong>${r.current ? '<span class="ps-tag">current</span>' : ''}`
      + `<span class="ps-asof">${r.open} open, ${r.closed} closed</span></summary>`
      + (list.length === 0
        ? '<p class="ps-none">No issues.</p>'
        : chips('Open', list.filter((i) => i.open)) + chips('Closed', list.filter((i) => !i.open)))
      + '</details>';
  });
  return when(input) + details.join('');
}

function checks(input: PartsInput): string {
  if (input.mode !== 'live') return '<p class="ps-none">Read live; not part of the build-time snapshot.</p>';
  if (!input.runs?.length) return `${when(input)}<p class="ps-none">No workflow run on <code>main</code> was read.</p>`;
  const items = input.runs.map((r) => {
    const sha = shortSha(r.sha);
    return `<li><a class="${cls('ps-chip', runFailed(r) && 'ps-chip-bad')}" href="${esc(ownUrl(r.url))}">${esc(r.workflow)} `
      + `<span class="ps-state">${esc(runState(r))}${sha ? ` · ${sha}` : ''} · ${esc(utc(r.at))}</span></a></li>`;
  });
  return `${when(input)}<ul class="ps-chips">${items.join('')}</ul>`;
}

// One part, as the page holds it between its heading and the next.
export function partHtml(part: Part, input: PartsInput): string {
  return part === 'cards' ? cards(input) : part === 'issues' ? issues(input) : checks(input);
}

// The fragment /api/status/live/ answers: every part, each in a container the page's script
// matches to the container of the same name on the page.
export function liveFragment(input: PartsInput): string {
  return `<div class="ps-body" data-mode="${input.mode}" data-as-of="${esc(input.asOf)}">`
    + PARTS.map((p) => `<div data-live-part="${p}">${partHtml(p, input)}</div>`).join('')
    + '</div>';
}
