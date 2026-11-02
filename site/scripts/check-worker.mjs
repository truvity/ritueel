#!/usr/bin/env node
// Tests of the site's Worker (src/worker/), of the renderer it shares with the status page
// (src/lib-status-html.ts), of the decisions of the page's live script (src/scripts/status-live-core.ts)
// and of the deploy configuration (scripts/deploy-config.mjs), in Node, with GitHub and KV replaced
// by fakes: no network, no Cloudflare account, no secret. Node runs the TypeScript modules directly
// (type stripping), the same modules Wrangler and Astro bundle.
//
// - the GitHub App JWT, signed with a PKCS#1 key the way GitHub issues them;
// - the reading of issues and milestones: pull requests and bots stay out, a short answer is not trusted;
// - the KV write rules: write on a change or an hour-old copy, never past the daily cap;
// - a refresh end to end: first write, no write when nothing changed, a failure that logs no secret;
// - the routes: /api/status and /api/status/live/, and what they refuse;
// - the live parts escape what they are given, and the snapshot and the live block are one renderer;
// - the live script's decisions, and the deploy configuration.
//
// An empty sweep is not a pass: the script fails when it ran no case.
//
// usage: site/scripts/check-worker.mjs
import { createPrivateKey, createPublicKey, createVerify, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const { appJwt, pemToPkcs8, forgetToken, PERMISSIONS } = await import('../src/worker/github.ts');
const { writeDecision, liveStatus, BOARD_KEY, BOARD_WRITE_CAP } = await import('../src/worker/status.ts');
const { api, STATUS_CACHE } = await import('../src/worker/api.ts');
const { default: worker } = await import('../src/worker/index.ts');
const { readIssues } = await import('../src/lib-github-rest.ts');
const { milestoneRows } = await import('../src/lib-milestones.ts');
const { partHtml, liveFragment, PARTS } = await import('../src/lib-status-html.ts');
const { liveProblem, carryOpen } = await import('../src/scripts/status-live-core.ts');
const { parseJsonc, withKvId } = await import('./deploy-config.mjs');

let cases = 0;
const failures = [];
async function test(name, fn) {
  cases++;
  try {
    await fn();
  } catch (e) {
    failures.push(`${name}: ${e.message}`);
  }
}

// ---- fakes
class FakeKV {
  constructor() { this.data = new Map(); this.puts = 0; }
  async get(key, type) { const v = this.data.get(key); return v === undefined ? null : type === 'json' ? JSON.parse(v) : v; }
  async put(key, value) { this.puts++; this.data.set(key, value); }
}
const ROADMAP = [
  { key: 'M1', name: 'First version', delivers: 'The first <working> tool.' },
  { key: 'M2', name: 'Hardware', delivers: 'Cards.' },
];
const BUILT = { schema: 1, builtAt: '2026-11-02T10:00:00Z', roadmap: ROADMAP };
const assets = { fetch: async (req) => (new URL(req.url ?? req).pathname === '/data/status.json' ? Response.json(BUILT) : new Response('no', { status: 404 })) };

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const pkcs1 = privateKey;
const publicPem = createPublicKey(pkcs1).export({ type: 'spki', format: 'pem' });

const issue = (number, title, state = 'open', milestone = null, extra = {}) =>
  ({ number, title, state, milestone: milestone ? { title: milestone } : null, user: { type: 'User' }, ...extra });
const MILESTONES = [{ title: 'M1: First version', description: 'x' }, { title: 'M2: Hardware', description: null }];
const ISSUES = [
  issue(1, 'Open one', 'open', 'M1: First version'),
  issue(2, 'Closed one', 'closed', 'M1: First version'),
  issue(3, 'Cards <img src=x onerror=alert(1)>', 'open', 'M2: Hardware'),
  issue(4, 'A pull request', 'open', 'M1: First version', { pull_request: {} }),
  issue(5, 'Dependency dashboard', 'open', null, { user: { type: 'Bot' } }),
  issue(6, 'No milestone', 'open'),
];
const RUNS = [
  { name: 'Site', head_branch: 'main', status: 'completed', conclusion: 'success', html_url: 'https://github.com/truvity/ritueel/actions/runs/2', head_sha: 'a'.repeat(40), updated_at: '2026-11-02T09:00:00Z' },
  { name: 'Site', head_branch: 'main', status: 'completed', conclusion: 'failure', html_url: 'https://github.com/truvity/ritueel/actions/runs/1', head_sha: 'b'.repeat(40), updated_at: '2026-11-01T09:00:00Z' },
  { name: 'Other', head_branch: 'feature', status: 'completed', conclusion: 'success', html_url: 'x', head_sha: 'c'.repeat(40), updated_at: '2026-11-01T09:00:00Z' },
  { name: 'Evil', head_branch: 'main', status: 'completed', conclusion: 'failure', html_url: 'https://evil.example/x" onmouseover="alert(1)', head_sha: 'd'.repeat(40), updated_at: '2026-11-02T08:00:00Z' },
];

// A GitHub that answers the calls the Worker makes. `state` can change between refreshes.
function fakeGitHub(state) {
  return async (input, init = {}) => {
    const url = String(input.url ?? input);
    state.calls.push(url);
    if (state.down) return new Response('no', { status: 502 });
    if (url.endsWith('/repos/truvity/ritueel/installation')) return Response.json({ id: 7 });
    if (url.endsWith('/app/installations/7/access_tokens')) {
      state.tokenRequest = JSON.parse(init.body);
      return Response.json({ token: 'test-installation-token', expires_at: new Date(Date.now() + 3600e3).toISOString() });
    }
    if (url.includes('/milestones')) return Response.json(state.milestones);
    if (url.includes('/issues')) return Response.json(state.issues);
    if (url.includes('/actions/runs')) {
      const inm = init.headers?.['if-none-match'];
      if (inm && inm === state.etag) return new Response(null, { status: 304 });
      return Response.json({ workflow_runs: state.runs }, { headers: { etag: state.etag } });
    }
    return new Response('unexpected ' + url, { status: 500 });
  };
}
const fresh = () => ({ calls: [], milestones: MILESTONES, issues: ISSUES, runs: RUNS, etag: '"e1"', down: false });
const secrets = () => ({ GITHUB_APP_CLIENT_ID: 'Iv1.test', GITHUB_APP_PRIVATE_KEY: pkcs1 });
let realFetch = globalThis.fetch;
const withGitHub = async (state, fn) => {
  globalThis.fetch = fakeGitHub(state);
  try { return await fn(); } finally { globalThis.fetch = realFetch; }
};
// The installation token is cached per isolate; every test starts without one.
const reload = async () => {
  forgetToken();
  return import('../src/worker/status.ts');
};

// ---- the App JWT
await test('appJwt: RS256 over the PKCS#1 key GitHub issues', async () => {
  const jwt = await appJwt('Iv1.test', pkcs1, 1_700_000_000);
  const [h, p, s] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { alg: 'RS256', typ: 'JWT' });
  assert.deepEqual(JSON.parse(Buffer.from(p, 'base64url')), { iat: 1_700_000_000 - 60, exp: 1_700_000_000 + 540, iss: 'Iv1.test' });
  assert.ok(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicPem, Buffer.from(s, 'base64url')));
});
await test('pemToPkcs8: accepts the key with its line breaks written as \\n, and a PKCS#8 key', () => {
  assert.ok(pemToPkcs8(pkcs1.replace(/\n/g, '\\n')).length > 1000);
  const pkcs8 = createPrivateKey(pkcs1).export({ type: 'pkcs8', format: 'pem' });
  assert.ok(pemToPkcs8(pkcs8).length > 1000);
});
await test('pemToPkcs8: refuses what is not a private key, naming no key material', () => {
  assert.throws(() => pemToPkcs8('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'), /not a PEM private key/);
});
await test('installationToken: reads the repository, asks for read-only issues and actions and nothing more', async () => {
  const state = fresh();
  forgetToken();
  const { installationToken: mint } = await import('../src/worker/github.ts');
  await withGitHub(state, async () => assert.equal(await mint(secrets()), 'test-installation-token'));
  assert.deepEqual(state.tokenRequest, { repositories: ['ritueel'], permissions: { issues: 'read', actions: 'read', metadata: 'read' } });
  assert.ok(Object.values(PERMISSIONS).every((v) => v === 'read'));
  assert.ok(state.calls[0].endsWith('/repos/truvity/ritueel/installation'));
});
await test('installationToken: without the secrets it throws a reason with no secret in it', async () => {
  forgetToken();
  const { installationToken: mint } = await import('../src/worker/github.ts');
  await assert.rejects(mint({}), /secrets of the Worker are not set/);
});

// ---- reading the issues
await test('readIssues: no pull request, no bot, sorted, with the milestone titles', async () => {
  const state = fresh();
  const out = await withGitHub(state, () => readIssues('t', 'ua'));
  assert.deepEqual(out.issues.map((i) => i.number), [1, 2, 3, 6]);
  assert.equal(out.issues[1].open, false);
  assert.equal(out.issues[3].milestone, null);
  assert.deepEqual(out.milestones.map((m) => m.title), ['M1: First version', 'M2: Hardware']);
});
await test('readIssues: a full page is followed, and an endless list fails closed', async () => {
  const state = fresh();
  state.issues = Array.from({ length: 100 }, (_, i) => issue(i + 1, 't'));
  await withGitHub(state, async () => {
    await assert.rejects(readIssues('t', 'ua'), /more than 1000 items/);
  });
});
await test('readIssues: an HTTP error names the status and not the token', async () => {
  const state = fresh();
  state.down = true;
  await withGitHub(state, async () => {
    await assert.rejects(readIssues('SECRET-TOKEN', 'ua'), (e) => /HTTP 502/.test(e.message) && !/SECRET-TOKEN/.test(e.message));
  });
});

// ---- the KV write rules
const NOW = Date.parse('2026-11-02T12:00:00Z');
await test('writeDecision: first, changed, heartbeat, unchanged', () => {
  const prev = { hash: 'a', checkedAt: '2026-11-02T11:30:00Z', writes: { day: '2026-11-02', n: 3 } };
  assert.equal(writeDecision(null, 'a', NOW), 'first');
  assert.equal(writeDecision(prev, 'b', NOW), 'changed');
  assert.equal(writeDecision(prev, 'a', NOW), 'unchanged');
  assert.equal(writeDecision({ ...prev, checkedAt: '2026-11-02T10:30:00Z' }, 'a', NOW), 'heartbeat');
});
await test('writeDecision: past the daily cap nothing is written; a new UTC day starts again', () => {
  const full = { hash: 'a', checkedAt: '2026-11-02T11:30:00Z', writes: { day: '2026-11-02', n: BOARD_WRITE_CAP } };
  assert.equal(writeDecision(full, 'b', NOW), 'over budget');
  assert.equal(writeDecision({ ...full, writes: { day: '2026-11-01', n: BOARD_WRITE_CAP } }, 'b', NOW), 'changed');
});
await test('the cap keeps the account under its 1,000 writes a day with the other site', () => {
  assert.ok(BOARD_WRITE_CAP <= 100);
});

// ---- a refresh end to end
await test('refresh: first write, then no write while nothing changes, then a write on a change', async () => {
  const { refresh: run } = await reload();
  const kv = new FakeKV();
  const env = { STATUS: kv, ASSETS: assets, ...secrets() };
  const state = fresh();
  await withGitHub(state, async () => {
    assert.match(await run(env, 'test', NOW), /wrote \(first, 4 issues, write 1 today\)/);
    assert.match(await run(env, 'test', NOW + 60_000), /unchanged/);
    assert.equal(kv.puts, 1);
    state.issues = [...ISSUES, issue(7, 'New')];
    assert.match(await run(env, 'test', NOW + 120_000), /wrote \(changed, 5 issues, write 2 today\)/);
    assert.equal(kv.puts, 2);
  });
  const doc = JSON.parse(kv.data.get(BOARD_KEY));
  assert.equal(doc.schema, 1);
  assert.equal(doc.runs.length, 2, 'the latest run of each workflow on main: Site and Evil, not the feature branch');
  assert.equal(doc.runs.find((r) => r.workflow === 'Site').conclusion, 'success', 'the newest run of a workflow wins');
});
await test('refresh: the runs are read with the ETag, and a 304 keeps the stored runs', async () => {
  const { refresh: run } = await reload();
  const kv = new FakeKV();
  const env = { STATUS: kv, ASSETS: assets, ...secrets() };
  const state = fresh();
  await withGitHub(state, async () => {
    await run(env, 'test', NOW);
    state.issues = [...ISSUES, issue(8, 'Another')];
    await run(env, 'test', NOW + 60_000);
  });
  const doc = JSON.parse(kv.data.get(BOARD_KEY));
  assert.equal(doc.runsEtag, '"e1"');
  assert.equal(doc.runs.length, 2, 'the 304 left the runs as they were');
});
await test('refresh: a GitHub that is down writes nothing, throws nothing and logs no secret', async () => {
  const { refresh: run } = await reload();
  const kv = new FakeKV();
  const env = { STATUS: kv, ASSETS: assets, ...secrets() };
  const state = fresh();
  state.down = true;
  const line = await withGitHub(state, () => run(env, 'test', NOW));
  assert.match(line, /failed: GitHub answered HTTP 502/);
  assert.equal(kv.puts, 0);
  assert.ok(!line.includes('BEGIN') && !line.includes(pkcs1.slice(40, 80)));
});
await test('refresh: without the App secrets it fails with that reason and writes nothing', async () => {
  const { refresh: run } = await reload();
  const kv = new FakeKV();
  const line = await run({ STATUS: kv, ASSETS: assets }, 'test', NOW);
  assert.match(line, /secrets of the Worker are not set/);
  assert.equal(kv.puts, 0);
});
await test('scheduled: the cron handler refreshes in the background', async () => {
  const kv = new FakeKV();
  const state = fresh();
  const waits = [];
  const log = console.log;
  console.log = () => {};
  try {
    await withGitHub(state, async () => {
      await worker.scheduled({}, { STATUS: kv, ASSETS: assets, ...secrets() }, { waitUntil: (p) => waits.push(p) });
      await Promise.all(waits);
    });
  } finally {
    console.log = log;
  }
  assert.equal(waits.length, 1);
  assert.equal(kv.puts, 1);
});

// ---- the routes
async function seeded(mutate = (d) => d) {
  const { refresh: run } = await reload();
  const kv = new FakeKV();
  const env = { STATUS: kv, ASSETS: assets, ...secrets() };
  await withGitHub(fresh(), () => run(env, 'test', NOW));
  const doc = JSON.parse(kv.data.get(BOARD_KEY));
  kv.data.set(BOARD_KEY, JSON.stringify(mutate(doc)));
  return env;
}
const get = (env, path, init) => api(new Request(`https://ritueel.id${path}`, init), env);

await test('/api/status: 503 with retry-after until the first refresh, and the snapshot is named', async () => {
  const res = await get({ STATUS: new FakeKV(), ASSETS: assets }, '/api/status');
  assert.equal(res.status, 503);
  assert.equal(res.headers.get('retry-after'), '300');
  assert.match((await res.json()).error, /build-time snapshot/);
});
await test('/api/status: JSON per milestone, the open issues, the runs; cached for a minute; read-only headers', async () => {
  const env = await seeded();
  const res = await get(env, '/api/status/');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), STATUS_CACHE);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  const body = await res.json();
  assert.equal(body.schema, 1);
  const m1 = body.milestones.find((m) => m.key === 'M1');
  assert.deepEqual([m1.open, m1.closed, m1.current], [1, 1, true]);
  assert.deepEqual(m1.openIssues, [{ number: 1, title: 'Open one' }]);
  assert.ok(body.milestones.find((m) => m.key === 'No milestone'), 'issues without a milestone have a row');
  assert.equal(body.ci.main.length, 2);
  assert.ok(!JSON.stringify(body).includes('test-installation-token'));
});
await test('/api/status/live/: an HTML fragment with every part, under a policy that allows no script', async () => {
  const env = await seeded();
  const res = await get(env, '/api/status/live/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^text\/html/);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  assert.ok(!/script-src/.test(res.headers.get('content-security-policy')));
  assert.equal(res.headers.get('x-robots-tag'), 'noindex');
  const html = await res.text();
  assert.match(html, /^<div class="ps-body" data-mode="live"/);
  for (const p of PARTS) assert.ok(html.includes(`data-live-part="${p}"`), `has the ${p} part`);
});
await test('/api/status/live/: 503 as plain text before the first refresh', async () => {
  const res = await get({ STATUS: new FakeKV(), ASSETS: assets }, '/api/status/live');
  assert.equal(res.status, 503);
  assert.match(res.headers.get('content-type'), /^text\/plain/);
  assert.match(await res.text(), /keeps its build-time snapshot/);
});
await test('the live parts escape what GitHub and the roadmap give; a foreign run URL is not a link', async () => {
  const env = await seeded();
  const html = await (await get(env, '/api/status/live/')).text();
  assert.ok(!html.includes('<img'), 'an issue title is text');
  assert.ok(!html.includes('<working>'), 'the roadmap text is text');
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.ok(!html.includes('evil.example'), 'a run URL outside the repository is dropped');
  assert.ok(!/onmouseover/.test(html));
  assert.ok(!/<script/i.test(html));
});
await test('the routes refuse writes, and unknown paths say what exists', async () => {
  const env = await seeded();
  for (const path of ['/api/status', '/api/status/live/']) {
    const res = await get(env, path, { method: 'POST', body: '{}' });
    assert.equal(res.status, 405);
    assert.equal(res.headers.get('allow'), 'GET, HEAD');
  }
  const res = await get(env, '/api/hooks/github', { method: 'POST' });
  assert.equal(res.status, 404, 'there is no webhook');
  assert.deepEqual((await res.json()).routes, ['/api/status', '/api/status/live/']);
});
await test('a broken static asset is a 500 with no detail, not a crash', async () => {
  const env = await seeded();
  const log = console.log;
  console.log = () => {};
  try {
    const res = await get({ ...env, ASSETS: { fetch: async () => new Response('x', { status: 500 }) } }, '/api/status');
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: 'internal error' });
  } finally {
    console.log = log;
  }
});
await test('liveStatus joins the document to the roadmap of this deployment', async () => {
  const env = await seeded();
  const live = await liveStatus(env, 'https://ritueel.id/api/status');
  assert.equal(live.repoBuiltAt, BUILT.builtAt);
  assert.deepEqual(live.rows.map((r) => r.key), ['M1', 'M2', 'No milestone']);
  assert.equal(live.rows[0].current, true);
});

// ---- one renderer for the snapshot and the live block
const rowsOf = (github) => milestoneRows(ROADMAP, github);
const gh = { available: true, milestones: MILESTONES, issues: [
  { number: 1, title: 'Open one', open: true, milestone: 'M1: First version' },
  { number: 2, title: 'Closed one', open: false, milestone: 'M1: First version' },
] };
const stripWhen = (html) => html.replace(/<p class="ps-asof-line">.*?<\/p>/, '');
await test('the snapshot and the live block draw the same cards and issues, apart from the "as of" line', () => {
  const base = { rows: rowsOf(gh), asOf: '2026-11-02T10:00:00Z', available: true };
  for (const p of ['cards', 'issues']) {
    const snap = partHtml(p, { ...base, mode: 'snapshot' });
    const live = partHtml(p, { ...base, mode: 'live' });
    assert.notEqual(snap, live);
    assert.equal(stripWhen(snap), stripWhen(live));
    assert.match(snap, /snapshot/);
    assert.match(live, /live/);
  }
});
await test('a card for every roadmap milestone, the current one marked, with the figures', () => {
  const html = partHtml('cards', { rows: rowsOf(gh), mode: 'live', asOf: '2026-11-02T10:00:00Z', available: true });
  assert.equal([...html.matchAll(/data-milestone="(M\d)"/g)].map((m) => m[1]).join(), 'M1,M2');
  assert.match(html, /M1 · <strong>current<\/strong>/);
  assert.match(html, /1 of 2 issues closed/);
  assert.match(html, /0 of 0 issues closed/);
});
await test('without issue data the snapshot says so with a dash, and the checks say they are live only', () => {
  const rows = rowsOf({ available: false, reason: 'x' });
  const input = { rows, mode: 'snapshot', asOf: '2026-11-02T10:00:00Z', available: false };
  assert.match(partHtml('cards', input), /— issues closed/);
  assert.match(partHtml('issues', input), /Not available in this build/);
  assert.match(partHtml('checks', input), /Read live/);
});
await test('liveFragment holds every part once, in a container the page can match by name', () => {
  const html = liveFragment({ rows: rowsOf(gh), mode: 'live', asOf: '2026-11-02T10:00:00Z', available: true, runs: [] });
  for (const p of PARTS) assert.equal(html.split(`data-live-part="${p}"`).length, 2, p);
  assert.match(html, /No workflow run on <code>main<\/code> was read/);
});
await test('the page carries a container for every part the fragment has', () => {
  const page = readFileSync(join(site, 'src/pages/status.astro'), 'utf8');
  for (const p of PARTS) assert.ok(page.includes(`data-live-part="${p}"`), `status.astro has the ${p} part`);
  assert.ok(page.includes('data-live-src="/api/status/live/"') && page.includes('data-live-note'));
  assert.ok(!/<script[^>]*>\s*[^<\s]/.test(page.replace(/<script>\s*import '..\/scripts\/status-live.ts';\s*<\/script>/, '')), 'no inline script but the import of the bundled one');
});

// ---- the live script's decisions
await test('liveProblem: only a 200 that is HTML is taken', () => {
  assert.equal(liveProblem(200, 'text/html; charset=utf-8'), null);
  assert.match(liveProblem(503, 'text/plain'), /HTTP 503/);
  assert.match(liveProblem(200, 'text/plain'), /content type text\/plain/);
  assert.match(liveProblem(200, null), /content type none/);
  assert.match(liveProblem(200, 'application/json'), /content type/);
});
await test('carryOpen: the reader keeps what they opened or closed; a new group takes the block default', () => {
  const out = carryOpen(new Map([['M1', false], ['M2', true]]), [{ group: 'M1', open: true }, { group: 'M2', open: false }, { group: 'M3', open: true }]);
  assert.deepEqual([...out], [['M1', false], ['M2', true], ['M3', true]]);
});

// ---- the deploy configuration
const wrangler = parseJsonc(readFileSync(join(site, 'wrangler.jsonc'), 'utf8'));
await test('wrangler.jsonc: the Worker runs first for /api/* only, with one cron, one KV binding and no webhook secret', () => {
  assert.equal(wrangler.main, 'src/worker/index.ts');
  assert.deepEqual(wrangler.assets.run_worker_first, ['/api/*']);
  assert.equal(wrangler.assets.binding, 'ASSETS');
  assert.deepEqual(wrangler.triggers.crons, ['*/15 * * * *']);
  assert.equal(wrangler.kv_namespaces.length, 1);
  assert.equal(wrangler.kv_namespaces[0].binding, 'STATUS');
  assert.equal(wrangler.workers_dev, false);
  assert.equal(wrangler.preview_urls, false);
  assert.ok(!('routes' in wrangler) && !('route' in wrangler) && !('account_id' in wrangler));
});
await test('the placeholder KV id is not a real one, and a real one is put in', () => {
  assert.equal(wrangler.kv_namespaces[0].id, '0'.repeat(32));
  const id = 'abcdef0123456789abcdef0123456789';
  const out = withKvId(structuredClone(wrangler), id);
  assert.equal(out.kv_namespaces[0].id, id);
  assert.equal(out.main, wrangler.main);
});
await test('withKvId refuses an id that is not 32 lowercase hex characters, without echoing it', () => {
  for (const bad of ['', 'xyz', 'ABCDEF0123456789ABCDEF0123456789', 'abcdef0123456789abcdef012345678']) {
    assert.throws(() => withKvId(structuredClone(wrangler), bad), (e) => /not a KV namespace id/.test(e.message) && (bad === '' || !e.message.includes(bad)));
  }
});
await test('parseJsonc: comments, comment markers inside strings, trailing commas', () => {
  const out = parseJsonc('// a\n{ "u": "https://x//y", /* c */ "a": [1, 2,], // t\n}\n');
  assert.deepEqual(out, { u: 'https://x//y', a: [1, 2] });
});

if (cases === 0) {
  console.error('check-worker: no case ran');
  process.exit(1);
}
if (failures.length) {
  console.error(`check-worker: ${failures.length} of ${cases} cases failed\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log(`check-worker: ok (${cases} cases)`);
