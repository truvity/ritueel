#!/usr/bin/env node
// A real render check of the project status page (/status/) in headless Chrome: the live script
// (src/scripts/status-live.ts) really swaps the Worker's parts in, and really leaves the snapshot
// when it cannot. Static greps (check-built.sh) cannot tell that the page script threw before it
// swapped anything; this can.
//
// This server stands in for the Worker at /api/status/live/: it answers with a live fragment
// drawn by the Worker's own renderer (src/lib-status-html.ts) from the roadmap the build
// published (dist/data/status.json) and a few made-up issues, or with the 503 a Worker without
// data answers. Each is checked in light and dark, at 1440, 390 and 375 px:
//   - live:     the parts are swapped in (data-live="live", the "live" tag, the made-up issue is
//               there), the note stays hidden;
//   - down:     the Worker answers 503, the snapshot stays (data-live="snapshot", the "snapshot"
//               tag) and the note is shown. Chrome logs one failed-load line for the 503; it is
//               expected and not counted;
//   - no script: script execution off, the snapshot is there and the note stays hidden;
//   and for every one: no exception, no console error, and nothing scrolls sideways.
// The check fails when it ran no case.
//
// Needs Chrome or Chromium (CHROME, or google-chrome / chromium on PATH) and Node 22+ (global
// fetch and WebSocket). No npm dependency.
//
// usage: site/scripts/check-render.mjs [dist] [screenshot-dir]
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const { milestoneRows } = await import('../src/lib-milestones.ts');
const { liveFragment } = await import('../src/lib-status-html.ts');

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const dist = resolve(root, process.argv[2] ?? 'site/dist');
const shots = process.argv[3] ? resolve(process.argv[3]) : null;
const LIVE = '/api/status/live/';
const WIDTHS = [1440, 390, 375];
const SCHEMES = ['light', 'dark'];
const STATES = ['live', 'down', 'nojs'];
const LAUNCH_MS = 120_000;
const WAIT_MS = 15_000;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.xml': 'application/xml', '.txt': 'text/plain', '.wasm': 'application/wasm' };

function findChrome() {
  for (const c of [process.env.CHROME, 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].filter(Boolean)) {
    if (spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 60000 }).status === 0) return c;
  }
  throw new Error('no Chrome or Chromium found: set CHROME, or put google-chrome or chromium on PATH');
}

// What the stand-in answers at /api/status/live/: 'live' or 'down'.
let route = 'live';
const MADE_UP = 'A made-up live issue';
function liveBlock() {
  const built = JSON.parse(readFileSync(join(dist, 'data', 'status.json'), 'utf8'));
  const first = built.roadmap[0];
  const github = {
    available: true,
    milestones: built.roadmap.map((m) => ({ title: `${m.key}: ${m.name}`, description: null })),
    issues: [
      { number: 9001, title: MADE_UP, open: true, milestone: `${first.key}: ${first.name}` },
      { number: 9002, title: 'A made-up closed issue', open: false, milestone: `${first.key}: ${first.name}` },
    ],
  };
  const runs = [{ workflow: 'Site', status: 'completed', conclusion: 'success', url: 'https://github.com/truvity/ritueel/actions/runs/1', sha: 'a'.repeat(40), at: '2026-01-01T00:00:00Z' }];
  return liveFragment({ rows: milestoneRows(built.roadmap, github), mode: 'live', asOf: '2026-01-01T00:00:00Z', available: true, runs });
}

function serve() {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    if (path === LIVE) {
      if (route === 'live') res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(liveBlock());
      else res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' }).end('not available');
      return;
    }
    let file = join(dist, normalize(decodeURIComponent(path)));
    if (!file.startsWith(dist)) { res.writeHead(403).end(); return; }
    if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
    if (!existsSync(file)) { res.writeHead(404).end('not found'); return; }
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Start Chrome and wait for the "DevTools listening on ws://host:port/..." line on its stderr.
function launchOnce(chrome) {
  const profile = mkdtempSync(join(tmpdir(), 'check-render-'));
  const child = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--hide-scrollbars',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-extensions',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let err = '';
  return new Promise((ok, fail) => {
    const bad = (why) => {
      child.kill('SIGKILL');
      rmSync(profile, { recursive: true, force: true });
      fail(new Error(`${why}\n--- Chrome stderr ---\n${err.slice(-4000) || '(empty)'}\n---`));
    };
    const timer = setTimeout(() => bad(`Chrome did not print its DevTools address within ${LAUNCH_MS / 1000} s`), LAUNCH_MS);
    child.stderr.on('data', (d) => {
      err += d;
      const m = err.match(/DevTools listening on ws:\/\/[^:/\s]+:(\d+)\//);
      if (m) { clearTimeout(timer); child.stderr.removeAllListeners('data'); child.stderr.resume(); ok({ child, port: m[1], profile }); }
    });
    child.on('error', (e) => { clearTimeout(timer); bad(`could not start ${chrome}: ${e.message}`); });
    child.on('exit', (code, sig) => { if (!err.includes('DevTools listening')) { clearTimeout(timer); bad(`Chrome exited early (code ${code}, signal ${sig})`); } });
  });
}
// One retry of the launch: a browser that never came up says nothing about the page. The assertions are never retried.
async function launch(chrome) {
  try { return await launchOnce(chrome); } catch (e) { console.error(`check-render: Chrome launch failed, retrying once: ${e.message}`); return await launchOnce(chrome); }
}

// A minimal CDP client over the page's WebSocket.
function connect(url) {
  const ws = new WebSocket(url);
  let id = 0;
  const pending = new Map();
  const listeners = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { ok, fail } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? fail(new Error(msg.error.message)) : ok(msg.result);
    } else if (msg.method) listeners.forEach((l) => l(msg));
  };
  const opened = new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = () => fail(new Error('CDP socket failed')); });
  return opened.then(() => ({
    send: (method, params = {}) => new Promise((ok, fail) => { const n = ++id; pending.set(n, { ok, fail }); ws.send(JSON.stringify({ id: n, method, params })); }),
    on: (l) => listeners.push(l),
    clear: () => { listeners.length = 0; },
    close: () => ws.close(),
  }));
}

const STATE = `(() => ({
  live: document.querySelector('[data-live-src]')?.dataset.live ?? null,
  note: document.querySelector('[data-live-note]') ? !document.querySelector('[data-live-note]').hidden : null,
  parts: [...document.querySelectorAll('[data-live-part]')].map((p) => p.dataset.livePart),
  tags: [...document.querySelectorAll('[data-live-part] .ps-asof-line .ps-tag')].map((t) => t.textContent.trim()),
  madeUp: document.body.textContent.includes(${JSON.stringify(MADE_UP)}),
  cards: document.querySelectorAll('[data-live-part="cards"] .ps-card').length,
  nested: document.querySelectorAll('[data-live-part] [data-live-part], .ps-body').length,
  scrollW: document.documentElement.scrollWidth,
  clientW: document.documentElement.clientWidth,
}))()`;

async function checkCase(cdp, base, { state, scheme, width }) {
  const problems = [];
  cdp.clear();
  cdp.on((m) => {
    if (m.method === 'Runtime.exceptionThrown') problems.push(`exception: ${m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text}`);
    else if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') problems.push(`console.error: ${m.params.args.map((a) => a.value ?? a.description).join(' ')}`);
    else if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
      if (state === 'down' && (m.params.entry.url ?? '').endsWith(LIVE)) return;
      problems.push(`log: ${m.params.entry.text} ${m.params.entry.url ?? ''}`);
    }
  });
  route = state === 'live' ? 'live' : 'down';
  await cdp.send('Emulation.setScriptExecutionDisabled', { value: state === 'nojs' });
  await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  // A fresh profile has no stored theme choice, so the emulated colour scheme applies.
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await cdp.send('Page.navigate', { url: `${base}/status/` });
  const t0 = Date.now();
  let st;
  for (;;) {
    await sleep(250);
    st = (await cdp.send('Runtime.evaluate', { expression: STATE, returnByValue: true })).result.value;
    if (st && (state === 'nojs' ? st.parts.length : st.live !== 'snapshot' || (state === 'down' && st.note))) break;
    if (Date.now() - t0 > WAIT_MS) break;
  }
  await sleep(500); // let a late error surface
  st = (await cdp.send('Runtime.evaluate', { expression: STATE, returnByValue: true })).result.value;
  if (!st) { problems.push('the page did not load'); return problems; }
  if (st.parts.join() !== 'cards,issues,checks') problems.push(`live parts on the page: ${st.parts.join() || 'none'}, expected cards,issues,checks`);
  if (st.cards < 1) problems.push('no milestone card');
  if (st.nested) problems.push('a live part holds another, or the fragment wrapper was inserted whole');
  if (state === 'live') {
    if (st.live !== 'live') problems.push(`expected the Worker's parts swapped in, found state ${st.live}`);
    if (st.note !== false) problems.push('the note is shown although the live data was read');
    if (!st.madeUp) problems.push('the live issue is not on the page');
    if (st.tags.length !== 3 || st.tags.some((t) => t !== 'live')) problems.push(`expected three "live" tags, found ${st.tags.join() || 'none'}`);
  } else {
    if (st.live !== 'snapshot') problems.push(`expected the snapshot kept, found state ${st.live}`);
    if (st.madeUp) problems.push('a live issue is on the page although the live data was not read');
    if (state === 'down' && st.note !== true) problems.push('the note is not shown although the live data could not be read');
    if (state === 'nojs' && st.note !== false) problems.push('the note is shown although no script ran');
    if (st.tags.some((t) => t !== 'snapshot')) problems.push(`the snapshot's tags: ${st.tags.join()}`);
  }
  if (st.scrollW > st.clientW) problems.push(`the page scrolls sideways at ${width} px (${st.scrollW} > ${st.clientW})`);
  if (shots) {
    mkdirSync(shots, { recursive: true });
    const png = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: width < 600 });
    writeFileSync(join(shots, `status-${state}-${scheme}-${width}.png`), Buffer.from(png.data, 'base64'));
  }
  return problems;
}

const server = await serve();
const base = `http://127.0.0.1:${server.address().port}`;
let chrome;
let failed = 0;
let ran = 0;
try {
  for (const f of ['status/index.html', 'data/status.json']) {
    if (!existsSync(join(dist, f))) { console.error(`check-render: FAIL ${f} is not in ${dist}; build the site first`); process.exit(1); }
  }
  chrome = await launch(findChrome());
  const target = await (await fetch(`http://127.0.0.1:${chrome.port}/json/new?about:blank`, { method: 'PUT' })).json();
  const cdp = await connect(target.webSocketDebuggerUrl);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Log.enable');
  for (const state of STATES) for (const scheme of SCHEMES) for (const width of WIDTHS) {
    ran++;
    const problems = await checkCase(cdp, base, { state, scheme, width });
    if (problems.length) {
      failed++;
      console.error(`check-render: FAIL /status/ (${state}, ${scheme}, ${width} px)`);
      for (const p of problems) console.error(`  ${p}`);
    } else console.log(`check-render: ok   /status/ (${state}, ${scheme}, ${width} px)`);
  }
  cdp.close();
} finally {
  chrome?.child.kill('SIGKILL');
  server.close();
  await sleep(200);
  if (chrome) rmSync(chrome.profile, { recursive: true, force: true });
}
if (ran === 0) { console.error('check-render: no case ran'); process.exit(1); }
if (failed) { console.error(`check-render: ${failed} of ${ran} renders failed`); process.exit(1); }
console.log(`check-render: ok (${ran} renders)`);
