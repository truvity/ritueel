#!/usr/bin/env node
// One screen: the start page (/) and the five case pages must fit the window with no scroll at 1440x900
// and at 1920x970, in the light and in the dark theme, with 5 percent of the window's height to spare.
// A real render in headless Chrome, the same launch and the same small CDP client as check-render.mjs.
//
// What is measured: the bottom of the page's footer, the last element of the page, in pixels from
// the top of the document (its box plus the scroll position). The page fits when that bottom is at
// most 95 percent of the window's height. scrollHeight is not used: Chrome never reports it below
// the window's height, so it cannot say how much room is left. The headroom is for another font on
// a CI runner, where a line may wrap one more time. A phone is not measured: its cards stack and
// the page scrolls; only "no sideways scroll" is checked there (check-render.mjs does it for the
// status page; this script does it for the pages it knows, at 400 px).
//
// A case page and the start page have no side menu: a visitor may come by a shared link.
//
// The pages are "/" and the page of each case of docs/coverage.yaml (its field `page`, a short address
// such as /pki/). The check fails when the file names no page, and when a page is not in the build (an
// empty sweep proves nothing).
//
// Needs Chrome or Chromium (CHROME, or google-chrome / chromium on PATH) and Node 22+. No npm dependency.
//
// usage: site/scripts/check-fit.mjs [dist]        (needs `just site-build`; run it with `just site-fit`)
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const dist = resolve(root, process.argv[2] ?? 'site/dist');
const SIZES = [[1440, 900], [1920, 970]];
const PHONE = [400, 900];
const HEADROOM = 0.95;
const THEMES = ['light', 'dark'];
const LAUNCH_MS = 120_000;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.xml': 'application/xml', '.txt': 'text/plain', '.woff2': 'font/woff2' };

function findChrome() {
  for (const c of [process.env.CHROME, 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].filter(Boolean)) {
    if (spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 60000 }).status === 0) return c;
  }
  throw new Error('no Chrome or Chromium found: set CHROME, or put google-chrome or chromium on PATH');
}

function serve() {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    let file = join(dist, normalize(decodeURIComponent(path)));
    if (!file.startsWith(dist)) { res.writeHead(403).end(); return; }
    if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
    if (!existsSync(file)) { res.writeHead(404).end('not found'); return; }
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok(server)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function launchOnce(chrome) {
  const profile = mkdtempSync(join(tmpdir(), 'check-fit-'));
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
// One retry of the launch: a browser that never came up says nothing about the page. The measures are never retried.
async function launch(chrome) {
  try { return await launchOnce(chrome); } catch (e) { console.error(`check-fit: Chrome launch failed, retrying once: ${e.message}`); return await launchOnce(chrome); }
}

function connect(url) {
  const ws = new WebSocket(url);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { ok, fail } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? fail(new Error(msg.error.message)) : ok(msg.result);
    }
  };
  const opened = new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = () => fail(new Error('CDP socket failed')); });
  return opened.then(() => ({
    send: (method, params = {}) => new Promise((ok, fail) => { const n = ++id; pending.set(n, { ok, fail }); ws.send(JSON.stringify({ id: n, method, params })); }),
    close: () => ws.close(),
  }));
}

const MEASURE = `(async () => {
  await document.fonts.ready;
  const footer = [...document.querySelectorAll('footer')].pop();
  const last = footer ?? document.querySelector('main');
  return {
    innerHeight: window.innerHeight,
    bottom: Math.round(last.getBoundingClientRect().bottom + window.scrollY),
    scrollHeight: document.documentElement.scrollHeight,
    scrollW: document.documentElement.scrollWidth,
    clientW: document.documentElement.clientWidth,
    h1: document.querySelectorAll('h1').length,
    sidebar: document.documentElement.hasAttribute('data-has-sidebar'),
  };
})()`;

async function measure(cdp, base, path, [width, height], mobile = false) {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile });
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await cdp.send('Page.navigate', { url: `${base}${path}` });
  await sleep(700);
  const r = await cdp.send('Runtime.evaluate', { expression: MEASURE, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails || !r.result.value) throw new Error(`could not measure ${path}: ${JSON.stringify(r.exceptionDetails ?? r.result)}`);
  return r.result.value;
}

// The pages: the start page and the page of each case of docs/coverage.yaml. The file is read as text
// (the YAML package is no dependency of the site); the field is `  page: /pki/` in an entry of a case.
const cases = [...readFileSync(join(root, 'docs', 'coverage.yaml'), 'utf8').matchAll(/^ {2}page: (\/[a-z-]+\/)$/gm)].map((m) => m[1]);
if (cases.length === 0) { console.error('check-fit: FAIL docs/coverage.yaml names no case page (an empty sweep proves nothing)'); process.exit(1); }
const pages = ['/', ...cases];
for (const path of pages) {
  if (!existsSync(join(dist, path, 'index.html'))) { console.error(`check-fit: FAIL ${path} is not in ${dist}; build the site first`); process.exit(1); }
}

const server = await serve();
const base = `http://127.0.0.1:${server.address().port}`;
let chrome;
let failed = 0;
let ran = 0;
const rows = [];
try {
  chrome = await launch(findChrome());
  const target = await (await fetch(`http://127.0.0.1:${chrome.port}/json/new?about:blank`, { method: 'PUT' })).json();
  const cdp = await connect(target.webSocketDebuggerUrl);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  for (const theme of THEMES) {
    await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] });
    for (const path of pages) {
      for (const size of SIZES) {
        ran++;
        const m = await measure(cdp, base, path, size);
        const limit = Math.floor(m.innerHeight * HEADROOM);
        const problems = [];
        if (m.bottom > limit) problems.push(`the page ends at ${m.bottom} px; the limit is ${limit} px (95 percent of ${m.innerHeight}); ${m.bottom - limit} px over`);
        if (m.scrollW > m.clientW) problems.push(`the page scrolls sideways (${m.scrollW} > ${m.clientW})`);
        if (m.h1 !== 1) problems.push(`the page has ${m.h1} h1`);
        if (m.sidebar) problems.push('the page has the side menu; a case page and the start page stand alone');
        rows.push({ path, theme, size: size.join('x'), window: m.innerHeight, bottom: m.bottom, limit, scrolls: m.scrollHeight > m.innerHeight, ok: problems.length === 0 });
        if (problems.length) { failed++; for (const p of problems) console.error(`check-fit: FAIL ${path} at ${size.join('x')}, ${theme}: ${p}`); }
      }
      ran++;
      const m = await measure(cdp, base, path, PHONE, true);
      if (m.scrollW > m.clientW) { failed++; console.error(`check-fit: FAIL ${path} at ${PHONE.join('x')}, ${theme}: the page scrolls sideways (${m.scrollW} > ${m.clientW})`); }
    }
  }
  cdp.close();
} finally {
  chrome?.child.kill('SIGKILL');
  server.close();
  await sleep(200);
  if (chrome) rmSync(chrome.profile, { recursive: true, force: true });
}
console.log('check-fit: page              theme  size       window  bottom  limit  scrolls');
for (const r of rows) console.log(`check-fit: ${r.path.padEnd(17)} ${r.theme.padEnd(5)}  ${r.size.padEnd(9)} ${String(r.window).padStart(6)} ${String(r.bottom).padStart(7)} ${String(r.limit).padStart(6)}  ${r.scrolls ? 'yes' : 'no'}${r.ok ? '' : '  FAIL'}`);
if (ran === 0) { console.error('check-fit: no page was measured'); process.exit(1); }
if (failed) { console.error(`check-fit: ${failed} of ${ran} measures failed`); process.exit(1); }
console.log(`check-fit: ok (${pages.length} pages, ${ran} measures)`);
