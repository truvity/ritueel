// A tiny driver for headless Chrome over the DevTools protocol. No library.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launch() {
  const profile = await mkdtemp(join(tmpdir(), 'ritueel-chrome-'));
  const port = 9300 + Math.floor(Math.random() * 600);
  const chrome = spawn(
    process.env.CHROME ?? 'google-chrome',
    ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--no-sandbox', '--disable-gpu', '--hide-scrollbars', 'about:blank'],
    { stdio: 'ignore' },
  );
  async function json(path, method = 'GET') {
    for (let i = 0; i < 60; i++) {
      try {
        return await (await fetch(`http://127.0.0.1:${port}${path}`, { method })).json();
      } catch {
        await sleep(200);
      }
    }
    throw new Error('chrome did not start');
  }
  const target = await json('/json/new?about:blank', 'PUT');
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0;
  const pending = new Map();
  // What the page complained about: console errors, uncaught exceptions, and what the browser
  // logged as an error or a warning (a Content-Security-Policy violation is one of these).
  const problems = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
      return;
    }
    if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) {
      problems.push(`log ${msg.params.entry.level}: ${msg.params.entry.text}`);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      problems.push(`exception: ${msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text}`);
    } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      problems.push(`console.error: ${msg.params.args.map((a) => a.value ?? a.description ?? '').join(' ')}`);
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      pending.set(n, (msg) => (msg.error ? reject(new Error(method + ': ' + msg.error.message)) : resolve(msg.result)));
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  const evalJs = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error('eval failed: ' + (r.exceptionDetails.exception?.description ?? r.exceptionDetails.text));
    return r.result.value;
  };
  async function close() {
    try {
      ws.close();
    } catch {}
    chrome.kill();
    await sleep(300);
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
  await send('Page.enable');
  await send('Log.enable');
  await send('Runtime.enable');
  return { send, evalJs, close, problems };
}

/** Finds a button or link by its visible text (exact) and clicks it. Returns false when none is found. */
export const clickText = (evalJs, text, scope = 'document') =>
  evalJs(`(() => {
    const els = [...${scope}.querySelectorAll('button, a, [role=button], summary')].filter((e) => e.offsetParent !== null || e.getClientRects().length);
    const hit = els.find((e) => e.textContent.trim() === ${JSON.stringify(text)}) ?? els.find((e) => e.textContent.trim().startsWith(${JSON.stringify(text)}));
    if (!hit) return false;
    hit.click();
    return true;
  })()`);
