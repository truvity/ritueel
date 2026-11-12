// Screenshots of every screen with headless Chrome over the DevTools protocol (no dependency):
// 1920, 1440 and 390 px wide, light and dark. Also the four states of a few screens, and
// it measures sideways overflow. It fails when a page scrolls sideways.
// usage: node scripts/shots.mjs http://127.0.0.1:PORT/demo/ [outdir] [part of a name]
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { launch, sleep } from './cdp.mjs';

const base = process.argv[2];
const out = process.argv[3] ?? new URL('../shots/', import.meta.url).pathname;
if (!base) throw new Error('give the base URL');
await mkdir(out, { recursive: true });

const { send, evalJs, close } = await launch();

// A group of the demo bar is a set of toggle buttons named by its label.
const pick = (group, label) =>
  evalJs(`(() => { const b = [...document.querySelectorAll('[aria-labelledby="${group}"] button')].find((x) => x.textContent.trim() === atob('${Buffer.from(label, 'utf8').toString('base64')}')); if (!b) return false; b.click(); return true; })()`);
const scene = (n) => evalJs(`document.querySelector('button[aria-label="Scene ${n} of 5"]')?.click()`);

// name, hash, steps to run after the page is up. The demo starts on acme, scene 1. A screen of another
// bundle or scene picks it in the demo bar (the page keeps the screen), then goes to its own address.
const via = (bundle, target, sceneNumber, more) => async () => {
  if (bundle) await pick('bundle-switch-label', bundle);
  await sleep(300);
  if (sceneNumber) await scene(sceneNumber);
  await sleep(300);
  await evalJs(`location.hash = ${JSON.stringify(target.slice(1))}`);
  await sleep(500);
  if (more) await more();
};
const KEY_A = '7D440B197D440B197D440B197D440B197D440B19';
const NEW = '20261124T100400Z-apply-7d41e9b3';
const screens = [
  ['todo', '#/todo'],
  ['todo-findings', '#/todo/findings'],
  ['todo-scene2', '#/todo', via(null, '#/todo', 2)],
  ['todo-scene3', '#/todo', via(null, '#/todo', 3)],
  ['todo-scene4-findings', '#/todo', via(null, '#/todo/findings', 4)],
  ['todo-scene5', '#/todo', via(null, '#/todo', 5)],
  ['todo-globex', '#/todo', via('globex', '#/todo')],
  ['todo-personal', '#/todo', via('personal', '#/todo')],
  ['inventory-cards', '#/inventory/cards'],
  ['inventory-card-root-a', '#/inventory/cards/card/root-a'],
  ['inventory-card-slot-open', '#/inventory/cards/card/root-a', async () => { await evalJs(`document.querySelector('button[aria-haspopup=dialog]')?.click()`); await sleep(400); }],
  ['inventory-roots', '#/inventory/roots'],
  ['inventory-root-key', `#/inventory/roots/key/${KEY_A}`],
  ['inventory-delegation', '#/inventory/roots/delegation/acme-release'],
  ['inventory-dates', '#/inventory/dates'],
  ['inventory-dates-scene5', '#/todo', via(null, '#/inventory/dates', 5)],
  ['inventory-certification', '#/inventory/dates/certification/cert-8'],
  ['inventory-scene2-roots', '#/todo', via(null, '#/inventory/roots', 2)],
  ['inventory-cards-globex', '#/todo', via('globex', '#/inventory/cards')],
  ['inventory-cards-personal', '#/todo', via('personal', '#/inventory/cards')],
  ['inventory-roots-personal', '#/todo', via('personal', '#/inventory/roots')],
  ['history', '#/history'],
  ['history-ceremony', '#/history/20261120T100000Z-apply-3fa9c1d2'],
  ['history-closed', '#/history/20250902T100000Z-apply-4d6b21fa'],
  ['history-scene3-planned', '#/todo', via(null, `#/history/${NEW}`, 3)],
  ['history-scene4-started', '#/todo', via(null, `#/history/${NEW}`, 4)],
  ['history-scene5-recorded', '#/todo', via(null, `#/history/${NEW}`, 5)],
  ['history-globex', '#/todo', via('globex', '#/history')],
  ['trust', '#/trust'],
  ['trust-scene5', '#/todo', via(null, '#/trust', 5)],
  ['trust-personal', '#/todo', via('personal', '#/trust')],
  ['notfound', '#/nothing-here'],
];
// the four states of a few screens (loaded is the screens above)
const states = [];
for (const [name, hash] of [['todo', '#/todo'], ['todo-findings', '#/todo/findings'], ['inventory', '#/inventory/cards'], ['history', '#/history'], ['trust', '#/trust']]) {
  for (const st of ['Empty', 'Failed read', 'Waiting']) states.push([`${name}-${st.split(' ')[0].toLowerCase()}`, hash, st]);
}

const sizes = [
  ['1920', 1920, 970, 1],
  ['1440', 1440, 900, 1],
  ['390', 390, 844, 2],
];
const report = [];

async function shoot(name, hash, steps, state, scheme, wname, w, h, dpr) {
  const mobile = wname === '390';
  await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: dpr, mobile });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
  // a fresh page each time: the state switch lives in the page and must start at Loaded
  await send('Page.navigate', { url: 'about:blank' });
  await send('Page.navigate', { url: base + '#/todo' });
  await sleep(900);
  await evalJs(`location.hash = ${JSON.stringify(hash.slice(1))}`);
  await sleep(500);
  if (state) {
    // the state switch is in the demo bar; Failed read and Waiting need no data first
    await pick('state-switch-label', state);
    await sleep(state === 'Waiting' ? 4200 : 600);
  }
  if (steps) await steps();
  await sleep(300);
  const m = JSON.parse(
    await evalJs(`JSON.stringify({sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, h: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight), scheme: (document.documentElement.hasAttribute('data-dark') ? 'dark' : 'light')})`),
  );
  const height = Math.min(m.h, 16000);
  await send('Emulation.setDeviceMetricsOverride', { width: w, height, deviceScaleFactor: height > 6500 ? 1 : dpr, mobile });
  await sleep(250);
  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  const file = join(out, `${name}-${wname}-${scheme}.png`);
  await writeFile(file, Buffer.from(shot.data, 'base64'));
  report.push({ file, overflowX: m.sw > m.cw, sw: m.sw, cw: m.cw, height: m.h, applied: m.scheme });
}

// An optional part of a screen's name: only the screens whose name holds it are taken.
const only = process.argv[4] ? String(process.argv[4]) : null;
for (const scheme of ['light', 'dark']) {
  for (const [wname, w, h, dpr] of sizes) {
    for (const [name, hash, steps] of screens) if (!only || name.includes(only)) await shoot(name, hash, steps, undefined, scheme, wname, w, h, dpr);
    // the states: light only at both widths, and dark at 390 for the failed read
    for (const [name, hash, st] of states) {
      if (only && !name.includes(only)) continue;
      if (scheme === 'dark' && !(wname === '390' && st === 'Failed read')) continue;
      await shoot(name, hash, undefined, st, scheme, wname, w, h, dpr);
    }
  }
}
const bad = report.filter((r) => r.overflowX);
console.log(JSON.stringify({ shots: report.length, overflow: bad }, null, 1));
await close();
if (bad.length > 0) process.exit(1);
