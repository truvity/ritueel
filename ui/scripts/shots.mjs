// Screenshots of every screen with headless Chrome over the DevTools protocol (no dependency):
// 1440 and 390 px wide, light and dark. Also the four states of a few screens, and
// it measures sideways overflow. It fails when a page scrolls sideways.
// usage: node scripts/shots.mjs http://127.0.0.1:PORT/demo/ [outdir]
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { clickText, launch, sleep } from './cdp.mjs';

const base = process.argv[2];
const out = process.argv[3] ?? new URL('../shots/', import.meta.url).pathname;
if (!base) throw new Error('give the base URL');
await mkdir(out, { recursive: true });

const { send, evalJs, close } = await launch();

// name, hash, steps to run after the page is up, [state to show]
const key = (n) => `#/key/${n}`;
// The demo starts on the personal bundle. A screen of another bundle starts on Start, picks the bundle in the
// demo bar (which sends the page back to Start), then goes to its own address.
const via = (bundle, target, more) => async () => {
  await clickText(evalJs, bundle);
  await sleep(300);
  await evalJs(`location.hash = ${JSON.stringify(target.slice(1))}`);
  await sleep(500);
  if (more) await more();
};
const saveThePlan = async () => { await clickText(evalJs, 'Show me the plan'); await sleep(500); await clickText(evalJs, 'Save the plan'); await sleep(500); };
const screens = [
  ['start', '#/start'],
  ['findings', '#/findings'],
  ['roots', '#/roots'],
  ['key-personal-A', key('A')],
  ['key-acme-A', '#/start', via('acme', key('A'))],
  ['key-acme-B', '#/start', via('acme', key('B'))],
  ['key-globex-A', '#/start', via('globex', key('A'))],
  ['roots-acme', '#/start', via('acme', '#/roots')],
  ['cards-acme', '#/start', via('acme', '#/cards')],
  ['cards-globex', '#/start', via('globex', '#/cards')],
  ['start-acme', '#/start', via('acme', '#/start')],
  ['start-globex', '#/start', via('globex', '#/start')],
  ['cards', '#/cards'],
  ['card-root', '#/cards/00000001'],
  ['card-day-to-day', '#/cards/00000004'],
  ['card-slot-open', '#/cards/00000001', async () => { await evalJs(`document.querySelector('button[aria-haspopup=dialog]')?.click()`); await sleep(400); }],
  ['card-unlisted', '#/cards/00000102'],
  ['history', '#/history'],
  ['ceremony', '#/history/20261103T142000Z-init'],
  ['history-acme', '#/start', via('acme', '#/history')],
  ['trust', '#/trust'],
  ['plan-goals', '#/plan'],
  ['plan-questions', '#/start', via('acme', '#/plan/renew-due')],
  ['plan-preview', '#/start', via('acme', '#/plan/renew-due', async () => { await clickText(evalJs, 'Show me the plan'); await sleep(500); })],
  ['plan-saved', '#/start', via('acme', '#/plan/renew-due', saveThePlan)],
  ['plan-saved-offline-key-file', '#/plan/retire-subkeys', saveThePlan],
  ['plan-saved-workstation', '#/start', via('globex', '#/plan/adopt-key', saveThePlan)],
  ['plan-refused', '#/plan/add-card'],
  ['notfound', '#/nothing-here'],
];
// the four states of a few screens (loaded is the screens above)
const states = [];
for (const [name, hash] of [['start', '#/start'], ['findings', '#/findings'], ['cards', '#/cards'], ['history', '#/history'], ['trust', '#/trust'], ['roots', '#/roots'], ['plan-goals', '#/plan']]) {
  for (const st of ['Empty', 'Failed read', 'Waiting']) states.push([`${name}-${st.split(' ')[0].toLowerCase()}`, hash, st]);
}
states.push(['key-personal-A-failed', key('A'), 'Failed read'], ['plan-saved-failed', '#/plan/retire-subkeys', 'Failed read']);

const sizes = [
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
  await send('Page.navigate', { url: base + '#/start' });
  await sleep(900);
  await evalJs(`location.hash = ${JSON.stringify(hash.slice(1))}`);
  await sleep(500);
  if (state) {
    // the state switch is in the demo bar; Failed read and Waiting need no data first
    await clickText(evalJs, state);
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
