// A browser test over the DevTools protocol (headless Chrome, no library): keyboard and focus,
// the panel, the scenes, the four states, copy, the layout, the phone and the routes.
// It runs against the demo build, under the content security policy of the site, and fails on a
// console error or a policy violation.
// usage: node scripts/e2e.mjs http://127.0.0.1:PORT/demo/
import { readFileSync } from 'node:fs';
import { launch, sleep } from './cdp.mjs';

const base = process.argv[2];
if (!base) throw new Error('give the base URL');
const started = Date.now();
const { send, evalJs, close, problems } = await launch();
const results = [];
const check = (name, cond, extra = '') => {
  results.push([name, !!cond]);
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '  ' + extra}`);
};
const KEYS = {
  Tab: { code: 'Tab', vk: 9 },
  Enter: { code: 'Enter', vk: 13, text: '\r' },
  Escape: { code: 'Escape', vk: 27 },
  ' ': { code: 'Space', vk: 32, text: ' ' },
  ArrowRight: { code: 'ArrowRight', vk: 39 },
  ArrowLeft: { code: 'ArrowLeft', vk: 37 },
};
async function press(key, shift = false) {
  const k = KEYS[key];
  const common = { key, code: k.code, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers: shift ? 8 : 0 };
  await send('Input.dispatchKeyEvent', { type: k.text ? 'keyDown' : 'rawKeyDown', ...common, text: k.text });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', ...common });
  await sleep(60);
}
const go = async (hash, ms = 400) => {
  await evalJs(`location.hash = ${JSON.stringify(hash)}`);
  await sleep(ms);
};
const active = () =>
  evalJs(
    `(() => { const a = document.activeElement; const row = a.closest('[data-row-id]'); return JSON.stringify({ tag: a.tagName, id: a.id, text: (a.textContent || '').trim().slice(0, 40), label: a.getAttribute('aria-label') || '', current: a.getAttribute('aria-current') || '', row: row ? row.getAttribute('data-row-id') : '', ring: getComputedStyle(a).outlineStyle + ' ' + getComputedStyle(a).outlineWidth }); })()`,
  ).then(JSON.parse);
const text = () => evalJs(`document.body.innerText`);
const mainText = async () => (await textOf('main')).replace(/\s+/g, ' ');
const flat = async () => (await text()).replace(/\s+/g, ' ');
const hash = () => evalJs('location.hash');
const b64 = (t) => Buffer.from(t, 'utf8').toString('base64');
const sel = (s) => `document.querySelector(atob('${b64(s)}'))`;
const selAll = (s) => `document.querySelectorAll(atob('${b64(s)}'))`;
const rectOfSel = (selector) =>
  evalJs(`(() => { const el = ${sel(selector)}; if (!el) return null; const r = el.getBoundingClientRect(); return JSON.stringify({ left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height, innerWidth, innerHeight }); })()`).then((v) => (v ? JSON.parse(v) : null));
const visible = (selector) => evalJs(`(() => { const el = ${sel(selector)}; return !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden'; })()`);
const count = (selector) => evalJs(`${selAll(selector)}.length`);
const textOf = (selector) => evalJs(`(() => { const el = ${sel(selector)}; return el ? el.innerText : ''; })()`);

// A bidirectional override. It is written as a code so that no source line holds it raw.
const OVERRIDE = String.fromCharCode(0x202e);

// ---- the demo bar: the three controls --------------------------------------------------------
const pick = (group, label) => evalJs(`(() => { const b = [...${selAll(`[aria-labelledby="${group}"] button`)}].find((x) => x.textContent.trim() === ${JSON.stringify(label)}); if (!b) return false; b.click(); return true; })()`);
const useBundle = async (name) => {
  await pick('bundle-switch-label', name);
  await sleep(350);
};
const useState = async (name) => {
  await pick('state-switch-label', name);
  await sleep(name === 'Waiting' ? 600 : 450);
};
const useScene = async (n) => {
  await evalJs(`${sel(`button[aria-label="Scene ${n} of 5"]`)}?.click()`);
  await sleep(350);
};
const clickButton = (label) => evalJs(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === ${JSON.stringify(label)}); if (!b) return false; b.click(); return true; })()`);
const pressedNames = (group) => evalJs(`JSON.stringify([...${selAll(`[aria-labelledby="${group}"] button`)}].filter((b) => b.getAttribute('aria-pressed') === 'true').map((b) => b.textContent.trim()))`).then(JSON.parse);
const fresh = async (hashValue = '#/todo') => {
  await send('Page.navigate', { url: 'about:blank' });
  await send('Page.navigate', { url: base + hashValue });
  await sleep(1300);
};
const desktop = (w = 1440, h = 900) => send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
const phone = (w, h, dpr = 1) => send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: dpr, mobile: true });

await desktop();
await send('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
// The clipboard can be read only by a document that has the focus.
await send('Emulation.setFocusEmulationEnabled', { enabled: true }).catch(() => {});
await send('Page.navigate', { url: base });
await sleep(1300);

// ======== A. the frame ===================================================================
check('A: the title of To do names the page and the demo', (await evalJs('document.title')) === 'To do - ritueel local page (demo)', await evalJs('document.title'));
{
  const t = await text();
  check('A: the demo bar names its controls: Example bundle, Scene and Page state', /Example bundle/.test(t) && /\bScene\b/.test(t) && /Page state/.test(t) && !/Try a bundle|Try the states/.test(t));
  const names = JSON.parse(await evalJs(`JSON.stringify([...${selAll('[aria-labelledby="bundle-switch-label"] button')}].map((b) => b.textContent.trim()))`));
  check('A: the switch offers acme, globex and personal, in that order, and the demo starts on acme', JSON.stringify(names) === '["acme","globex","personal"]' && JSON.stringify(await pressedNames('bundle-switch-label')) === '["acme"]', JSON.stringify(names));
  check('A: the sidebar names the bundle and where it is', (await textOf('aside')).includes('acme') && (await textOf('aside')).includes('~/ritueel/acme'));
  const nav = JSON.parse(await evalJs(`JSON.stringify([...${selAll('aside nav[aria-label=Screens] a')}].map((a) => a.querySelector('span').textContent.trim()))`));
  check('A: the sidebar has four entries, in this order: To do, Inventory, History, Trust set', JSON.stringify(nav) === '["To do","Inventory","History","Trust set"]', JSON.stringify(nav));
  check('A: the entry of the screen shown is marked as the current page', (await evalJs(`${sel('aside nav a[aria-current=page]')}?.textContent ?? ''`)).startsWith('To do'));
  check('A: the sidebar shows the time of the read', /Read\s+2026-11-24 09:00 UTC/.test(await textOf('aside')));
}

// ---- keyboard: skip link, focus ring on MUI controls ------------------------------------------
await fresh('#/trust');
await press('Tab');
{
  const first = await active();
  check('A: the first Tab stop is the skip link', first.text === 'Skip to the page', JSON.stringify(first));
  await press('Enter');
  check('A: Enter on the skip link moves focus to the page heading', (await active()).id === 'page-title');
  let sawToggle = false;
  let sawButton = false;
  let ringOk = true;
  for (let i = 0; i < 120 && !(sawToggle && sawButton); i++) {
    await press('Tab');
    const a = await active();
    const isToggle = await evalJs(`document.activeElement.classList.contains('MuiToggleButton-root')`);
    const isButton = await evalJs(`document.activeElement.classList.contains('MuiButton-root')`);
    if (isToggle) sawToggle = true;
    if (isButton) sawButton = true;
    if ((isToggle || isButton) && !(a.ring.startsWith('solid') && parseFloat(a.ring.split(' ')[1]) >= 2)) {
      ringOk = false;
      console.log('   no ring on', JSON.stringify(a));
    }
  }
  check('A: the keyboard reaches a MUI ToggleButton and a MUI Button', sawToggle && sawButton);
  check('A: both show the focus ring (solid, 2px or more)', ringOk);
}

// ---- colour scheme toggle and its stored choice -------------------------------------------------
{
  const scheme = () => evalJs(`(document.documentElement.hasAttribute('data-dark') ? 'dark' : 'light')`);
  const click = (label) => evalJs(`(() => { const b = [...${selAll('aside [aria-label="Colour scheme"] button')}].find((x) => x.textContent.trim() === ${JSON.stringify(label)}); b.click(); return true; })()`);
  await click('Dark');
  await sleep(300);
  check('A: Dark sets the dark scheme, and the choice is stored', (await scheme()) === 'dark' && (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'dark');
  const darkBg = await evalJs(`getComputedStyle(document.body).backgroundColor`);
  await send('Page.reload');
  await sleep(1000);
  check('A: after a reload the page is still dark', (await scheme()) === 'dark' && (await evalJs(`getComputedStyle(document.body).backgroundColor`)) === darkBg);
  await click('Light');
  await sleep(300);
  check('A: Light sets the light scheme', (await scheme()) === 'light' && (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'light');
  await click('Auto');
  await sleep(300);
  check('A: Auto follows the system', (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'system');
}

// ======== B. routes ========================================================================
await fresh('#/todo');
const KEY_A = '7D440B197D440B197D440B197D440B197D440B19';
const ROUTES = [
  ['#/todo', 'To do'],
  ['#/todo/findings', 'To do'],
  ['#/inventory', 'Inventory'],
  ['#/inventory/cards', 'Inventory'],
  ['#/inventory/roots', 'Inventory'],
  ['#/inventory/dates', 'Inventory'],
  ['#/inventory/cards/card/root-a', 'Inventory'],
  ['#/inventory/roots/root/acme-release', 'Inventory'],
  ['#/inventory/roots/delegation/acme-release', 'Inventory'],
  [`#/inventory/roots/key/${KEY_A}`, 'Inventory'],
  ['#/inventory/dates/certification/cert-8', 'Inventory'],
  ['#/history', 'History'],
  ['#/history/20261120T100000Z-apply-3fa9c1d2', 'History'],
  ['#/trust', 'Trust set'],
];
for (const [h, heading] of ROUTES) {
  await go(h);
  check(`B: ${h} shows its screen, ${heading}, and not "No such screen"`, (await textOf('h1')) === heading && !/No such screen/.test(await text()), await textOf('h1'));
}
for (const h of ['#/start', '#/findings', '#/roots', '#/key/A', '#/cards', '#/cards/00000011', '#/plan', '#/plan/renew-due', '#/nothing-here', '#/todo/x', '#/inventory/x', '#/history/a/b']) {
  await go(h);
  check(`B: ${h} says "No such screen" and is no other screen`, (await textOf('h1')) === 'No such screen' && (await evalJs('document.title')).startsWith('No such screen'), await textOf('h1'));
}
await go('#/' + encodeURIComponent(OVERRIDE + 'x'.repeat(300)));
{
  const t = await text();
  check('B: a hostile address says "No such screen", shows no raw override and cuts the address', (await textOf('h1')) === 'No such screen' && !t.includes(OVERRIDE) && t.length < 6000 && /cut: the text is longer/.test(t));
}

// ======== C. To do =========================================================================
await fresh('#/todo');
{
  const t = await flat();
  check('C: scene 1 lists one change, Renew acme-release, in the state Waits, with its reason', (await count('main tr[data-row-id], main li[data-row-id]')) === 1 && /Renew acme-release/.test(t) && /\bWaits\b/.test(t) && /No request for acme-release has come\./.test(t));
  check('C: the Apply block has no command and says what is missing', /No change is ready\. Ask the requester for a request for acme-release\./.test(t) && (await count('main button[aria-label="Copy the command"]')) === 0);
  check('C: the tab Not applied yet counts 1 and the entry of the sidebar counts 1', (await evalJs(`${sel('#todo-tab-changes')}.textContent`)).includes('1') && /1 change not applied yet/.test(await textOf('aside nav')));
  await go('#/todo/findings');
  const f = await flat();
  check('C: the tab Findings shows "1 finding, worst first" and the title "acme-release ends in 60 days"', /1 finding, worst first/.test(f) && /acme-release ends in 60 days/.test(f));
  // The tabs move with the arrow keys; Enter follows the link and the focus stays on the tab.
  await go('#/todo');
  await evalJs(`${sel('#todo-tab-changes')}.focus()`);
  await press('ArrowRight');
  check('C: ArrowRight moves the focus from the tab Not applied yet to the tab Findings', (await active()).id === 'todo-tab-findings', JSON.stringify(await active()));
  await press('Enter');
  await sleep(300);
  check('C: Enter on the tab opens its address and the focus stays on the tab', (await hash()) === '#/todo/findings' && (await active()).id === 'todo-tab-findings', `${await hash()} ${JSON.stringify(await active())}`);
  await press('ArrowLeft');
  check('C: ArrowLeft moves the focus back', (await active()).id === 'todo-tab-changes');
}
await useScene(2);
await go('#/todo');
{
  const t = await flat();
  check('C: scene 2 lists four changes', /Changes not applied yet\. 4 lines\./.test(t));
  check('C: scene 2 shows the command to apply as text, and says this page cannot confirm', (await textOf('main code')).includes('ritueel apply --allow-missing acme-release') && /This page cannot confirm\./.test(t));
  const shown = await evalJs(`${sel('main code')}.textContent`);
  await evalJs(`${sel('main button[aria-label="Copy the command"]')}.click()`);
  await sleep(400);
  const clip = await evalJs(`navigator.clipboard.readText().catch((e) => 'ERR ' + e.message)`);
  check('C: Copy writes exactly the command that is shown', shown === 'ritueel apply --allow-missing acme-release' && clip === shown, JSON.stringify({ shown, clip }));
  check('C: the Copy answer says the command line is not built yet', /not built yet/.test(await evalJs(`${sel('.MuiSnackbarContent-message')}?.textContent || ''`)));
}
await useBundle('globex');
await go('#/todo');
{
  const t = await flat();
  check('C: globex says "Nothing waits." and names the next end', /Nothing waits\./.test(t) && /The next end is globex-ca, on 2027-11-20, in 361 days\./.test(t), t.slice(0, 300));
  check('C: the time of the read is on screen', /Read 2026-11-24 09:00 UTC/.test(t));
}
await useBundle('acme');

// ======== D. Inventory =====================================================================
await fresh('#/inventory/cards');
{
  const t = await flat();
  check('D: By card has the groups root-a, root-b, day-ana and Cloud keys', ['root-a', 'root-b', 'day-ana', 'Cloud keys'].every((g) => t.includes(g)));
  const table = await textOf('main table');
  // No run of 16 hexadecimal characters in the text as shown, and no group of three groups of four: neither a bare nor a grouped fingerprint.
  check('D: the rows of the list show no fingerprint', !/[0-9A-Fa-f]{16}/.test(table) && !/[0-9A-Fa-f]{4} [0-9A-Fa-f]{4} [0-9A-Fa-f]{4}/.test(table), table.slice(0, 120));
  check('D: the list shows 11 keys and the panel is beside it with the first object implied (root-a)', (await count('main tr[data-key-fp]')) === 11 && (await textOf('#panel-title')) === 'root-a');
  const list = await rectOfSel('main table');
  const panel = await rectOfSel('aside[aria-labelledby=panel-title]');
  check('D: at 1440 px the panel stands at the right of the list', list && panel && panel.left >= list.right && Math.abs(panel.top - list.top) < 140, JSON.stringify({ list, panel }));
  // choose a key: the link of its row
  await evalJs(`${sel(`tr[data-key-fp="${KEY_A}"] a`)}.click()`);
  await sleep(350);
  const panelText = await flat();
  check('D: choosing a key opens its panel with the full fingerprint in groups of four', (await hash()) === `#/inventory/cards/key/${KEY_A}` && /7D44 0B19 7D44 0B19 7D44 0B19 7D44 0B19 7D44 0B19/.test(panelText));
  check('D: the chosen row is marked as current', (await evalJs(`${sel(`tr[data-key-fp="${KEY_A}"] a`)}.getAttribute('aria-current')`)) === 'true');
  check('D: choosing a line does not move the focus at 1440 px', (await active()).id !== 'panel-title');
  await clickButton('By root');
  await sleep(350);
  check('D: the view switch keeps the chosen object', (await hash()) === `#/inventory/roots/key/${KEY_A}` && /7D44 0B19/.test(await flat()));
  await go('#/inventory/dates/certification/cert-8');
  await clickButton('By card');
  await sleep(350);
  check('D: a certification stays chosen in By card, and the panel says it is not listed in this view', (await hash()) === '#/inventory/cards/certification/cert-8' && /Not listed in this view\./.test(await flat()));
}
// the card panel
await go('#/inventory/cards/card/root-a');
{
  check('D: the card panel draws the slot grid', (await count('main button[aria-haspopup=dialog]')) >= 3);
  check('D: the revoke command is text with a Copy button', (await textOf('main code')).includes('ritueel revoke --card root-a --reason REASON') && (await count('main button[aria-label="Copy the command"]')) >= 1);
  await evalJs(`${sel('button[aria-haspopup=dialog]')}.focus()`);
  const slotLabel = (await active()).label;
  await press('Enter');
  await sleep(300);
  check('D: Enter on a slot opens its details', await evalJs(`!!${sel('[role=dialog][aria-label^="Slot"]')}`));
  check('D: the details show the purpose, PIN and touch', /PIN/.test(await text()) && /Touch/.test(await text()));
  await press('Escape');
  await sleep(400);
  check('D: Escape closes the details and the focus returns to the slot', !(await evalJs(`!!${sel('[role=dialog][aria-label^="Slot"]')}`)) && (await active()).label === slotLabel, JSON.stringify(await active()));
}
// Escape in the panel at 1440 px returns the focus to the chosen link
await go('#/inventory/roots/delegation/acme-release');
await evalJs(`document.getElementById('panel-title').focus()`);
await press('Escape');
{
  const a = await active();
  check('D: at 1440 px Escape in the panel returns the focus to the chosen link', a.tag === 'A' && a.current === 'true' && a.row === 'delegation/acme-release', JSON.stringify(a));
}
// 1280 px: the panel replaces the list
await desktop(1280, 900);
await go('#/inventory/cards');
{
  check('D: at 1280 px the list alone is shown when no object is chosen', (await visible('main table, main ul[aria-label]')) && !(await visible('aside[aria-labelledby=panel-title]')));
  await evalJs(`${sel('[data-row-id^="key/"] a')}.click()`);
  await sleep(450);
  check('D: at 1280 px choosing a line replaces the list by the panel and moves the focus to its heading', (await visible('aside[aria-labelledby=panel-title]')) && !(await visible('main table, main ul[aria-label]')) && (await active()).id === 'panel-title', JSON.stringify(await active()));
  const chosen = await hash();
  await evalJs(`([...${selAll('a')}].find((a) => a.textContent.trim() === 'Back to the list')).click()`);
  await sleep(450);
  const a = await active();
  check('D: Back to the list returns to the list and puts the focus on the row that was chosen', (await hash()) === '#/inventory/cards' && a.tag === 'A' && a.row !== '' && chosen.endsWith(a.row.split('/')[1]), `${chosen} ${JSON.stringify(a)}`);
  await go(chosen);
  await evalJs(`document.getElementById('panel-title').focus()`);
  await press('Escape');
  await sleep(450);
  const b = await active();
  check('D: at 1280 px Escape does what Back to the list does', (await hash()) === '#/inventory/cards' && b.tag === 'A' && b.row !== '', `${await hash()} ${JSON.stringify(b)}`);
}
await desktop();

// ======== D2. behaviours of the lists and the panel ==========================================
// The findings filter, the hidden button that goes to the panel, the mark on the implied first row, the
// rows of a table as row headers, the lines of the Apply block, the Back button, and the focus when a link
// inside the panel changes the object.
await fresh('#/todo/findings');
{
  await clickButton('Critical');
  await sleep(500);
  check('D2: the filter Critical on scene 1 says "No finding at this level."', /No finding at this level\./.test(await mainText()), (await mainText()).slice(0, 200));
  await clickButton('All');
  await sleep(500);
  check('D2: the filter All brings the finding back', /1 finding, worst first/.test(await mainText()) && /acme-release ends in 60 days/.test(await mainText()));
}
await useScene(2);
await go('#/todo');
{
  const t = await mainText();
  check('D2: the Apply block of scene 2 names the cards at hand, the allow-missing line and the command', /Cards at hand: root-a, root-b/.test(t) && /unless you name it with --allow-missing/.test(t) && /3 ready, 1 waiting/.test(t), t.slice(0, 400));
  check('D2: each line of the Changes table has a row header (th scope=row), four of them', (await count('main table th[scope=row]')) === 4, String(await count('main table th[scope=row]')));
}
await useScene(1);
await fresh('#/inventory/cards');
{
  check('D2: the implied first row is marked as current at 1440 px', (await evalJs(`${sel('main tr[data-row-id] a')}.getAttribute('aria-current')`)) === 'true' || (await evalJs(`!!document.querySelector('main [aria-current=true]')`)));
  check('D2: the hidden button "Go to the panel" exists at 1440 px', await evalJs(`[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Go to the panel')`));
  await clickButton('Go to the panel');
  await sleep(200);
  check('D2: "Go to the panel" moves the focus to the heading of the panel', (await active()).id === 'panel-title', JSON.stringify(await active()));
}
await desktop(1280, 900);
await go('#/inventory/cards');
{
  await evalJs(`${sel('[data-row-id^="key/"] a')}.click()`);
  await sleep(450);
  const chosen = await hash();
  await evalJs('history.back()');
  await sleep(500);
  const a = await active();
  check('D2: the Back button of the browser returns to the list and puts the focus on the row', (await hash()) === '#/inventory/cards' && a.tag === 'A' && a.row !== '' && chosen.endsWith(a.row.split('/')[1]), `${chosen} ${JSON.stringify(a)}`);
  // A link inside the panel changes the object: the panel starts again and the focus goes to its heading.
  await go(`#/inventory/roots/key/${KEY_A}`);
  const before = await textOf('#panel-title');
  const moved = await evalJs(`(() => { const a = [...document.querySelectorAll('aside[aria-labelledby=panel-title] a')].find((x) => /#\\/inventory\\/roots\\/root\\//.test(x.getAttribute('href') || '')); if (!a) return false; a.focus(); a.click(); return true; })()`);
  await sleep(500);
  check('D2: a link inside the panel (Key to Root) changes the object and the focus goes to the new heading', moved && (await textOf('#panel-title')) !== before && (await active()).id === 'panel-title', JSON.stringify({ moved, before, now: await textOf('#panel-title'), active: await active() }));
}
await desktop();

// ======== E. History ==========================================================================
await fresh('#/history');
{
  const t = await flat();
  check('E: scene 1 folds the two plans that were never run into one line', /2 plans were never run/.test(t) && (await evalJs(`${sel('details')}.open`)) === false);
  await evalJs(`${sel('details summary')}.click()`);
  await sleep(300);
  check('E: opening the fold lists two rows, planned, stale', (await count('details [data-state="planned, stale"]')) === 2);
  check('E: the panel of the newest ceremony shows it as recorded', (await textOf('#panel-title')).startsWith('20261120T100000Z-apply-3fa9c1d2') && /recorded/.test(await textOf('aside[aria-labelledby=panel-title]')));
  check('E: the history line says the end of the history and the count', /14 records/.test(t) && /End of the history d7e8f90a/.test(t));
}
await useScene(3);
await go('#/history');
{
  const rows = JSON.parse(await evalJs(`JSON.stringify([...${selAll('main [data-row-id][data-state]')}].slice(0, 2).map((r) => r.getAttribute('data-state')))`));
  const t = await flat();
  check('E: scene 3 puts a planned ceremony first', rows[0] === 'planned', JSON.stringify(rows));
  check('E: its panel shows the full digest in groups of four and says to type the first eight characters in the terminal, not here', /7d41 e9b3 7d41 e9b3 7d41 e9b3 7d41 e9b3 7d41 e9b3 7d41 e9b3 7d41 e9b3 7d41 e9b3/.test(t) && /Type the first eight characters in the terminal, not here\./.test(t));
}
await useScene(4);
await go('#/history/20261124T100400Z-apply-7d41e9b3');
{
  const t = await flat();
  check('E: scene 4 shows the ceremony as started, with the command to close it as text', (await evalJs(`${sel('[data-row-id][data-state="started"]')} !== null`)) && (await textOf('main code')).includes('ritueel close 20261124T100400Z-apply-7d41e9b3 --reason TEXT') && /started/.test(t));
  check('E: scene 4 marks the To do entry as critical', await evalJs(`!!${sel('aside nav a .bg-critical')}`));
}
await useScene(5);
await go('#/history/20261124T100400Z-apply-7d41e9b3');
{
  const t = await flat();
  check('E: scene 5 shows the ceremony as recorded, with the section After the record and the command ritueel publish', /After the record/.test(t) && (await textOf('main code')).includes('ritueel publish') && (await evalJs(`${sel('[data-row-id][data-state="recorded"]')} !== null`)));
  check('E: scene 5 names the new trust set 14-7d41e9b3', /14-7d41e9b3/.test(t));
}
await useScene(1);
await go('#/history/20250902T100000Z-apply-4d6b21fa');
{
  const closing = await evalJs(`JSON.stringify([...${selAll('aside[aria-labelledby=panel-title] a')}].map((a) => a.getAttribute('href')))`);
  check('E: a closed ceremony shows closed and links to its closing record', (await evalJs(`${sel('[data-row-id][data-state="closed"]')} !== null`)) && closing.includes('#/history/20250903T093000Z-close-0c9e47d1'), closing);
}

// ======== F. Trust set ==========================================================================
await go('#/trust');
{
  const t = await flat();
  check('F: acme shows set 13-3fa9c1d2 with seven files, each with a check word', /Set 13-3fa9c1d2/.test(t) && (await count('main [data-row-id]')) === 7 && (t.match(/\bpassed\b/g) ?? []).length >= 7);
  const codes = JSON.parse(await evalJs(`JSON.stringify([...${selAll('main code')}].map((c) => c.textContent))`));
  const verify = codes.filter((c) => c.startsWith('ritueel verify '));
  check('F: each file has a command that verifies it', verify.length >= 7, String(verify.length));
  let allExact = true;
  const buttons = await count('main button[aria-label="Copy the command"]');
  for (let i = 0; i < buttons; i++) {
    const shown = await evalJs(`${selAll('main button[aria-label="Copy the command"]')}[${i}].closest('[role=group]').querySelector('code').textContent`);
    await evalJs(`${selAll('main button[aria-label="Copy the command"]')}[${i}].click()`);
    await sleep(120);
    const clip = await evalJs(`navigator.clipboard.readText().catch((e) => 'ERR ' + e.message)`);
    if (clip !== shown) {
      allExact = false;
      console.log('   copied differs from shown:', JSON.stringify({ shown, clip }));
    }
  }
  check('F: every Copy writes exactly the command that is shown', buttons >= 7 && allExact, String(buttons));
  check('F: the text says once that the commands are examples', (t.match(/Example only\. The ritueel command line is not built yet\./g) ?? []).length === 1);
}
await useScene(5);
await go('#/trust');
check('F: scene 5 shows set 14-7d41e9b3', /Set 14-7d41e9b3/.test(await flat()));
await useScene(1);
await useBundle('personal');
await go('#/trust');
{
  const t = await flat();
  check('F: personal shows two files and the text that it has no command', (await count('main [data-row-id]')) === 2 && (t.match(/No command: a personal bundle has no root list to check this file against\./g) ?? []).length === 2);
}
await useBundle('acme');

// ======== G. scenes ===============================================================================
await fresh('#/todo');
{
  const names = JSON.parse(await evalJs(`JSON.stringify([...${selAll('[aria-labelledby="scene-switch-label"] button')}].map((b) => b.getAttribute('aria-label')))`));
  check('G: the control offers Scene 1 of 5 to Scene 5 of 5', JSON.stringify(names) === JSON.stringify([1, 2, 3, 4, 5].map((n) => `Scene ${n} of 5`)), JSON.stringify(names));
  const counts = [];
  for (let n = 1; n <= 5; n++) {
    await useScene(n);
    const line = await textOf('[data-testid=scene-line]');
    const todo = await evalJs(`${sel('aside nav a[href="#/todo"]')}.innerText`);
    counts.push(todo.split('\n')[0] + ':' + (todo.match(/\d+/) ?? [''])[0]);
    check(`G: scene ${n}: the live line reads "Scene ${n} of 5: ..." and is a status`, new RegExp(`^Scene ${n} of 5: .{10,}`).test(line) && (await evalJs(`${sel('[data-testid=scene-line]')}.getAttribute('role')`)) === 'status', line);
  }
  check('G: choosing a scene changes the counts of the sidebar', JSON.stringify(counts) === JSON.stringify(['To do:1', 'To do:4', 'To do:4', 'To do:4', 'To do:1']), JSON.stringify(counts));
  await useScene(1);
  await useBundle('globex');
  check('G: the control is absent for globex', (await count('[data-testid=scene-line], [aria-labelledby="scene-switch-label"]')) === 0);
  await useBundle('personal');
  check('G: the control is absent for personal', (await count('[data-testid=scene-line], [aria-labelledby="scene-switch-label"]')) === 0);
  await useBundle('acme');
  await useState('Empty');
  check('G: the control is absent in the Empty state', (await count('[data-testid=scene-line], [aria-labelledby="scene-switch-label"]')) === 0);
  await useState('Failed read');
  check('G: the control is absent in the Failed state', (await count('[data-testid=scene-line], [aria-labelledby="scene-switch-label"]')) === 0);
  await useState('Loaded');
  check('G: the control is back when the page state is Loaded', (await count('[data-testid=scene-line]')) === 1);
  // A scene keeps the screen; an object the scene lacks falls back to its list.
  await useScene(5);
  await go('#/inventory/dates/certification/cert-9');
  const kept = await hash();
  await useScene(1);
  check('G: a scene keeps the screen, and an object the scene lacks falls back to the list of its view', kept === '#/inventory/dates/certification/cert-9' && (await hash()) === '#/inventory/dates', `${kept} ${await hash()}`);
}

// ======== H. page states, I. no text input, J. controls ===========================================
const SCREENS = [
  ['#/todo', /Nothing waits\./, /Reading the changes/],
  ['#/todo/findings', /No findings\./, /Reading the findings/],
  ['#/inventory/cards', /Nothing in the inventory yet\./, /Reading the inventory/],
  ['#/history', /No ceremony yet\./, /Reading the history|Reading the ceremonies/],
  ['#/trust', /No trust set yet\./, /Reading the trust set/],
];
const ACT = /^(apply|sign|run|confirm|revoke|publish)\b/i;
const noInput = () => count('input, textarea, select, [contenteditable]');
const actNames = () =>
  evalJs(`JSON.stringify([...document.querySelectorAll('button, a, [role=tab], [role=menuitem], [role=button]')].map((e) => (e.getAttribute('aria-label') || e.textContent || '').trim()).filter((n) => /^(apply|sign|run|confirm|revoke|publish)\\b/i.test(n)))`).then(JSON.parse);
await fresh('#/todo');
for (const [h, emptyText, waitingText] of SCREENS) {
  await go(h);
  const loaded = await flat();
  await useState('Failed read');
  const failed = await flat();
  check(`H: Failed read on ${h} shows an alert, never an empty page, and the sentence about the ended process`, (await evalJs(`!!${sel('[role=alert]')}`)) && /Could not read/.test(failed) && /the ritueel process may have ended/.test(failed) && !emptyText.test(failed));
  check(`H: Failed read on ${h} shows no time of a read`, !/Read 20\d\d-\d\d-\d\d/.test(await mainText()), failed.slice(0, 160));
  check(`I: no text input on ${h} in the Failed state`, (await noInput()) === 0);
  await useState('Empty');
  const empty = await flat();
  check(`H: Empty on ${h} shows no alert and says what it means`, !(await evalJs(`!!${sel('[role=alert]')}`)) && emptyText.test(empty), empty.slice(0, 200));
  check(`H: Empty on ${h} shows the time of its read`, /Read 2026-11-24 09:00 UTC/.test(await mainText()), empty.slice(0, 200));
  check(`I: no text input on ${h} in the Empty state`, (await noInput()) === 0);
  await useState('Waiting');
  const waiting = await flat();
  check(`H: Waiting on ${h} says it is reading and shows neither empty nor failed`, waitingText.test(waiting) && !/Could not read/.test(waiting) && !emptyText.test(waiting));
  check(`H: Waiting on ${h} shows no time of a read`, !/Read 20\d\d-\d\d-\d\d/.test(await mainText()), waiting.slice(0, 160));
  check(`I: no text input on ${h} in the Waiting state`, (await noInput()) === 0);
  await useState('Loaded');
  check(`H: Loaded again on ${h} returns the data and the time of the read`, (await flat()).length > 200 && !waitingText.test(await flat()) && !/Could not read/.test(await flat()) && /Read 2026-11-24 09:00 UTC/.test(await mainText()));
}
{
  // Waiting does not end by itself.
  await go('#/todo');
  await useState('Waiting');
  await sleep(4200);
  check('H: Waiting is still waiting after the late notice (it does not end by itself)', /Reading the changes/.test(await flat()) && /Still waiting for ritueel/.test(await flat()) && /never answers, on purpose/.test(await flat()));
  await useState('Loaded');
}
for (const [h] of ROUTES) {
  await go(h);
  const inputs = await noInput();
  const acts = await actNames();
  check(`I: no text input on ${h}`, inputs === 0, String(inputs));
  check(`J: no button, link or tab on ${h} is named apply, sign, run, confirm, revoke or publish`, acts.length === 0, JSON.stringify(acts));
}
for (const [bundle, h] of [['globex', '#/todo'], ['globex', '#/inventory/roots'], ['personal', '#/todo/findings'], ['personal', '#/inventory/cards'], ['personal', '#/history'], ['personal', '#/trust']]) {
  await useBundle(bundle);
  await go(h);
  check(`I and J: ${bundle} ${h} has no text input and no control named like an act`, (await noInput()) === 0 && (await actNames()).length === 0);
}
await useBundle('acme');
{
  // The Copy control is named Copy the command or Copy the path.
  await go(`#/inventory/roots/key/${KEY_A}`);
  const names = JSON.parse(await evalJs(`JSON.stringify([...new Set([...document.querySelectorAll('button')].map((b) => b.getAttribute('aria-label') || '').filter((n) => /^copy/i.test(n)))].sort())`));
  check('J: the Copy controls are named "Copy the command" and "Copy the path"', JSON.stringify(names) === '["Copy the command","Copy the path"]', JSON.stringify(names));
}

// ======== K. the focus read ====================================================================
await fresh('#/inventory/roots');
{
  await sleep(1300); // past the quiet second of the data layer
  const before = await flat();
  await evalJs(`window.__seen = []; new MutationObserver(() => { const t = document.body.innerText; if (/Reading the /.test(t)) window.__seen.push(t.slice(0, 80)); }).observe(document.body, { subtree: true, childList: true, characterData: true }); window.dispatchEvent(new Event('focus'))`);
  await sleep(700);
  const after = await flat();
  const seen = await evalJs('window.__seen.length');
  check('K: a focus on the window does not blink to the waiting state', seen === 0, String(seen));
  check('K: the time of the read is still on screen after the focus, and the screen is unchanged', /Read 2026-11-24 09:00 UTC/.test(after) && after === before);
  await useScene(2);
  await sleep(1300);
  const t2 = await flat();
  await evalJs(`window.dispatchEvent(new Event('focus'))`);
  await sleep(600);
  check('K: after a scene, the time of the read is the time of the scene and a focus keeps it', /Read 2026-11-24 09:40 UTC/.test(t2) && /Read 2026-11-24 09:40 UTC/.test(await flat()));
  await useScene(1);
}

// ======== L. layout, measured =====================================================================
// At 1440 by 900 and 1920 by 970, for seven worlds and seven screens: the height as a multiple of the
// window, the width, the longest line of text, the use of the width, and the place of the panel. The
// aims are one screen for To do and one and a half for the others. The table is printed so that it can be
// put into the pull request. A number above its aim is reported under the table and the aim is not
// loosened; a number more than AIM_SLACK above its aim fails, so that a long screen cannot come back unseen.
const AIM_SLACK = 0.15;
const LAYOUT_ROUTES = [
  ['#/todo', 1.0],
  ['#/todo/findings', 1.0],
  ['#/inventory/cards', 1.5],
  ['#/inventory/roots', 1.5],
  ['#/inventory/dates', 1.5],
  ['#/history', 1.5],
  ['#/trust', 1.5],
];
const WORLDS = [
  ['acme scene 1', async () => { await useBundle('acme'); await useScene(1); }],
  ['acme scene 2', async () => { await useBundle('acme'); await useScene(2); }],
  ['acme scene 3', async () => { await useBundle('acme'); await useScene(3); }],
  ['acme scene 4', async () => { await useBundle('acme'); await useScene(4); }],
  ['acme scene 5', async () => { await useBundle('acme'); await useScene(5); }],
  ['globex', async () => { await useBundle('globex'); }],
  ['personal', async () => { await useBundle('personal'); }],
];
/** In the page: the longest line of text, by block and by top of the characters. */
const LONGEST_LINE = `(() => {
  const worst = { chars: 0, text: '' };
  const root = document.body;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const blockOf = (n) => { let e = n.parentElement; while (e && getComputedStyle(e).display.startsWith('inline')) e = e.parentElement; return e; };
  const lines = new Map();
  const range = document.createRange();
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const s = n.nodeValue;
    if (!s.trim() || n.parentElement.closest('.sr-only, script, style')) continue;
    const block = blockOf(n);
    let ids = lines.get(block);
    if (!ids) lines.set(block, (ids = new Map()));
    for (let i = 0; i < s.length; i++) {
      range.setStart(n, i);
      range.setEnd(n, i + 1);
      const r = range.getClientRects()[0];
      if (!r || r.width === 0) continue;
      const key = Math.round(r.top / 4) + ':' + Math.round(r.left / 600);
      const line = ids.get(key) ?? { chars: 0, text: '' };
      line.chars += 1;
      line.text += s[i];
      ids.set(key, line);
    }
  }
  for (const ids of lines.values()) for (const l of ids.values()) if (l.text.trim().length > worst.chars) { worst.chars = l.text.trim().length; worst.text = l.text.trim().slice(0, 90); }
  return JSON.stringify(worst);
})()`;
const table = [];
const over = [];
for (const [w, h] of [[1440, 900], [1920, 970]]) {
  await desktop(w, h);
  await fresh('#/todo');
  for (const [world, setup] of WORLDS) {
    await setup();
    for (const [route, aim] of LAYOUT_ROUTES) {
      await go(route, 250);
      const m = JSON.parse(
        await evalJs(`JSON.stringify({ ratio: document.documentElement.scrollHeight / innerHeight, sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth })`),
      );
      const ratio = Math.round(m.ratio * 100) / 100;
      const where = `${world}, ${route}, ${w}x${h}`;
      table.push({ world, route, size: `${w}x${h}`, ratio, aim });
      // A height above its aim is reported and the aim is the maintainer's, so it is not loosened. Only a height
      // more than AIM_SLACK above the aim is a failure.
      if (m.ratio > aim + 0.005) over.push(`${where}: ${ratio} (aim ${aim})`);
      check(`L: the document is not more than ${AIM_SLACK} above its aim (${where})`, m.ratio <= aim + AIM_SLACK, `${ratio} > ${aim} + ${AIM_SLACK}`);
      check(`L: the document is not wider than the window (${where})`, m.sw <= m.cw, `${m.sw} > ${m.cw}`);
      const noted = (await evalJs(`document.body.innerText`)).match(/Example only\. The ritueel command line is not built yet\./g) ?? [];
      check(`L: the note that a command is an example stands at most once (${where})`, noted.length <= 1, String(noted.length));
      const line = JSON.parse(await evalJs(LONGEST_LINE));
      check(`L: no line of text is longer than 70 characters (${where})`, line.chars <= 70, `${line.chars}: ${line.text}`);
      // The right column reaches the right edge of the window; the list is wide.
      if (route === '#/trust') {
        // Trust set has one table at the full width, and its facts in a strip above it.
        const t = await rectOfSel('main table');
        check(`L: the table reaches within 72 px of the right edge of the window and is at least 900 px wide (${where})`, t && t.innerWidth - t.right <= 72 && t.width >= 900, JSON.stringify(t));
        continue;
      }
      const grid = 'main div.grid.gap-6';
      const cols = await evalJs(
        `(() => { const g = document.querySelector('${grid}'); if (!g || g.children.length < 2) return null; const a = g.children[0].getBoundingClientRect(); const b = g.children[1].getBoundingClientRect(); return JSON.stringify({ listWidth: a.width, rightEdge: b.right, rightLeft: b.left, listRight: a.right, innerWidth }); })()`,
      ).then((v) => (v ? JSON.parse(v) : null));
      if (cols && cols.rightLeft > 0) {
        check(`L: the right column ends within 72 px of the window and the list is at least 600 px wide (${where})`, cols.innerWidth - cols.rightEdge <= 72 && cols.listWidth >= 600, JSON.stringify(cols));
        check(`L: the right column stands beside the list (${where})`, cols.rightLeft >= cols.listRight - 1, JSON.stringify(cols));
      } else if (route === '#/todo/findings' && (await count('main article')) > 0) {
        // With findings, the cards stand in columns over the width and the facts of the bundle follow them
        // (one or two findings: in the next column; more: in a strip). There is no right column to measure.
        const wideCards = await evalJs(`(() => { const a = [...document.querySelectorAll('main article')].map((e) => e.getBoundingClientRect()); return JSON.stringify({ n: a.length, rows: new Set(a.map((r) => Math.round(r.top))).size, innerWidth }); })()`).then(JSON.parse);
        check(`L: ${wideCards.n} findings stand in ${wideCards.rows} row(s), not in one long column (${where})`, wideCards.n <= 1 || wideCards.rows < wideCards.n, JSON.stringify(wideCards));
      } else {
        check(`L: the screen has a list and a right column (${where})`, false, JSON.stringify(cols));
      }
    }
  }
}
console.log('\nHeight of the document as a multiple of the window height (aim: 1.0 for To do, 1.5 for the others)');
console.log('world'.padEnd(14) + '| ' + LAYOUT_ROUTES.map(([r]) => r.replace('#/', '').padEnd(17)).join(''));
for (const size of ['1440x900', '1920x970']) {
  console.log(`-- ${size}`);
  for (const [world] of WORLDS) console.log(world.padEnd(14) + '| ' + LAYOUT_ROUTES.map(([r]) => String(table.find((t) => t.world === world && t.route === r && t.size === size)?.ratio.toFixed(2) ?? '').padEnd(17)).join(''));
}
console.log(over.length ? `Above the aim (reported; a failure only above the aim plus ${AIM_SLACK}):\n  ${over.join('\n  ')}` : 'No screen is above its aim.');
check('L: every height is measured and the table is printed', table.length === 2 * WORLDS.length * LAYOUT_ROUTES.length, String(table.length));
console.log('');
await desktop();
await fresh('#/inventory/cards');
{
  // The panel beside the list at 1440 and 1920, and in place of it at 1280, for an object that is chosen.
  for (const [w, h, beside] of [[1440, 900, true], [1920, 970, true], [1280, 900, false]]) {
    await desktop(w, h);
    await go('#/inventory/roots/key/' + KEY_A);
    await sleep(200);
    const list = await visible('main table, main ul[aria-label]');
    check(`L: at ${w} px the panel is ${beside ? 'beside the list' : 'in place of the list'}`, (await visible('aside[aria-labelledby=panel-title]')) && list === beside, `${list}`);
  }
}
await desktop();

// ======== the phone: bottom bar, no sideways scroll ================================================
await phone(390, 844, 2);
await fresh('#/todo');
{
  const bar = JSON.parse(await evalJs(`JSON.stringify([...${selAll('nav[aria-label=Screens].fixed a')}].map((a) => a.querySelector('span').textContent.trim()))`));
  check('phone: the bottom bar has four entries, To do, Inventory, History, Trust set, and no More', JSON.stringify(bar) === '["To do","Inventory","History","Trust set"]' && !(await evalJs(`[...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'More')`)), JSON.stringify(bar));
  check('phone: the bar shows the count of changes', /1/.test(await textOf('nav[aria-label=Screens].fixed')));
}
await phone(390, 844);
{
  await go('#/todo/findings');
  await evalJs('window.scrollTo(0, 1500)');
  await sleep(300);
  const chip = await evalJs(`(() => { const a = ${sel('a[aria-label^="This is a demo"]')}; if (!a) return null; const r = a.getBoundingClientRect(); return { top: r.top, h: r.height, w: r.width }; })()`);
  check('phone: the DEMO mark stays in view after scrolling', chip && chip.top >= 0 && chip.top < 20 && chip.h >= 44, JSON.stringify(chip));
  await go('#/inventory/cards/card/' + encodeURIComponent(OVERRIDE + 'x'.repeat(6000)));
  check('phone: a hostile address shows a capped panel and the page does not scroll sideways', (await evalJs('document.documentElement.scrollWidth <= window.innerWidth')) && !(await text()).includes(OVERRIDE));
  await go('#/todo');
  const tiny = await evalJs(`(() => { let worst = 99; for (const e of document.querySelectorAll('body *')) { if (e.children.length === 0 && e.textContent.trim() && e.offsetParent !== null) { const s = parseFloat(getComputedStyle(e).fontSize); if (s < worst && !e.closest('svg')) worst = s; } } return worst; })()`);
  check('phone: no text on To do is smaller than 12px at 390', tiny >= 12, String(tiny));
  const lede = await evalJs(`(() => { const p = [...document.querySelectorAll('p')].find((e) => e.textContent.includes('helps you keep a root')); if (!p) return null; const r = p.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, height: innerHeight }; })()`);
  check('phone: the first sentence of what ritueel is lies inside the first screen (390x844)', lede && lede.top >= 0 && lede.bottom <= lede.height, JSON.stringify(lede));
}
// small phone: nothing is wider than the window
await phone(360, 740, 2);
await fresh('#/todo');
{
  check('phone 360x740: the layout viewport is the window and the document does not scroll sideways', (await evalJs('window.innerWidth')) === 360 && (await evalJs('document.documentElement.scrollWidth <= document.documentElement.clientWidth')), await evalJs('document.documentElement.scrollWidth + " > " + document.documentElement.clientWidth'));
  const buttons = JSON.parse(await evalJs(`JSON.stringify([...${selAll('header [aria-label="Colour scheme"] button')}].map((b) => { const r = b.getBoundingClientRect(); return [b.textContent.trim(), Math.round(r.left), Math.round(r.right)]; }))`));
  check('phone 360x740: Auto, Light and Dark all lie inside the window', buttons.length === 3 && buttons.every(([, l, r]) => l >= 0 && r <= 360), JSON.stringify(buttons));
  const bar = await rectOfSel('nav[aria-label=Screens].fixed');
  check('phone 360x740: the bottom bar is not wider than the window', bar && bar.right <= bar.innerWidth && bar.width <= bar.innerWidth, JSON.stringify(bar));
  const last = await rectOfSel('nav[aria-label=Screens].fixed > :last-child');
  check('phone 360x740: Trust set, the last entry, lies inside the window', last && last.left >= 0 && last.right <= last.innerWidth, JSON.stringify(last));
  const rights = JSON.parse(await evalJs(`JSON.stringify(['bundle-switch-label', 'scene-switch-label', 'state-switch-label'].map((id) => { const g = document.querySelector('[aria-labelledby="' + id + '"]'); return [id, g ? Math.round(g.getBoundingClientRect().right) : null]; }))`));
  check('phone 360x740: the three switches of the demo bar end inside the window', rights.every(([, r]) => r !== null && r <= 360), JSON.stringify(rights));
}

// ---- no example text runs into the page's own cut, and no screen scrolls sideways on a phone ---------
const CUT_MARKER = 'cut: the text is longer';
const notCut = async (label) => {
  const whole = await evalJs('document.body.textContent');
  const at = whole.indexOf(CUT_MARKER);
  check(`${label}: no text is cut (the page's own marker is not shown)`, at < 0, at < 0 ? '' : whole.slice(Math.max(0, at - 120), at + 80));
};
const fixture = (bundle, name) => JSON.parse(readFileSync(new URL(`../src/fixtures/${bundle}/inspect.${name}.json`, import.meta.url), 'utf8'));
/** Every address of a bundle: the screens, each object and each ceremony the fixtures hold. */
function routesOf(bundle) {
  const inv = fixture(bundle, 'get-inventory');
  const slug = (kind, list, field) => (inv[list] ?? []).map((o) => `#/inventory/${kind === 'card' ? 'cards' : kind === 'certification' ? 'dates' : 'roots'}/${kind}/${encodeURIComponent(o[field])}`);
  return [
    '#/todo',
    '#/todo/findings',
    '#/inventory/cards',
    '#/inventory/roots',
    '#/inventory/dates',
    ...slug('card', 'cards', 'name'),
    ...slug('root', 'roots', 'name'),
    ...slug('key', 'keys', 'fingerprint'),
    ...slug('userid', 'userIds', 'id'),
    ...slug('delegation', 'delegations', 'name'),
    ...slug('certification', 'certifications', 'id'),
    ...slug('request', 'requests', 'stem'),
    '#/history',
    ...(fixture(bundle, 'list-ceremonies').ceremonies ?? []).map((c) => `#/history/${encodeURIComponent(c.id)}`),
    '#/trust',
  ];
}
const sidewaysPass = async (width, height) => {
  await phone(width, height);
  await fresh('#/todo');
  for (const bundle of ['acme', 'globex', 'personal']) {
    await useBundle(bundle);
    const wide = [];
    const all = routesOf(bundle);
    for (const h of all) {
      await go(h, 220);
      const ok = (await evalJs('document.documentElement.scrollWidth <= document.documentElement.clientWidth')) && (await evalJs('window.innerWidth')) === width;
      if (!ok) wide.push(`${h}: ${await evalJs('document.documentElement.scrollWidth + " > " + document.documentElement.clientWidth')}`);
    }
    check(`at ${width}x${height} none of the ${all.length} addresses of ${bundle} is wider than the window`, wide.length === 0, wide.slice(0, 3).join(' | '));
  }
  await useBundle('acme');
  await useScene(5);
  const wide = [];
  for (const h of ['#/todo', '#/todo/findings', '#/inventory/roots', '#/inventory/dates', '#/history', '#/history/20261124T100400Z-apply-7d41e9b3', '#/trust']) {
    await go(h, 220);
    if (!(await evalJs('document.documentElement.scrollWidth <= document.documentElement.clientWidth'))) wide.push(h);
  }
  check(`at ${width}x${height} no screen of acme scene 5 is wider than the window`, wide.length === 0, wide.join(' '));
  await useScene(1);
};
await sidewaysPass(360, 740);
await sidewaysPass(390, 844);

// ---- the desktop pass: every address of every bundle and scene, without the cut marker ----------------
await desktop();
await fresh('#/todo');
for (const bundle of ['acme', 'globex', 'personal']) {
  await useBundle(bundle);
  for (const scene of bundle === 'acme' ? [1, 2, 3, 4, 5] : [1]) {
    if (bundle === 'acme') await useScene(scene);
    for (const h of scene === 1 ? routesOf(bundle) : ['#/todo', '#/todo/findings', '#/inventory/roots', '#/history', '#/history/20261124T100400Z-apply-7d41e9b3', '#/trust']) {
      await go(h, 220);
      await notCut(`at 1440 ${h} of ${bundle} scene ${scene}`);
    }
  }
}

// ======== M. policy ===========================================================================
check('M: the page logged no error, no exception and no policy violation', problems.length === 0, problems.slice(0, 5).join(' | '));

const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length} of ${results.length} passed in ${Math.round((Date.now() - started) / 1000)} s`);
await close();
if (failed.length) process.exit(1);
