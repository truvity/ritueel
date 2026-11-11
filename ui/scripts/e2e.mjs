// A browser test over the DevTools protocol (headless Chrome, no library):
// keyboard and focus, the slot popover, the colour scheme toggle and its
// stored choice, the wizard, the four states, copy, the phone menu, routes.
// usage: node scripts/e2e.mjs http://127.0.0.1:PORT/demo/
import { clickText, launch, sleep } from './cdp.mjs';

const base = process.argv[2];
if (!base) throw new Error('give the base URL');
const { send, evalJs, close, problems } = await launch();
const results = [];
const check = (name, cond, extra = '') => {
  results.push([name, !!cond]);
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '  ' + extra}`);
};
const KEYS = { Tab: { code: 'Tab', vk: 9 }, Enter: { code: 'Enter', vk: 13, text: '\r' }, Escape: { code: 'Escape', vk: 27 }, ' ': { code: 'Space', vk: 32, text: ' ' } };
async function press(key, shift = false) {
  const k = KEYS[key];
  const base = { key, code: k.code, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers: shift ? 8 : 0 };
  await send('Input.dispatchKeyEvent', { type: k.text ? 'keyDown' : 'rawKeyDown', ...base, text: k.text });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
  await sleep(60);
}
const go = async (hash) => {
  await evalJs(`location.hash = ${JSON.stringify(hash)}`);
  await sleep(500);
};
const active = () => evalJs(`(() => { const a = document.activeElement; return JSON.stringify({ tag: a.tagName, id: a.id, text: (a.textContent || '').trim().slice(0, 40), label: a.getAttribute('aria-label') || '', ring: getComputedStyle(a).outlineStyle + ' ' + getComputedStyle(a).outlineWidth }); })()`).then(JSON.parse);
const text = () => evalJs(`document.body.innerText`);

await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
await send('Page.navigate', { url: base });
await sleep(1200);

// ---- the demo bar: the bundle switch (demo chrome, not part of the contract) -----------------
const switchState = () => evalJs(`JSON.stringify([...document.querySelectorAll('button[aria-pressed]')].map((b) => [b.textContent.trim(), b.getAttribute('aria-pressed')]))`).then(JSON.parse);
const pressed = (all, name) => all.some(([n, on]) => n === name && on === 'true');
check('the demo bar has a bundle switch next to the state switch', /Try a bundle/.test(await text()) && /Try the states/.test(await text()));
const sw0 = await switchState();
check('the switch offers personal, acme and globex, and the demo starts on personal', ['personal', 'acme', 'globex'].every((n) => sw0.some(([x]) => x === n)) && pressed(sw0, 'personal') && !pressed(sw0, 'acme') && !pressed(sw0, 'globex'), JSON.stringify(sw0));
check('the sidebar names the bundle and where it is', /personal/.test(await text()) && /~\/ritueel\/personal/.test(await text()));

// ---- routes, titles, focus -------------------------------------------------
check('Start is the first screen and the tab has a title', (await evalJs('document.title')).startsWith('Start - ritueel local page (demo)'));
await go('#/findings');
check('a change of screen sets the title', (await evalJs('document.title')).startsWith('Findings'));
check('a change of screen moves focus to the heading', (await active()).id === 'page-title');
await go('#/nothing-here');
check('an unknown address says so, and is not another screen', /no such screen/i.test(await text()));
await go('#/cards/00000102');
check('a card that is not in the inventory says so and shows the command', /not in your inventory/i.test(await text()) && /ritueel card adopt --card 00000102/.test(await text()));

// ---- keyboard: skip link, focus ring on MUI controls --------------------------
await send('Page.navigate', { url: 'about:blank' });
await send('Page.navigate', { url: base + '#/start' });
await sleep(1500);
await press('Tab');
const first = await active();
check('the first Tab stop is the skip link', first.text === 'Skip to the page', JSON.stringify(first));
await press('Enter');
check('Enter on the skip link moves focus to the page heading', (await active()).id === 'page-title');
// walk the tab order until a MUI toggle button (colour scheme) and a MUI button have been seen with a ring
let sawToggle = false;
let sawButton = false;
let ringOk = true;
for (let i = 0; i < 60 && !(sawToggle && sawButton); i++) {
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
check('keyboard reaches a MUI ToggleButton and a MUI Button', sawToggle && sawButton);
check('both show the focus ring (solid, 2px or more)', ringOk);

// ---- colour scheme toggle and its stored choice ----------------------------------
const scheme = () => evalJs(`(document.documentElement.hasAttribute('data-dark') ? 'dark' : 'light')`);
await clickText(evalJs, 'Dark');
await sleep(300);
check('Dark sets the dark scheme', (await scheme()) === 'dark');
check('the choice is stored', (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'dark');
const darkBg = await evalJs(`getComputedStyle(document.body).backgroundColor`);
await send('Page.reload');
await sleep(900);
check('after a reload the page is still dark', (await scheme()) === 'dark' && (await evalJs(`getComputedStyle(document.body).backgroundColor`)) === darkBg);
await clickText(evalJs, 'Light');
await sleep(300);
check('Light sets the light scheme', (await scheme()) === 'light' && (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'light');
await clickText(evalJs, 'Auto');
await sleep(300);
check('Auto follows the system', (await evalJs(`localStorage.getItem('ritueel-mode')`)) === 'system');

// ---- slot popover: open by keyboard, Escape, focus returns -------------------------------
await go('#/cards/00000001');
await evalJs(`document.querySelector('button[aria-haspopup=dialog]').focus()`);
const slotLabel = (await active()).label;
await press('Enter');
await sleep(300);
check('Enter on a slot opens its details', (await evalJs(`!!document.querySelector('[role=dialog][aria-label^="Slot"]')`)));
check('the details show the purpose, PIN and touch', /PIN/.test(await text()) && /Touch/.test(await text()));
await press('Escape');
await sleep(400);
check('Escape closes the details', !(await evalJs(`!!document.querySelector('[role=dialog][aria-label^="Slot"]')`)));
check('focus returns to the slot', (await active()).label === slotLabel, JSON.stringify(await active()));
check('the card page also writes every slot out', /What every slot is for/.test(await text()));

// ---- copy -------------------------------------------------------------------------------
await go('#/findings');
await clickText(evalJs, 'Copy');
await sleep(400);
const shownCmd = await evalJs(`document.querySelector('code')?.textContent ?? ''`);
const clip = await evalJs(`navigator.clipboard.readText().catch((e) => 'ERR ' + e.message)`);
check('Copy writes exactly the command that is shown', shownCmd.length > 10 && clip === shownCmd, JSON.stringify({ shownCmd, clip }));
check('Copy answers on screen, and in the demo says nothing ran', /Copied\.|Could not copy/.test(await text()) && /demo/i.test(await evalJs(`document.querySelector('.MuiSnackbarContent-message')?.textContent || ''`)) || /Could not copy/.test(await text()));

// ---- findings filter (min_severity goes through the transport) -----------------------------
await go('#/findings');
check('Findings lists all seven of the personal bundle', /7 findings, worst first/.test(await text()));
await clickText(evalJs, 'Critical only');
await sleep(400);
check('Critical only lists one', /1 finding, worst first/.test(await text()));

// ---- the wizard, in the personal bundle: a key file, run on the offline system ------------------------
await go('#/plan');
const goalsText = await text();
check('the goals grey four goals with their reason', (goalsText.match(/Not now\./g) ?? []).length === 4 && /card connected to this computer/.test(goalsText), String((goalsText.match(/Not now\./g) ?? []).length));
await go('#/plan/retire-subkeys');
await sleep(300);
check('the wizard of the personal bundle asks about subkeys first', /A few choices/.test(await text()) && /Which subkeys do you want to retire/.test(await text()));
await clickText(evalJs, 'Show me the plan');
await sleep(500);
const pplan = await text();
check('the plan retires subkeys, runs on the offline system and shows the digest and the plan.json command', /C41E/i.test(pplan) && /To run it, on the offline system/.test(pplan) && /ritueel run ledger\/20261111T090000Z-personal-subkey-revoke\/plan\.json --confirm/.test(pplan), pplan.slice(0, 200));
check('the plan lists what changes in the bundle', /What changes in the bundle/.test(pplan));
await clickText(evalJs, 'Save the plan');
await sleep(500);
const psaved = await text();
check('the saved plan of the personal bundle: written nowhere, inside the bundle at ledger/<ceremony>/plan.json', /Nothing was written\./.test(psaved) && /Would be written to\s*~\/ritueel\/personal\/ledger\/20261111T090000Z-personal-subkey-revoke\/plan\.json/.test(psaved));
check('it is canonical JSON, and no pending area or .plan file is named', /canonical JSON/.test(psaved) && !/pending/i.test(psaved) && !/\.plan\b/.test(psaved));

// ---- the bundle switch: a company with two roots on two cards -----------------------------------------
// the demo bar picks the bundle; the page goes back to Start, and the bundle of a company has the renewals
await clickText(evalJs, 'acme');
await sleep(500);
check('the bundle switch changes the bundle and sends the page back to Start', /~\/ritueel\/acme/.test(await text()) && (await evalJs('location.hash')) === '#/start');
check('the switch now shows acme as the chosen bundle', pressed(await switchState(), 'acme') && !pressed(await switchState(), 'personal'));
check('Start of acme lists three due items', /3 in the next/i.test(await text()) && /Renew acme-ca/.test(await text()));
await go('#/roots');
check('Roots of acme writes its two roots as acme/A and acme/B', /acme\/A/.test(await text()) && /acme\/B/.test(await text()) && !/personal\/A/.test(await text()));
await go('#/key/B');
check('the key of acme/B says it has certified no delegated key at the moment', /Primary key of\s+acme\/B/.test(await text()) && /certified no delegated key at the moment/.test(await text()));
await go('#/cards');
check('Cards of acme lists two root cards, and no personal serial', /2 cards/.test(await text()) && /00000011/.test(await text()) && /00000012/.test(await text()) && !/00000004/.test(await text()));
await go('#/plan');
check('the goals of acme grey four goals, and suggest one: the renewals', ((await text()).match(/Not now\./g) ?? []).length === 4 && ((await text()).match(/Suggested/gi) ?? []).length === 1 && /Nothing waits to be adopted in this bundle/.test(await text()));
await go('#/plan/renew-due');
await sleep(300);
check('the wizard asks choices first', /A few choices/.test(await text()) && /Which due items go into this plan/.test(await text()));
check('there is no free text field anywhere in the wizard', await evalJs(`document.querySelectorAll('input[type=text], input[type=password], textarea').length === 0`));
await clickText(evalJs, 'Show me the plan');
await sleep(500);
check('after "Show me the plan" the focus is on the page heading', (await active()).id === 'page-title', JSON.stringify(await active()));
const plan = await text();
check('the plan shows its steps, digest and the exact commands', /Steps, in order/.test(plan) && /7F3A/i.test(plan) && /ritueel run/.test(plan) && /deadbeef|DEAD BEEF/i.test(plan.replace(/\s/g, '')));
check('the plan says it runs on the offline system, and the digest is not typed here', /To run it, on the offline system/.test(plan) && /never\s+asks you to type it/i.test(plan.replace(/\n/g, ' ')));
await clickText(evalJs, 'Save the plan');
await sleep(500);
check('after "Save the plan" the focus is on the result', (await active()).id === 'saved-result', JSON.stringify(await active()));
const saved = await text();
check('Save the plan says nothing was written and what would be', /Nothing was written\./.test(saved) && /This is a demo/.test(saved) && /Would be written to/.test(saved) && /"ceremony": "20261111T090000Z-due"/.test(saved));
check('the plan is saved inside the bundle as ledger/<ceremony>/plan.json', /~\/ritueel\/acme\/ledger\/20261111T090000Z-due\/plan\.json/.test(saved) && /ritueel run ledger\/20261111T090000Z-due\/plan\.json --confirm/.test(saved));
check('the saved view shows what to copy and bring, the stick, and the run command', /Copy to the offline system/.test(saved) && /USB stick/.test(saved) && /Bring with you/.test(saved) && /--confirm/.test(saved));
await go('#/plan/add-card');
check('a goal that cannot be planned is refused with its reason', /cannot be planned now/.test(await text()));
// a goal that applies in another bundle is refused here, with the reason the goals screen gives
await go('#/plan/retire-subkeys');
check('a goal of another bundle is refused here, not planned', /cannot be planned now/.test(await text()) && /does not apply to this bundle/.test(await text()));

// ---- the bundle switch: a company with one cloud root, used from the workstation ---------------------
await clickText(evalJs, 'globex');
await sleep(500);
check('switching to globex goes back to Start and names the bundle', /~\/ritueel\/globex/.test(await text()) && (await evalJs('location.hash')) === '#/start' && pressed(await switchState(), 'globex'));
await go('#/roots');
check('Roots of globex writes its one root as globex/A', /globex\/A/.test(await text()) && !/acme\/A/.test(await text()));
await go('#/cards');
check('Cards of globex says there is none, and that a cloud root needs no card', /No cards in the inventory yet/.test(await text()) && /needs no card/.test(await text()));
await go('#/plan/adopt-key');
await sleep(300);
check('the wizard of globex asks about the key first', /A few choices/.test(await text()) && /How will you use this key/.test(await text()));
await clickText(evalJs, 'Show me the plan');
await sleep(500);
const gplan = await text();
check('the plan of a cloud root runs on your workstation, not the offline system', /To run it, on your workstation/.test(gplan) && !/To run it, on the offline system/.test(gplan) && /A92D/i.test(gplan), gplan.slice(0, 200));
await clickText(evalJs, 'Save the plan');
await sleep(500);
const gsaved = await text();
check('the saved plan of globex needs no USB stick and no copy to the offline system', /No stick is needed/.test(gsaved) && !/USB stick/.test(gsaved) && !/Copy to the offline system/.test(gsaved) && /Bring with you/.test(gsaved));
check('it is still saved as ledger/<ceremony>/plan.json inside its bundle', /~\/ritueel\/globex\/ledger\/20261111T090000Z-root-add\/plan\.json/.test(gsaved) && /then, on your workstation/i.test(gsaved.replace(/\n/g, ' ')));
await clickText(evalJs, 'personal');
await sleep(500);
check('switching back to personal goes back to Start', /~\/ritueel\/personal/.test(await text()) && (await evalJs('location.hash')) === '#/start' && pressed(await switchState(), 'personal'));

// ---- the four states ------------------------------------------------------------------------
await go('#/findings');
await clickText(evalJs, 'Empty');
await sleep(500);
check('Empty: findings says there is nothing to check yet', /Nothing to check yet/.test(await text()));
await clickText(evalJs, 'Failed read');
await sleep(500);
const failedText = await text();
check('Failed read: says it could not read, and that this is not empty', /Could not read the findings/.test(failedText) && /not the same as empty/.test(failedText) && !/Nothing to check yet/.test(failedText));
check('Failed read: is an alert with a retry', await evalJs(`!!document.querySelector('[role=alert]') && [...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Try again')`));
await clickText(evalJs, 'Waiting');
await sleep(600);
check('Waiting: says it is reading, and shows neither empty nor failed', /Reading the findings/.test(await text()) && !/Could not read/.test(await text()) && !/Nothing to check yet/.test(await text()));
await clickText(evalJs, 'Loaded');
await sleep(500);
check('Loaded again: the findings are back', /7 findings, worst first/.test(await text()));
for (const hash of ['#/start', '#/roots', '#/key/A', '#/cards', '#/history', '#/trust', '#/plan']) {
  await go(hash);
  await clickText(evalJs, 'Failed read');
  await sleep(500);
  check(`Failed read on ${hash} shows an alert, not an empty page`, await evalJs(`!!document.querySelector('[role=alert]')`) && /Could not read/.test(await text()));
  await clickText(evalJs, 'Empty');
  await sleep(500);
  check(`Empty on ${hash} shows no alert and says what it means`, await evalJs(`!document.querySelector('[role=alert]')`) && /(no |nothing|empty)/i.test(await text()));
  await clickText(evalJs, 'Loaded');
  await sleep(300);
}

// ---- the phone: bottom bar and the More menu ---------------------------------------------------------
await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
await go('#/start');
check('the phone has a bottom bar with the findings count', await evalJs(`!!document.querySelector('nav[aria-label=Screens].fixed') && /7/.test(document.querySelector('nav[aria-label=Screens].fixed').textContent)`));
await clickText(evalJs, 'More');
await sleep(400);
const menu = await evalJs(`[...document.querySelectorAll('[role=menuitem]')].map((e) => e.textContent.trim()).join('|')`);
check('More opens History, Trust files and Make a plan', menu === 'History|Trust files|Make a plan', menu);
await press('Escape');
await sleep(300);
await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
await go('#/findings');
await evalJs('window.scrollTo(0, 1500)');
await sleep(300);
const chip = await evalJs(`(() => { const a = document.querySelector('a[aria-label^="This is a demo"]'); if (!a) return null; const r = a.getBoundingClientRect(); return { top: r.top, h: r.height, w: r.width }; })()`);
check('on a phone the DEMO mark stays in view after scrolling', chip && chip.top >= 0 && chip.top < 20 && chip.h >= 44, JSON.stringify(chip));
await go('#/cards/' + encodeURIComponent('\u202e' + 'x'.repeat(6000)));
const h1 = await evalJs(`document.querySelector('h1')?.textContent ?? ''`);
check('a hostile address shows a capped heading with the override written as a code', h1.length < 100 && h1.includes('U+202E') && !h1.includes('\u202e'), h1.slice(0, 80));
check('and the page does not scroll sideways', await evalJs('document.documentElement.scrollWidth <= window.innerWidth'));
await go('#/start');
const tiny = await evalJs(`(() => { let worst = 99; for (const e of document.querySelectorAll('body *')) { if (e.children.length === 0 && e.textContent.trim() && e.offsetParent !== null) { const s = parseFloat(getComputedStyle(e).fontSize); if (s < worst && !e.closest('svg')) worst = s; } } return worst; })()`);
check('no text on Start is smaller than 12px at 390', tiny >= 12, String(tiny));

check('the page logged no error, no exception and no policy violation', problems.length === 0, problems.slice(0, 5).join(' | '));

const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length} of ${results.length} passed`);
await close();
if (failed.length) process.exit(1);
