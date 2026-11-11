// A browser test over the DevTools protocol (headless Chrome, no library):
// keyboard and focus, the slot popover, the colour scheme toggle and its
// stored choice, the wizard and its step bar, the four states, copy, the phone menu, routes,
// and the help for a first visitor (what ritueel is, the Start-here path, the named switches, the notes).
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
// where the wizard's step bar is: the item marked as the current step, and how many items are done
const stepBar = () =>
  evalJs(`(() => { const ol = document.querySelector('ol[aria-label="Where you are in the wizard"]'); if (!ol) return null; const cur = ol.querySelector('li[aria-current="step"]'); return JSON.stringify({ current: cur ? cur.textContent.replace(/\\s+/g, ' ').trim() : '', done: [...ol.querySelectorAll('li')].filter((li) => /\\(done\\)/.test(li.textContent)).length, items: ol.querySelectorAll('li').length }); })()`).then((v) => (v ? JSON.parse(v) : null));
// base64 of a text, so a value can be put into the page's code without quoting it
const b64 = (t) => Buffer.from(t, 'utf8').toString('base64');
// the rectangle of the first element whose own text matches, relative to the window
const rectOf = (needle, tag = '*') =>
  evalJs(`(() => { const el = [...document.querySelectorAll(atob('${b64(tag)}'))].find((e) => e.children.length === 0 || e.tagName === 'P' ? e.textContent.includes(new TextDecoder().decode(Uint8Array.from(atob('${b64(needle)}'), (c) => c.charCodeAt(0)))) : false); if (!el) return null; const r = el.getBoundingClientRect(); return JSON.stringify({ top: r.top, bottom: r.bottom, height: innerHeight }); })()`).then((v) => (v ? JSON.parse(v) : null));

// the rectangle of the first element that matches a CSS selector, relative to the window (null when there is none)
const rectOfSel = (selector) =>
  evalJs(`(() => { const el = document.querySelector(atob('${b64(selector)}')); if (!el) return null; const r = el.getBoundingClientRect(); return JSON.stringify({ left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height, innerWidth, innerHeight }); })()`).then((v) => (v ? JSON.parse(v) : null));

await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] }).catch(() => {});
await send('Page.navigate', { url: base });
await sleep(1200);

// ---- the demo bar: the bundle switch (demo chrome, not part of the contract) -----------------
const switchState = () => evalJs(`JSON.stringify([...document.querySelectorAll('button[aria-pressed]')].map((b) => [b.textContent.trim(), b.getAttribute('aria-pressed')]))`).then(JSON.parse);
const pressed = (all, name) => all.some(([n, on]) => n === name && on === 'true');
check('the demo bar names its two switches: Example bundle and Page state', /Example bundle/.test(await text()) && /Page state/.test(await text()) && !/Try a bundle|Try the states/.test(await text()));
const sw0 = await switchState();
check('the switch offers personal, acme and globex, and the demo starts on personal', ['personal', 'acme', 'globex'].every((n) => sw0.some(([x]) => x === n)) && pressed(sw0, 'personal') && !pressed(sw0, 'acme') && !pressed(sw0, 'globex'), JSON.stringify(sw0));
check('the sidebar names the bundle and where it is', /personal/.test(await text()) && /~\/ritueel\/personal/.test(await text()));

// ---- routes, titles, focus -------------------------------------------------
check('Start is the first screen and the tab has a title', (await evalJs('document.title')).startsWith('Start - ritueel local page (demo)'));

// ---- the first visit: what ritueel is, and a path (1440 px; the phone is checked at the end) -----------
const lede = await rectOf('helps you keep a root', 'p');
check('Start says in its first sentence what ritueel is, inside the first screen at 1440x900', lede && lede.top >= 0 && lede.bottom <= lede.height, JSON.stringify(lede));
check('the lede explains root, ceremony and history where they first appear', /keep a root \(the key that everything else trusts\)/.test((await text()).replace(/\s+/g, ' ')) && /ceremony \(one sitting at a terminal/.test((await text()).replace(/\s+/g, ' ')) && /history \(the record of every ceremony\)/.test((await text()).replace(/\s+/g, ' ')));
check('Start says what a bundle is, in the Start-here box next to the switch that names it', /Example bundle changes the made-up keys \(a bundle is the directory that holds everything ritueel knows about one set of keys\)/.test((await text()).replace(/\s+/g, ' ')));
const startHere = await rectOf('Start here', 'h2');
check('the Start-here box begins inside the first screen at 1440x900', startHere && startHere.top >= 0 && startHere.top < startHere.height, JSON.stringify(startHere));
const pathLinks = JSON.parse(await evalJs(`JSON.stringify([...document.querySelectorAll('section[aria-labelledby="start-here-h"] ol a')].map((a) => [a.getAttribute('href'), a.textContent.trim()]))`));
check('Start here lists three links, in order: Roots, Findings, Make a plan', JSON.stringify(pathLinks) === JSON.stringify([['#/roots', 'Roots'], ['#/findings', 'Findings'], ['#/plan', 'Make a plan']]), JSON.stringify(pathLinks));
check('the Start-here box explains the two switches in the bar and links to the words', /Example bundle changes the made-up keys/.test((await text()).replace(/\s+/g, ' ')) && /Page state shows each screen/.test((await text()).replace(/\s+/g, ' ')) && /All the words/.test(await text()) && /Read what a root is/.test(await text()));
for (const [i, [hash]] of pathLinks.entries()) {
  await evalJs(`document.querySelectorAll('section[aria-labelledby="start-here-h"] ol a')[${i}].click()`);
  await sleep(500);
  check(`the Start-here link ${i + 1} lands on ${hash}, a screen that exists`, (await evalJs('location.hash')) === hash && !/no such screen/i.test(await text()), await evalJs('location.hash'));
  await go('#/start');
}

// ---- layout, desktop: the sidebar ends at the bottom of the window, whatever the height of the demo bar (1280x900) ----------
// The sidebar used to be sized for a 48 px bar under a 64 px bar, so its last control (Auto, Light, Dark) lay below the window.
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
await go('#/start');
for (const y of [0, 800]) {
  await evalJs(`window.scrollTo(0, ${y})`);
  await sleep(300);
  const group = await rectOfSel('aside [aria-label="Colour scheme"]');
  const dark = await evalJs(`(() => { const b = [...document.querySelectorAll('aside [aria-label="Colour scheme"] button')].find((x) => x.textContent.trim() === 'Dark'); if (!b) return null; const r = b.getBoundingClientRect(); return JSON.stringify({ top: r.top, bottom: r.bottom, innerHeight }); })()`).then((v) => (v ? JSON.parse(v) : null));
  const box = await rectOfSel('aside > div');
  check(`at 1280x900 and scroll ${y} the colour scheme group lies inside the window`, group && group.top >= 0 && group.bottom <= group.innerHeight, JSON.stringify(group));
  check(`at 1280x900 and scroll ${y} the Dark button lies inside the window`, dark && dark.top >= 0 && dark.bottom <= dark.innerHeight, JSON.stringify(dark));
  check(`at 1280x900 and scroll ${y} the sidebar ends at or above the bottom of the window`, box && box.bottom <= box.innerHeight, JSON.stringify(box));
}
await evalJs('window.scrollTo(0, 0)');
await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
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
check('the card page draws the row of another bundle as OTHER, with no key digest', /OTHER/.test(await text()) && /another bundle/.test(await text()));

// ---- copy -------------------------------------------------------------------------------
await go('#/findings');
await clickText(evalJs, 'Copy');
await sleep(400);
const shownCmd = await evalJs(`document.querySelector('code')?.textContent ?? ''`);
const clip = await evalJs(`navigator.clipboard.readText().catch((e) => 'ERR ' + e.message)`);
check('Copy writes exactly the command that is shown', shownCmd.length > 10 && clip === shownCmd, JSON.stringify({ shownCmd, clip }));
check('every command in the demo says the command line is not built yet', /Example only\. The ritueel command line is not built yet\./.test(await text()) && (await evalJs(`document.querySelectorAll('code').length`)) === (await evalJs(`[...document.querySelectorAll('p[role=note]')].filter((p) => /not built yet/.test(p.textContent)).length`)));
check('the Copy toast says the command is an example', /not built yet/.test(await evalJs(`document.querySelector('.MuiSnackbarContent-message')?.textContent || ''`)));
check('Copy answers on screen, and in the demo says the command is an example', /Copied\.|Could not copy/.test(await text()) && /demo/i.test(await evalJs(`document.querySelector('.MuiSnackbarContent-message')?.textContent || ''`)) || /Could not copy/.test(await text()));

// ---- findings filter (min_severity goes through the transport) -----------------------------
await go('#/findings');
check('Findings lists all eight of the personal bundle', /8 findings, worst first/.test(await text()));
check('Findings names the row of root card two that no bundle declares', /Root card two holds a key in row 4 that no bundle declares/.test(await text()));
await clickText(evalJs, 'Critical only');
await sleep(400);
check('Critical only lists one', /1 finding, worst first/.test(await text()));

// ---- the wizard, in the personal bundle: a key file, run in the offline system ------------------------
await go('#/plan');
const goalsText = await text();
check('the goals point to no control that does not exist (no "Cards screen", no "Mark one")', !/Cards screen|Mark one/.test(goalsText) && /No card in this bundle is lost or retired\./.test(goalsText));
check('the goals grey four goals with their reason', (goalsText.match(/Not now\./g) ?? []).length === 4 && /card connected to this computer/.test(goalsText), String((goalsText.match(/Not now\./g) ?? []).length));
await go('#/plan/retire-subkeys');
await sleep(300);
check('the wizard of the personal bundle asks about subkeys first', /A few choices/.test(await text()) && /Which subkeys do you want to retire/.test(await text()));
await clickText(evalJs, 'Show me the plan');
await sleep(500);
const pplan = await text();
check('the plan retires subkeys, runs in the offline system and shows the digest and the plan.json command', /C41E/i.test(pplan) && /To run it, in the offline system/.test(pplan) && /ritueel --dir ~\/ritueel\/personal run history\/20261111T090000Z-personal-subkey-revoke\/plan\.json --confirm/.test(pplan), pplan.slice(0, 200));
check('the plan lists what changes in the bundle', /What changes in the bundle/.test(pplan));
check('the plan of a key file says where it runs: in the offline system, vanilla AirgapOS from the ceremony stick', /Where it runs: in the offline system/.test(pplan) && /vanilla AirgapOS/i.test(pplan) && !/A touch for every signature/.test(pplan), pplan.slice(0, 200));
await clickText(evalJs, 'Save the plan');
await sleep(500);
const psaved = await text();
check('the saved plan of the personal bundle: written nowhere, inside the bundle at history/<ceremony>/plan.json', /Nothing was written\./.test(psaved) && /Would be written to\s*~\/ritueel\/personal\/history\/20261111T090000Z-personal-subkey-revoke\/plan\.json/.test(psaved));
const pbar = await stepBar();
check('after "Save the plan" the step bar reaches Save, with Goal, Choices and Plan done', pbar && /Save/.test(pbar.current) && pbar.items === 4 && pbar.done === 3, JSON.stringify(pbar));
check('the saved plan of the personal bundle has the stick step, titled On the ceremony stick', /On the ceremony stick/.test(psaved) && /extra partition/.test(psaved) && !/Copy to the offline system/.test(psaved));
check('it is canonical JSON, and no pending area or .plan file is named', /canonical JSON/.test(psaved) && !/pending/i.test(psaved) && !/\.plan\b/.test(psaved));

// ---- the bundle switch: a company with two roots on two cards -----------------------------------------
// the demo bar picks the bundle; the page keeps the screen, except for a detail view the new bundle cannot show
// (the wizard of retire-subkeys, which personal offers and acme does not, falls back to the goals), and the bundle of a company has the renewals
await clickText(evalJs, 'acme');
await sleep(500);
check('the bundle switch changes the bundle, and a goal acme does not offer falls back to the list of goals', /~\/ritueel\/acme/.test(await text()) && (await evalJs('location.hash')) === '#/plan');
check('the switch now shows acme as the chosen bundle', pressed(await switchState(), 'acme') && !pressed(await switchState(), 'personal'));
await go('#/start');
check('Start of acme lists three due items', /3 in the next/i.test(await text()) && /Renew acme-ca/.test(await text()));
await go('#/roots');
check('Roots of acme writes its two roots as acme/A and acme/B', /acme\/A/.test(await text()) && /acme\/B/.test(await text()) && !/personal\/A/.test(await text()));
await go('#/key/B');
check('the key of acme/B says it has certified no delegated key at the moment', /Primary key of\s+acme\/B/.test(await text()) && /certified no delegated key at the moment/.test(await text()));
await go('#/cards');
check('Cards of acme lists two root cards, and no personal serial', /2 cards/.test(await text()) && /00000011/.test(await text()) && /00000012/.test(await text()) && !/00000004/.test(await text()));
await go('#/history');
const ahist = await text();
check('History of acme says where each ceremony ran: on the workstation, and in the offline system for the first', /ran on the workstation/.test(ahist) && /ran in the offline system/.test(ahist));
await go('#/history/20260602T142000Z-card-check');
check('the detail of a record shows where it ran', /Where it ran/.test(await text()) && /On the workstation/.test(await text()));
await go('#/trust');
const atrust = await text();
check('Trust files of acme: six files in trust/7/, and no package file', /6 files/.test(atrust) && /trust\/7\//.test(atrust) && !/rpm/i.test(atrust), atrust.slice(0, 200));
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
check('the plan shows its steps, digest and the exact commands', /Steps, in order/.test(plan) && /7F3A/i.test(plan) && /ritueel --dir ~\/ritueel\/acme run/.test(plan) && /deadbeef|DEAD BEEF/i.test(plan.replace(/\s/g, '')));
check('the plan says it runs on your workstation, and the digest is not typed here', /To run it, on your workstation/.test(plan) && /never\s+asks you to type it/i.test(plan.replace(/\n/g, ' ')));
check('the plan of acme states the four conditions with its counts, and has no stick', /Where it runs/.test(plan) && /7 signatures/.test(plan) && /A touch for every signature/.test(plan) && /No retry/.test(plan) && /second device/.test(plan) && !/USB stick/.test(plan) && !/On the ceremony stick/.test(plan), plan.slice(0, 200));
const abar = await stepBar();
check('before saving, the step bar is on Plan, not on Save', abar && /Plan/.test(abar.current) && !/Save/.test(abar.current) && abar.done === 2, JSON.stringify(abar));
await clickText(evalJs, 'Save the plan');
await sleep(500);
check('after "Save the plan" the focus is on the result', (await active()).id === 'saved-result', JSON.stringify(await active()));
const saved = await text();
check('Save the plan says nothing was written and what would be', /Nothing was written\./.test(saved) && /This is a demo/.test(saved) && /Would be written to/.test(saved) && /"ceremony": "20261111T090000Z-due"/.test(saved));
check('the plan is saved inside the bundle as history/<ceremony>/plan.json', /~\/ritueel\/acme\/history\/20261111T090000Z-due\/plan\.json/.test(saved) && /ritueel --dir ~\/ritueel\/acme run history\/20261111T090000Z-due\/plan\.json --confirm/.test(saved));
check('the saved view of acme shows what to bring and the run command, and no stick step', !/USB stick/.test(saved) && !/On the ceremony stick/.test(saved) && /No stick is needed/.test(saved) && /Bring with you/.test(saved) && /second device/.test(saved) && /--confirm/.test(saved));
await go('#/plan/add-card');
check('a goal that cannot be planned is refused with its reason', /cannot be planned now/.test(await text()));
// a goal that applies in another bundle is refused here, with the reason the goals screen gives
await go('#/plan/retire-subkeys');
check('a goal of another bundle is refused here, not planned', /cannot be planned now/.test(await text()) && /does not apply to this bundle/.test(await text()));

// ---- the bundle switch: a company with one cloud root, used from the workstation ---------------------
// the key of acme/B is a detail view that globex lacks: the page falls back to Roots, not to Start
await go('#/key/B');
await clickText(evalJs, 'globex');
await sleep(500);
check('switching to globex names the bundle, and the key of acme/B falls back to Roots', /~\/ritueel\/globex/.test(await text()) && (await evalJs('location.hash')) === '#/roots' && pressed(await switchState(), 'globex'));
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
check('the plan of a cloud root runs on your workstation, not in the offline system', /To run it, on your workstation/.test(gplan) && !/To run it, in the offline system/.test(gplan) && /A92D/i.test(gplan), gplan.slice(0, 200));
check('the plan of a cloud root says a cloud key has no touch, asks for 0 touches and marks nothing as proposed', /a cloud key has no touch/i.test(gplan) && !/Proposed/.test(gplan) && /0 touches/.test(gplan) && /second device/.test(gplan), gplan.slice(0, 200));
await clickText(evalJs, 'Save the plan');
await sleep(500);
const gsaved = await text();
check('the saved plan of globex needs no USB stick and no stick step', /No stick is needed/.test(gsaved) && !/USB stick/.test(gsaved) && !/On the ceremony stick/.test(gsaved) && /Bring with you/.test(gsaved));
check('it is still shown saved as history/<ceremony>/plan.json inside its bundle', /~\/ritueel\/globex\/history\/20261111T090000Z-root-add\/plan\.json/.test(gsaved) && /then, on your workstation/i.test(gsaved.replace(/\n/g, ' ')));
// a screen every bundle has stays where it is
await go('#/trust');
await clickText(evalJs, 'personal');
await sleep(500);
check('switching back to personal keeps the Trust files screen', /~\/ritueel\/personal/.test(await text()) && (await evalJs('location.hash')) === '#/trust' && pressed(await switchState(), 'personal'));
await go('#/cards/00000004');
await clickText(evalJs, 'acme');
await sleep(500);
check('a card of personal is not in acme: the page falls back to Cards, and shows the cards of acme', (await evalJs('location.hash')) === '#/cards' && /00000011/.test(await text()) && !/00000004/.test(await text()));
await clickText(evalJs, 'personal');
await sleep(500);
check('Cards stays on Cards when the bundle changes back', (await evalJs('location.hash')) === '#/cards' && /00000004/.test(await text()));

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
check('Waiting: says at once that ritueel never answers here, on purpose, and how to end the wait', /never answers, on purpose/.test(await text()) && /Choose another page state to end the wait/.test(await text()));
await sleep(3800);
check('Waiting: it is still waiting after the late notice (it does not end by itself)', /Reading the findings/.test(await text()) && /Still waiting for ritueel/.test(await text()) && !/8 findings/.test(await text()));
await clickText(evalJs, 'Loaded');
await sleep(500);
check('Loaded again: the findings are back, and the wait is over', /8 findings, worst first/.test(await text()) && !/never answers, on purpose/.test(await text()));

// ---- Empty: the wizard answers by itself, never with the loaded bundle's made-up data -----------------
await go('#/plan');
await clickText(evalJs, 'Empty');
await sleep(500);
const emptyGoals = await text();
check('Empty: the goals say a card goal cannot be planned because the bundle holds no card, and point to no screen', /The bundle holds no card yet\./.test(emptyGoals) && /No card is registered yet, and the demo has no card to connect\./.test(emptyGoals) && !/Cards screen|Mark one/.test(emptyGoals));
await go('#/plan/add-card');
check('Empty: a card goal is refused, not planned from the loaded bundle', /cannot be planned now/.test(await text()) && !/personal-subkey-revoke/.test(await text()));
await go('#/plan/retire-subkeys');
check('Empty: a goal that needs a key is refused too', /cannot be planned now/.test(await text()) && !/personal-subkey-revoke|C41E/i.test(await text()));
await go('#/plan/adopt-key');
await sleep(300);
check('Empty: the one goal that applies asks its choices', /A few choices/.test(await text()));
await clickText(evalJs, 'Show me the plan');
await sleep(500);
const eplan = await text();
check('Empty: the plan says it is an example of an empty bundle, and holds nothing of the loaded personal bundle', /this bundle is empty/.test(eplan) && /The key named here is made up/.test(eplan) && !/personal-subkey-revoke|C41E/i.test(eplan), eplan.slice(0, 200));
// the wizard stays on adopt-key in another bundle (the address is kept), but its answers do not: it asks again
await clickText(evalJs, 'acme');
await sleep(500);
check('Empty: switching the bundle on the plan keeps the goal and asks the choices again', (await evalJs('location.hash')) === '#/plan/adopt-key' && /A few choices/.test(await text()) && /~\/ritueel\/acme/.test(await text()));
await clickText(evalJs, 'personal');
await sleep(500);
await clickText(evalJs, 'Show me the plan');
await sleep(500);
await clickText(evalJs, 'Save the plan');
await sleep(500);
const esaved = await text();
const ebar = await stepBar();
check('Empty: saving shows the common adoption plan only, with nothing written', /Nothing was written\./.test(esaved) && !/personal-subkey-revoke/.test(esaved));
check('Empty: the step bar reaches Save after saving', ebar && /Save/.test(ebar.current) && ebar.done === 3, JSON.stringify(ebar));
await clickText(evalJs, 'Loaded');
await sleep(500);
check('Loaded again from the Empty wizard: the step bar is no longer on Save (the saved plan left the screen)', !(await stepBar())?.current?.includes('Save'));
await go('#/start');
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
check('the phone has a bottom bar with the findings count', await evalJs(`!!document.querySelector('nav[aria-label=Screens].fixed') && /8/.test(document.querySelector('nav[aria-label=Screens].fixed').textContent)`));
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

// ---- the first visit on a phone ----------------------------------------------------------------------
const plede = await rectOf('helps you keep a root', 'p');
check('on a phone the first sentence of what ritueel is lies inside the first screen (390x844)', plede && plede.top >= 0 && plede.bottom <= plede.height, JSON.stringify(plede));
const pstart = await rectOf('Start here', 'h2');
check('on a phone the Start-here box begins inside the first screen (390x844)', pstart && pstart.top >= 0 && pstart.top < pstart.height, JSON.stringify(pstart));
// The three Start-here links lie above the fixed bottom bar at scroll 0: checked at 390x844 here and at 360x740 in the layout section.
const startHereAboveBar = async (name, size) => {
  await evalJs('window.scrollTo(0, 0)');
  await sleep(200);
  const found = JSON.parse(
    await evalJs(`JSON.stringify((() => { const bar = document.querySelector('nav[aria-label=Screens].fixed'); const barTop = bar ? bar.getBoundingClientRect().top : innerHeight; return { barTop, height: innerHeight, links: [...document.querySelectorAll('section[aria-labelledby="start-here-h"] ol a')].map((a) => { const r = a.getBoundingClientRect(); return [a.textContent.trim(), Math.round(r.top), Math.round(r.bottom)]; }) }; })())`),
  );
  check(
    `${name} the three Start-here links are fully visible above the bottom bar on first load (${size})`,
    found.links.length === 3 && found.barTop < found.height && found.links.every(([, top, bottom]) => top >= 0 && bottom <= found.barTop),
    JSON.stringify(found),
  );
};
await startHereAboveBar('on a phone', '390x844');
check('on a phone the Start-here box still says the data is made up, and explains the switches, below the links', /Everything on this page is made up\./.test(await text()) && /Example bundle changes the made-up keys/.test((await text()).replace(/\s+/g, ' ')));
check('on a phone the demo bar keeps its two switches, and the page does not scroll sideways', /Example bundle/.test(await text()) && /Page state/.test(await text()) && (await evalJs('document.documentElement.scrollWidth <= window.innerWidth')));

// ---- layout, small phone (360x740): nothing is wider than the window, and the first screen still holds the path ---------------
// At 360 px the header was 368 px wide: Dark was cut, the document scrolled sideways, the layout viewport widened and pushed More off the bottom bar.
// The pixel values behind these limits are estimates; this check is the measurement.
await send('Emulation.setDeviceMetricsOverride', { width: 360, height: 740, deviceScaleFactor: 2, mobile: true });
await send('Page.navigate', { url: base });
await sleep(1200);
await go('#/start');
check('at 360x740 the layout viewport is the window (nothing widens it)', (await evalJs('window.innerWidth')) === 360, String(await evalJs('window.innerWidth')));
check('at 360x740 the document does not scroll sideways', await evalJs('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), await evalJs('document.documentElement.scrollWidth + " > " + document.documentElement.clientWidth'));
const schemeButtons = JSON.parse(await evalJs(`JSON.stringify([...document.querySelectorAll('header [aria-label="Colour scheme"] button')].map((b) => { const r = b.getBoundingClientRect(); return [b.textContent.trim(), Math.round(r.left), Math.round(r.right)]; }))`));
check('at 360x740 Auto, Light and Dark all lie inside the window', schemeButtons.length === 3 && schemeButtons.every(([, left, right]) => left >= 0 && right <= 360), JSON.stringify(schemeButtons));
const fixedBar = await rectOfSel('nav[aria-label=Screens].fixed');
check('at 360x740 the bottom bar is not wider than the window', fixedBar && fixedBar.right <= fixedBar.innerWidth && fixedBar.width <= fixedBar.innerWidth, JSON.stringify(fixedBar));
const lastTab = await rectOfSel('nav[aria-label=Screens].fixed > :last-child');
check('at 360x740 More, the last tab, lies inside the window', lastTab && lastTab.left >= 0 && lastTab.right <= lastTab.innerWidth, JSON.stringify(lastTab));
await startHereAboveBar('at 360x740', '360x740');
const switchRights = JSON.parse(await evalJs(`JSON.stringify(['bundle-switch-label', 'state-switch-label'].map((id) => { const g = document.querySelector('[aria-labelledby="' + id + '"]'); if (!g) return [id, null]; return [id, Math.round(g.getBoundingClientRect().right)]; }))`));
check('at 360x740 the Example bundle and Page state switches end inside the window', switchRights.every(([, right]) => right !== null && right <= 360), JSON.stringify(switchRights));
check('at 360x740 the three links of Start here keep their text and order', (await evalJs(`JSON.stringify([...document.querySelectorAll('section[aria-labelledby="start-here-h"] ol a')].map((a) => a.textContent.trim()))`)) === '["Roots","Findings","Make a plan"]');

// ---- no screen scrolls sideways on a phone: 360x740 and 390x844 -------------------------------------
// The long unbreakable strings (the run command, a digest, a path in a record, a row of the cards) must wrap inside the window. Each screen is
// measured, not only Start: the document must not be wider than the window and the window must be the size asked for.
const sidewaysCheck = async (label, width) => {
  const wide = await evalJs('document.documentElement.scrollWidth + " > " + document.documentElement.clientWidth');
  check(`${label}: the document is not wider than the window, and the window is ${width} px`, (await evalJs('document.documentElement.scrollWidth <= document.documentElement.clientWidth')) && (await evalJs('window.innerWidth')) === width, wide);
};
const sidewaysPass = async (width, height) => {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: true });
  await send('Page.navigate', { url: base });
  await sleep(1200);
  const size = `${width}x${height}`;
  for (const hash of ['#/start', '#/roots', '#/key/A', '#/findings', '#/cards', '#/cards/00000003', '#/history', '#/history/20261103T142000Z-init', '#/trust', '#/plan']) {
    await go(hash);
    await sidewaysCheck(`at ${size} ${hash} of personal`, width);
  }
  await go('#/plan/retire-subkeys');
  await sleep(300);
  await clickText(evalJs, 'Show me the plan');
  await sleep(500);
  await sidewaysCheck(`at ${size} the plan of personal`, width);
  await clickText(evalJs, 'Save the plan');
  await sleep(500);
  await sidewaysCheck(`at ${size} the saved plan of personal`, width);
  await go('#/start');
  await clickText(evalJs, 'acme');
  await sleep(500);
  for (const hash of ['#/roots', '#/cards', '#/history/20260602T142000Z-card-check', '#/trust']) {
    await go(hash);
    await sidewaysCheck(`at ${size} ${hash} of acme`, width);
  }
  await go('#/plan/renew-due');
  await sleep(300);
  await clickText(evalJs, 'Show me the plan');
  await sleep(500);
  await sidewaysCheck(`at ${size} the plan of acme`, width);
  await clickText(evalJs, 'Save the plan');
  await sleep(500);
  await sidewaysCheck(`at ${size} the saved plan of acme`, width);
  await go('#/start');
  await clickText(evalJs, 'personal');
  await sleep(500);
};
await sidewaysPass(360, 740);
await sidewaysPass(390, 844);

check('the page logged no error, no exception and no policy violation', problems.length === 0, problems.slice(0, 5).join(' | '));

const failed = results.filter(([, ok]) => !ok);
console.log(`\n${results.length - failed.length} of ${results.length} passed`);
await close();
if (failed.length) process.exit(1);
