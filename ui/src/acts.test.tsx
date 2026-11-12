import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { attrsOf, emptyWorld, feed, noStyle, plain, WORLDS, type World } from './testkit';
import { BUNDLES } from './testkit';
import type { InventoryView, ObjectSlug } from './lib/route';
import { CeremonyState } from './gen/ritueel/local/v1alpha1/inspect_service_pb';

vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

// The first build of the page has no write (record 0010, rule 7 and the security profile row 7 of
// docs/reference/wizard.md): no control is named like an act, no field takes text, and the only
// controls that do something are Copy (a command or a path) and the choices of the demo bar.
// This test draws every screen of every world and every page state and reads the name of every
// control from the markup.

const ACT = /^(apply|sign|run|confirm|revoke|publish)\b/;

interface Control {
  tag: string;
  name: string;
}

/** The accessible name of every control of the markup: a button, a link, a tab, a menu item, a button input. */
function controlsOf(html: string): Control[] {
  const out: Control[] = [];
  const clean = noStyle(html);
  for (const m of clean.matchAll(/<(button|a)\b([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const attrs = attrsOf(`<${m[1]} ${m[2]}>`);
    out.push({ tag: m[1], name: (attrs['aria-label'] ?? plain(m[3])).toLowerCase().trim() });
  }
  for (const m of clean.matchAll(/<([a-z]+)\b([^>]*\brole="(?:button|tab|menuitem)"[^>]*)>([\s\S]*?)<\/\1>/g)) {
    if (m[1] === 'button' || m[1] === 'a') continue; // counted above
    const attrs = attrsOf(`<${m[1]} ${m[2]}>`);
    out.push({ tag: `${m[1]}[role]`, name: (attrs['aria-label'] ?? plain(m[3])).toLowerCase().trim() });
  }
  for (const m of clean.matchAll(/<input\b([^>]*)>/g)) {
    const attrs = attrsOf(m[0]);
    out.push({ tag: `input[${attrs.type ?? 'text'}]`, name: (attrs['aria-label'] ?? attrs.value ?? '').toLowerCase().trim() });
  }
  return out;
}

/** True if the markup has a control that takes text. */
const takesText = (html: string) => /<(input|textarea|select|form)\b/.test(html) || /\bcontenteditable\b/i.test(html);


describe('the checker itself', () => {
  it('finds a button, a link, a tab and a menu item by their names', () => {
    const html = '<button aria-label="Apply the plan">x</button><a href="#">Revoke key A</a><a role="tab" href="#">Publish</a><div role="menuitem">Sign it</div><input type="submit" value="Run">';
    expect(controlsOf(html).map((c) => c.name)).toEqual(['apply the plan', 'revoke key a', 'publish', 'sign it', 'run']);
    expect(controlsOf(html).filter((c) => ACT.test(c.name))).toHaveLength(5);
    expect(takesText('<input type="text">')).toBe(true);
    expect(takesText('<p contenteditable="true">x</p>')).toBe(true);
    expect(takesText('<form action="#"></form>')).toBe(true);
    expect(takesText('<button>Copy</button>')).toBe(false);
  });
});

const VIEW_OF: Record<ObjectSlug, InventoryView> = { card: 'cards', root: 'roots', key: 'roots', userid: 'roots', delegation: 'roots', certification: 'dates', request: 'roots' };

async function drawn(w: World, state: 'ready' | 'loading' | 'error'): Promise<string[]> {
  const { Todo } = await import('./screens/Todo');
  const { Inventory } = await import('./screens/Inventory');
  const { History } = await import('./screens/History');
  const { Trust } = await import('./screens/Trust');
  const { NotFound } = await import('./screens/NotFound');
  const { Shell } = await import('./ui/Shell');
  feed.world = w;
  feed.state = state;
  const els: ReactElement[] = [
    <Todo tab="changes" />,
    <Todo tab="findings" />,
    <Inventory view="cards" />,
    <Inventory view="roots" />,
    <Inventory view="dates" />,
    <History />,
    <Trust />,
    <NotFound hash="#/plan" />,
    <Shell route={{ name: 'todo', tab: 'changes' }}>
      <p>x</p>
    </Shell>,
  ];
  if (state === 'ready') {
    // Every object in its own view, and every ceremony: the panels hold the commands.
    const inv = w.inventory;
    const objects: [ObjectSlug, string][] = [
      ...inv.cards.map((o): [ObjectSlug, string] => ['card', o.name]),
      ...inv.roots.map((o): [ObjectSlug, string] => ['root', o.name]),
      ...inv.keys.map((o): [ObjectSlug, string] => ['key', o.fingerprint]),
      ...inv.userIds.map((o): [ObjectSlug, string] => ['userid', o.id]),
      ...inv.delegations.map((o): [ObjectSlug, string] => ['delegation', o.name]),
      ...inv.certifications.map((o): [ObjectSlug, string] => ['certification', o.id]),
      ...inv.requests.map((o): [ObjectSlug, string] => ['request', o.stem]),
    ];
    for (const [kind, id] of objects) els.push(<Inventory view={VIEW_OF[kind]} object={{ kind, id }} />);
    for (const c of w.ceremonies.ceremonies) els.push(<History id={c.id} />);
  }
  return els.map((el) => noStyle(renderToStaticMarkup(el)));
}

describe('N5: no control is named like an act, and no field takes text', () => {
  let empties: World[];
  beforeAll(async () => {
    empties = await Promise.all(BUNDLES.map((b) => emptyWorld(b)));
  });

  it('in every world and every page state, no button, link, tab or menu item is named apply, sign, run, confirm, revoke or publish', async () => {
    let met = 0;
    const bad: string[] = [];
    for (const w of [...WORLDS(), ...empties])
      for (const state of ['ready', 'loading', 'error'] as const)
        for (const html of await drawn(w, state))
          for (const c of controlsOf(html)) {
            met += 1;
            if (ACT.test(c.name)) bad.push(`${w.id} ${state}: ${c.tag} "${c.name}"`);
          }
    expect(met, 'the walk met many controls').toBeGreaterThan(5000);
    expect([...new Set(bad)]).toEqual([]);
  });

  it('the Copy control is named "copy the command" or "copy the path", and there are many of them', async () => {
    const names = new Map<string, number>();
    for (const w of [...WORLDS(), ...empties])
      for (const html of await drawn(w, 'ready'))
        for (const c of controlsOf(html)) if (/^copy/.test(c.name)) names.set(c.name, (names.get(c.name) ?? 0) + 1);
    expect([...names.keys()].sort()).toEqual(['copy the command', 'copy the path']);
    expect(names.get('copy the command') ?? 0).toBeGreaterThan(100);
    expect(names.get('copy the path') ?? 0).toBeGreaterThan(10);
  });

  it('no input, textarea, select or contenteditable is drawn anywhere', async () => {
    for (const w of [...WORLDS(), ...empties])
      for (const state of ['ready', 'loading', 'error'] as const)
        for (const html of await drawn(w, state)) expect(takesText(html), `${w.id} ${state}`).toBe(false);
  });

  it('the demo bar draws choices only: toggle buttons for the bundle, the scene and the page state', async () => {
    const { DemoBar } = await import('./ui/DemoBar');
    const html = noStyle(renderToStaticMarkup(<DemoBar />));
    const names = controlsOf(html).map((c) => c.name);
    expect(names).toEqual(expect.arrayContaining(['acme', 'globex', 'personal', 'loaded', 'empty', 'failed read', 'waiting', 'scene 1 of 5', 'scene 5 of 5', 'back to ritueel.id']));
    expect(takesText(html)).toBe(false);
    for (const n of names) expect(ACT.test(n), n).toBe(false);
  });

  it('a revoke command is text with a Copy control, never a control of its own', async () => {
    const { Inventory } = await import('./screens/Inventory');
    const w = WORLDS()[0];
    feed.world = w;
    feed.state = 'ready';
    const html = noStyle(renderToStaticMarkup(<Inventory view="cards" object={{ kind: 'card', id: 'root-a' }} />));
    expect(plain(html)).toContain('ritueel revoke --card root-a --reason REASON');
    expect(controlsOf(html).filter((c) => /revoke/.test(c.name))).toEqual([]);
    expect(html).toMatch(/<code[^>]*>[\s\S]*?ritueel[\s\S]*?revoke/);
    feed.state = 'ready';
  });

  it('the footer of every screen says that the page cannot confirm a ceremony', async () => {
    for (const w of [...WORLDS(), ...empties])
      for (const state of ['ready', 'loading', 'error'] as const) {
        const { Shell } = await import('./ui/Shell');
        feed.world = w;
        feed.state = state;
        for (const route of [{ name: 'todo', tab: 'changes' }, { name: 'history' }, { name: 'trust' }] as const) {
          const t = plain(noStyle(renderToStaticMarkup(<Shell route={route as never}><p>x</p></Shell>)));
          expect(t, `${w.id} ${state} ${route.name}`).toContain('it cannot confirm a ceremony');
        }
      }
  });

  it('the apply block of To do and the plan digest of a planned ceremony say that the page cannot confirm', async () => {
    const { Todo } = await import('./screens/Todo');
    const { History } = await import('./screens/History');
    let planned = 0;
    let applyBlocks = 0;
    for (const w of WORLDS()) {
      feed.world = w;
      feed.state = 'ready';
      const todo = plain(noStyle(renderToStaticMarkup(<Todo tab="changes" />)));
      if (todo.includes('The terminal prints the plan and its digest')) {
        applyBlocks += 1;
        expect(todo, `${w.id} apply block`).toContain('This page cannot confirm.');
      }
      for (const c of w.ceremonies.ceremonies) {
        if (!c.planSha256 || c.state !== CeremonyState.PLANNED) continue;
        const t = plain(noStyle(renderToStaticMarkup(<History id={c.id} />)));
        if (!t.includes('Plan digest')) continue;
        if (t.includes('Compare it with the terminal')) {
          planned += 1;
          expect(t, `${w.id} ${c.id}`).toContain('This page cannot confirm.');
        }
      }
    }
    expect(applyBlocks, 'some world has an apply block').toBeGreaterThan(0);
    expect(planned, 'some ceremony is planned with a digest').toBeGreaterThan(0);
  });

  it('every command that holds REASON or TEXT is followed by a sentence that names the placeholder', async () => {
    let met = 0;
    for (const w of [...WORLDS(), ...empties])
      for (const html of await drawn(w, 'ready'))
        for (const m of html.matchAll(/<code\b[^>]*>([\s\S]*?)<\/code>([\s\S]*?)(?=<code\b|$)/g)) {
          const command = plain(m[1]);
          for (const word of ['REASON', 'TEXT']) {
            if (!new RegExp(`(^| )${word}( |$)`).test(command)) continue;
            met += 1;
            expect(plain(m[2]), `${w.id}: ${command}`).toContain(`Replace ${word} before you use it.`);
          }
        }
    expect(met, 'the walk met commands with a placeholder').toBeGreaterThan(20);
  });
});
