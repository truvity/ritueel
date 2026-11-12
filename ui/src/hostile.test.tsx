import { describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CeremonyState } from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { BAD, feed, loadWorld, markedWorld, plain, WORLDS, type World } from './testkit';
import type { InventoryView, ObjectSlug } from './lib/route';

vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

// Every string that comes from the bundle is data. This test gives each screen a world
// (the three example bundles, and scenes 2 to 5 of acme) in which EVERY string field ends in
// a bidirectional override, a joiner and a BEL (control) character, renders the screen, and
// fails if any of those characters reaches the markup raw, in a text node or in an
// attribute such as aria-label or title. A string a screen forgot to pass through T or
// safeString shows up here.

const RANGES: [number, number][] = [[0, 8], [0xb, 0x1f], [0x7f, 0x9f], [0xad, 0xad], [0x61c, 0x61c], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0xfeff, 0xfeff]];
const hex = (n: number) => '\\u' + n.toString(16).padStart(4, '0');
const RAW = new RegExp('[' + RANGES.map(([a, b]) => (a === b ? hex(a) : hex(a) + '-' + hex(b))).join('') + ']');

function offending(html: string): string[] {
  const seen = new Set<string>();
  for (const m of html.matchAll(new RegExp('(?:' + RAW.source + ')+', 'g'))) {
    const at = m.index ?? 0;
    seen.add(JSON.stringify(html.slice(Math.max(0, at - 36), at + 1).replace(/^[^<"=>]*/, '')));
  }
  return [...seen].slice(0, 12);
}

const noStyle = (html: string) => html.replace(/<style[\s\S]*?<\/style>/g, '');

const VIEW_OF: Record<ObjectSlug, InventoryView> = { card: 'cards', root: 'roots', key: 'roots', userid: 'roots', delegation: 'roots', certification: 'dates', request: 'roots' };

/** Every object of a world as the route names it, with the view that shows it. */
function objectsOf(w: World): { kind: ObjectSlug; id: string; view: InventoryView }[] {
  const inv = w.inventory;
  const list: [ObjectSlug, string][] = [
    ...inv.cards.map((o): [ObjectSlug, string] => ['card', o.name]),
    ...inv.roots.map((o): [ObjectSlug, string] => ['root', o.name]),
    ...inv.keys.map((o): [ObjectSlug, string] => ['key', o.fingerprint]),
    ...inv.userIds.map((o): [ObjectSlug, string] => ['userid', o.id]),
    ...inv.delegations.map((o): [ObjectSlug, string] => ['delegation', o.name]),
    ...inv.certifications.map((o): [ObjectSlug, string] => ['certification', o.id]),
    ...inv.requests.map((o): [ObjectSlug, string] => ['request', o.stem]),
  ];
  return list.map(([kind, id]) => ({ kind, id, view: VIEW_OF[kind] }));
}

async function screens(w: World): Promise<[string, () => ReactElement][]> {
  const { Todo } = await import('./screens/Todo');
  const { Inventory } = await import('./screens/Inventory');
  const { History } = await import('./screens/History');
  const { Trust } = await import('./screens/Trust');
  const { NotFound } = await import('./screens/NotFound');
  const { Shell } = await import('./ui/Shell');
  const list: [string, () => ReactElement][] = [
    ['to do', () => <Todo tab="changes" />],
    ['findings', () => <Todo tab="findings" />],
    ['inventory by card', () => <Inventory view="cards" />],
    ['inventory by root', () => <Inventory view="roots" />],
    ['inventory by date', () => <Inventory view="dates" />],
    ['history', () => <History />],
    ['trust set', () => <Trust />],
    ['not found', () => <NotFound hash={'#/x/' + BAD} />],
    ['frame', () => (
      <Shell route={{ name: 'todo', tab: 'changes' }}>
        <p>x</p>
      </Shell>
    )],
    // The routes with hostile ids: an object or a ceremony the bundle does not hold, named by an address.
    ['object route param', () => <Inventory view="cards" object={{ kind: 'card', id: 'nope' + BAD }} />],
    ['key route param', () => <Inventory view="roots" object={{ kind: 'key', id: 'nope' + BAD }} />],
    ['history route param', () => <History id={'nope' + BAD} />],
  ];
  // Each object in its own view, and in the other two views (where the panel says it is not listed).
  for (const o of objectsOf(w)) for (const view of ['cards', 'roots', 'dates'] as const) list.push([`${o.kind} ${o.id} in ${view}`, () => <Inventory view={view} object={{ kind: o.kind, id: o.id }} />]);
  for (const c of w.ceremonies.ceremonies) list.push([`ceremony ${c.id}`, () => <History id={c.id} />]);
  return list;
}

describe('hostile text never reaches the markup raw', () => {
  it('the marker is a bidi override, a joiner and a control character', () => {
    expect(RAW.test(BAD)).toBe(true);
  });
  for (const plainWorld of WORLDS()) {
    it(`every screen of ${plainWorld.id}, with every string of the world marked`, async () => {
      const w = markedWorld(plainWorld);
      feed.world = w;
      feed.state = 'ready';
      const list = await screens(w);
      // The world is the one it is said to be: the test would prove nothing on an empty one.
      expect(w.inventory.keys.length).toBeGreaterThan(3);
      expect(list.length).toBeGreaterThanOrEqual(12 + 3 * objectsOf(w).length + w.ceremonies.ceremonies.length);
      const failures: string[] = [];
      let sawEscape = 0;
      for (const [name, render] of list) {
        const html = noStyle(renderToStaticMarkup(render()));
        const bad = offending(html);
        if (bad.length) failures.push(`${name}:\n   ${bad.join('\n   ')}`);
        if (html.includes('U+202E')) sawEscape += 1;
      }
      expect(failures).toEqual([]);
      // The marked world did reach the screens, drawn as escapes: nearly every screen shows some of it.
      expect(sawEscape, `${plainWorld.id}: screens that show an escape`).toBeGreaterThanOrEqual(list.length - 6);
    });
  }

  it('the page states that read nothing draw no data at all, and still no raw character', async () => {
    const w = markedWorld(loadWorld('acme', 1));
    feed.world = w;
    const { Todo } = await import('./screens/Todo');
    const { Inventory } = await import('./screens/Inventory');
    const { History } = await import('./screens/History');
    const { Trust } = await import('./screens/Trust');
    for (const state of ['loading', 'error'] as const) {
      feed.state = state;
      for (const el of [<Todo tab="changes" />, <Todo tab="findings" />, <Inventory view="roots" />, <History />, <Trust />]) {
        const html = noStyle(renderToStaticMarkup(el));
        expect(offending(html), state).toEqual([]);
        expect(html, state).not.toContain('U+202E');
      }
    }
    feed.state = 'ready';
  });

  it('the marked name of the bundle reaches the frame, the heading line and the command as an escape, never raw', async () => {
    const w = markedWorld(loadWorld('acme', 1));
    feed.world = w;
    feed.state = 'ready';
    const { History } = await import('./screens/History');
    const { Inventory } = await import('./screens/Inventory');
    const { Shell } = await import('./ui/Shell');
    // Each escape is a span of its own: read the text with the tags removed and no space put in their place.
    const flat = (el: ReactElement) => noStyle(renderToStaticMarkup(el)).replace(/<[^>]*>/g, '');
    const head = flat(<History />);
    expect(head).toContain('acmeU+202EU+200DU+0007');
    const inv = flat(<Inventory view="cards" object={{ kind: 'card', id: w.inventory.cards[0].name }} />);
    // The revoke command of the card is the program's text: the marker after it is an escape in the command.
    expect(inv).toContain('REASONU+202EU+200DU+0007');
    const frame = flat(
      <Shell route={{ name: 'trust' }}>
        <p>x</p>
      </Shell>,
    );
    expect(frame).toContain('acmeU+202EU+200DU+0007');
  });

  it('a count of one reads in the singular wherever the page builds a count', async () => {
    const { Todo } = await import('./screens/Todo');
    const { History } = await import('./screens/History');
    const { Inventory } = await import('./screens/Inventory');
    const { Trust } = await import('./screens/Trust');
    const text = (el: ReactElement) => plain(noStyle(renderToStaticMarkup(el)));
    // One record: globex cut to its newest ceremony.
    const one = loadWorld('globex', 1);
    one.ceremonies.ceremonies = one.ceremonies.ceremonies.slice(0, 1);
    if (one.ceremonies.history) one.ceremonies.history.recordCount = 1;
    if (one.summary.history) one.summary.history.recordCount = 1;
    feed.world = one;
    feed.state = 'ready';
    expect(text(<History />)).toMatch(/\b1 record\b/);
    expect(text(<History />)).not.toMatch(/\b1 records\b/);
    expect(text(<Todo tab="changes" />)).toMatch(/\b1 record\b/);
    // One plan that was never run: acme without one of its two stale plans.
    const plan = loadWorld('acme', 1);
    plan.ceremonies.ceremonies = plan.ceremonies.ceremonies.filter((c) => c.id !== '20250130T100000Z-apply-b27c9e15');
    expect(plan.ceremonies.ceremonies.filter((c) => c.state === CeremonyState.PLANNED)).toHaveLength(1);
    feed.world = plan;
    expect(text(<History />)).toMatch(/\b1 plan was never run\b/);
    expect(text(<History />)).not.toMatch(/\b1 plans were never run\b/);
    // The worlds as they are: a number other than one takes the plural, and one takes the singular, in every screen.
    const NOUNS: [string, string][] = [['change', 'changes'], ['finding', 'findings'], ['record', 'records'], ['line', 'lines'], ['slot', 'slots'], ['day', 'days'], ['key', 'keys'], ['byte', 'bytes'], ['file', 'files'], ['signature', 'signatures'], ['touch', 'touches']];
    const seen = new Set<string>();
    for (const world of WORLDS()) {
      feed.world = world;
      const objects = objectsOf(world).slice(0, 6);
      const rendered = [
        text(<Todo tab="changes" />),
        text(<Todo tab="findings" />),
        text(<History />),
        text(<Trust />),
        ...(['cards', 'roots', 'dates'] as const).map((view) => text(<Inventory view={view} />)),
        ...objects.map((o) => text(<Inventory view={o.view} object={{ kind: o.kind, id: o.id }} />)),
        ...world.ceremonies.ceremonies.slice(0, 5).map((c) => text(<History id={c.id} />)),
      ].join('\n');
      for (const [one1, many] of NOUNS) {
        for (const m of rendered.matchAll(new RegExp(`(?<![\\w-])(\\d+) (${one1}|${many})(?![\\w-])`, 'g'))) {
          seen.add(m[0]);
          expect(m[2], `${world.id}: "${m[0]}"`).toBe(m[1] === '1' ? one1 : many);
        }
      }
    }
    // The walk did meet counts of both kinds.
    expect([...seen].some((s) => s.startsWith('1 '))).toBe(true);
    expect([...seen].some((s) => !s.startsWith('1 '))).toBe(true);
    feed.state = 'ready';
  });
});
