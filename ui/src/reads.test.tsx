import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { emptyWorld, loadWorld, plain, WORLDS, BUNDLES, type World } from './testkit';

vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

// The page reads when a screen opens and when the window gets the focus. There is no timer
// (security profile row 9 of docs/reference/wizard.md and record 0010), so a page left alone
// does not keep the process alive. Every screen that has read shows the time of its read.

const HERE = new URL('./', import.meta.url).pathname;

// ---- N7 (a): the focus read, on the real hooks, with a small stand-in for React ------------------------
//
// The tests have no browser and no DOM library. The hooks are plain functions of React's own hooks, so
// this stand-in runs them one "component" at a time: state, refs, memoised callbacks and effects, in
// the order React runs them. It replaces React only for the module graph of ./api/hooks, inside one test.

type Slot = { v?: unknown; current?: unknown; fn?: () => unknown; deps?: unknown[]; cleanup?: unknown };

function standIn() {
  const slots: Slot[] = [];
  let i = 0;
  let dirty = false;
  const queue: number[] = [];
  const same = (a?: unknown[], b?: unknown[]) => !!a && !!b && a.length === b.length && a.every((x, k) => Object.is(x, b[k]));
  const react = {
    useState(init: unknown) {
      const k = i++;
      slots[k] ??= { v: typeof init === 'function' ? (init as () => unknown)() : init };
      const s = slots[k];
      return [s.v, (n: unknown) => {
        s.v = typeof n === 'function' ? (n as (p: unknown) => unknown)(s.v) : n;
        dirty = true;
      }];
    },
    useRef(init: unknown) {
      const k = i++;
      slots[k] ??= { current: init };
      return slots[k];
    },
    useCallback(fn: () => unknown, deps: unknown[]) {
      const k = i++;
      if (!slots[k] || !same(slots[k].deps, deps)) slots[k] = { fn, deps };
      return slots[k].fn;
    },
    useEffect(fn: () => unknown, deps: unknown[]) {
      const k = i++;
      const prev = slots[k];
      if (!prev || !same(prev.deps, deps)) queue.push(k);
      slots[k] = { fn, deps: prev && same(prev.deps, deps) ? prev.deps : deps, cleanup: prev?.cleanup };
    },
    useSyncExternalStore(_subscribe: unknown, get: () => unknown) {
      i++;
      return get();
    },
  };
  return { react, mount: <T,>(body: () => T) => {
    let result: T;
    const render = () => {
      i = 0;
      result = body();
      // Effects run after the render, cleanup first, as React does.
      for (const k of queue.splice(0)) {
        (slots[k].cleanup as (() => void) | undefined)?.();
        slots[k].cleanup = slots[k].fn?.();
      }
    };
    render();
    return {
      get value() {
        return result;
      },
      /** Render again while a state setter has marked the component dirty. */
      settle: async () => {
        for (let n = 0; n < 5; n++) {
          await new Promise((r) => setTimeout(r, 0));
          while (dirty) {
            dirty = false;
            render();
          }
        }
      },
      unmount: () => {
        for (const s of slots) if (typeof s?.cleanup === 'function') (s.cleanup as () => void)();
      },
    };
  } };
}

describe('N7: the page reads on the focus, and has no timer', () => {
  afterEach(() => {
    vi.doUnmock('react');
    vi.doUnmock('./api/client');
    vi.resetModules();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function hooks(clock: { now: number }) {
    const win = new EventTarget();
    vi.stubGlobal('window', win);
    vi.spyOn(performance, 'now').mockImplementation(() => clock.now);
    const kit = standIn();
    vi.resetModules();
    vi.doMock('react', () => ({ ...kit.react, default: kit.react }));
    const calls = { GetSummary: 0, ListFindings: 0, GetInventory: 0, ListCeremonies: 0, ListTrustFiles: 0 };
    const answer = (name: keyof typeof calls) => async () => {
      calls[name] += 1;
      return { n: calls[name] };
    };
    vi.doMock('./api/client', () => ({
      isDemo: true,
      inspect: {
        getSummary: answer('GetSummary'),
        listFindings: answer('ListFindings'),
        getInventory: answer('GetInventory'),
        listCeremonies: answer('ListCeremonies'),
        listTrustFiles: answer('ListTrustFiles'),
      },
    }));
    const real = await vi.importActual<typeof import('./api/hooks')>('./api/hooks');
    return { win, kit, real, calls };
  }

  it('each of the five reads is made once when the screen opens, and once more when the window gets the focus', async () => {
    const clock = { now: 10_000 };
    const { win, kit, real, calls } = await hooks(clock);
    const view = kit.mount(() => [real.useSummary(), real.useFindings(), real.useInventory(), real.useCeremonies(), real.useTrustFiles()]);
    await view.settle();
    expect(Object.values(calls)).toEqual([1, 1, 1, 1, 1]);
    expect(view.value.map((v) => v.state)).toEqual(['ready', 'ready', 'ready', 'ready', 'ready']);
    clock.now += 5_000;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(Object.values(calls), 'one more read for each').toEqual([2, 2, 2, 2, 2]);
    view.unmount();
  });

  it('a second focus within one second makes no read, and a focus after that makes one', async () => {
    const clock = { now: 0 };
    const { win, kit, real, calls } = await hooks(clock);
    const view = kit.mount(() => real.useSummary());
    await view.settle();
    clock.now = 400;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(calls.GetSummary, 'a focus 0.4 s after the read').toBe(1);
    clock.now = 2_000;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(calls.GetSummary).toBe(2);
    clock.now = 2_600;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(calls.GetSummary, 'a second focus within one second').toBe(2);
    view.unmount();
  });

  it('the screen keeps its data while it reads again: the state is never loading after the first read', async () => {
    const clock = { now: 0 };
    const { win, kit, real } = await hooks(clock);
    let release: (() => void) | undefined;
    let n = 0;
    const slow = () => {
      n += 1;
      const mine = n;
      return n === 1 ? Promise.resolve({ n: mine }) : new Promise<{ n: number }>((r) => (release = () => r({ n: mine })));
    };
    const view = kit.mount(() => real.useCall('slow', slow));
    await view.settle();
    expect(view.value).toMatchObject({ state: 'ready', data: { n: 1 } });
    clock.now = 5_000;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    // The second read is still on its way: the first answer is still shown.
    expect(view.value).toMatchObject({ state: 'ready', data: { n: 1 } });
    release?.();
    await view.settle();
    expect(view.value).toMatchObject({ state: 'ready', data: { n: 2 } });
    view.unmount();
  });

  it('a read again that fails turns the screen into error, and Try again reads again from loading', async () => {
    const clock = { now: 0 };
    const { win, kit, real } = await hooks(clock);
    let n = 0;
    const run = async () => {
      n += 1;
      if (n === 2) throw new Error('the process has ended');
      return { n };
    };
    const view = kit.mount(() => real.useCall('flaky', run));
    await view.settle();
    clock.now = 5_000;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(view.value).toMatchObject({ state: 'error', message: 'the process has ended' });
    const error = view.value as { state: 'error'; retry: () => void };
    error.retry();
    await view.settle();
    expect(view.value).toMatchObject({ state: 'ready', data: { n: 3 } });
    view.unmount();
  });

  it('after the screen is closed a focus makes no read', async () => {
    const clock = { now: 0 };
    const { win, kit, real, calls } = await hooks(clock);
    const view = kit.mount(() => real.useSummary());
    await view.settle();
    view.unmount();
    clock.now = 9_000;
    win.dispatchEvent(new Event('focus'));
    await view.settle();
    expect(calls.GetSummary).toBe(1);
  });

  it('there is no timer: no interval anywhere, and no timeout in a screen or in the data layer', () => {
    const files = (dir: string): string[] =>
      readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(`${dir}/${e.name}`) : /\.tsx?$/.test(e.name) && !/\.test\./.test(e.name) && e.name !== 'testkit.ts' && dir !== 'gen' ? [`${dir}/${e.name}`] : []));
    const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
    const all = ['api', 'screens', 'ui', 'lib'].flatMap(files).concat(['App.tsx', 'main.tsx']);
    const withTimer: string[] = [];
    for (const f of all) {
      const code = strip(readFileSync(join(HERE, f), 'utf8'));
      expect(code, `${f}: no interval`).not.toMatch(/\bsetInterval\b|requestIdleCallback/);
      if (/\bsetTimeout\b/.test(code)) withTimer.push(f);
      // A file that reads must not hold a timer.
      if (/\b(useSummary|useFindings|useInventory|useCeremonies|useTrustFiles|useCall)\s*\(/.test(code)) expect(code, `${f}: reads and has a timer`).not.toMatch(/\bsetTimeout\b/);
    }
    // The only timers: the 1.6 s flash "Copied" of the Copy control (used by Cmd and PathCopy) and the 3.5 s note of a long wait.
    expect(withTimer.sort()).toEqual(['ui/Cmd.tsx', 'ui/Sec.tsx']);
    expect(strip(readFileSync(join(HERE, 'ui/Cmd.tsx'), 'utf8'))).toMatch(/setTimeout\(\(\) => setDone\(false\), 1600\)/);
    expect(strip(readFileSync(join(HERE, 'ui/Sec.tsx'), 'utf8'))).toMatch(/useAfter\(3500\)/);
    // The data layer reads on a focus event and on nothing else.
    const hooksSource = strip(readFileSync(join(HERE, 'api/hooks.ts'), 'utf8'));
    expect(hooksSource).toMatch(/addEventListener\('focus'/);
    expect(hooksSource).not.toMatch(/visibilitychange|online|setTimeout|setInterval/);
  });
});

// ---- N8: every screen that has read shows the time of its read -------------------------------------------

describe('N8: a screen that has read shows the time of its read', () => {
  const TIMES: Record<string, string> = {
    acme: '2026-11-24 09:00 UTC',
    globex: '2026-11-24 09:00 UTC',
    personal: '2026-11-24 09:00 UTC',
    'acme scene 2': '2026-11-24 09:40 UTC',
    'acme scene 3': '2026-11-24 10:05 UTC',
    'acme scene 4': '2026-11-24 10:30 UTC',
    'acme scene 5': '2026-11-24 11:10 UTC',
  };
  let empties: World[];
  beforeAll(async () => {
    empties = await Promise.all(BUNDLES.map((b) => emptyWorld(b)));
  });

  // To do keeps the time in a state that it sets when its tab has read, so a static render, which runs no
  // effect, cannot show it; the browser test (scripts/e2e.mjs, set C and K) checks that screen on the page.
  // The tests before this block reset the module graph, so the mocked hooks read the feed of the testkit that is loaded now.
  async function setFeed(world: World, state: 'ready' | 'loading' | 'error' = 'ready') {
    const { feed } = await import('./testkit');
    feed.world = world;
    feed.state = state;
  }
  async function screens(): Promise<[string, () => React.ReactElement][]> {
    const { Inventory } = await import('./screens/Inventory');
    const { History } = await import('./screens/History');
    const { Trust } = await import('./screens/Trust');
    const { Shell } = await import('./ui/Shell');
    return [
      ['inventory by card', () => <Inventory view="cards" />],
      ['inventory by root', () => <Inventory view="roots" />],
      ['inventory by date', () => <Inventory view="dates" />],
      ['history', () => <History />],
      ['trust set', () => <Trust />],
      ['frame', () => (
        <Shell route={{ name: 'trust' }}>
          <p>x</p>
        </Shell>
      )],
    ];
  }
  // The time elements that hold a time of a read ("2026-11-24 09:00 UTC"). A day alone (Day) is a time element too.
  const timesOf = (html: string) =>
    [...html.matchAll(/<time dateTime="([^"]*)"([^>]*)>([^<]*)<\/time>/g)]
      .map((m) => ({ iso: m[1], attrs: m[2], text: m[3] }))
      .filter((t) => t.text.endsWith(' UTC'));
  const daysOf = (html: string) =>
    [...html.matchAll(/<time dateTime="([^"]*)"([^>]*)>([^<]*)<\/time>/g)]
      .map((m) => ({ iso: m[1], attrs: m[2], text: m[3] }))
      .filter((t) => !t.text.endsWith(' UTC'));

  it('in the loaded state: "Read <time>" inside a time element, with the time of the scene', async () => {
    for (const w of WORLDS()) {
      await setFeed(w);
      for (const [name, render] of await screens()) {
        const html = renderToStaticMarkup(render());
        const times = timesOf(html);
        expect(times.length, `${w.id} ${name}`).toBeGreaterThan(0);
        for (const t of times) {
          expect(t.text, `${w.id} ${name}`).toBe(TIMES[w.id]);
          expect(t.attrs, `${w.id} ${name}`).toContain('whitespace-nowrap');
          expect(t.iso, `${w.id} ${name}`).toBe(new Date(TIMES[w.id].replace(' UTC', 'Z').replace(' ', 'T')).toISOString());
        }
        if (name !== 'frame') expect(plain(html), `${w.id} ${name}`).toContain(`Read ${TIMES[w.id]}`);
      }
    }
  });
  it('a time and a day never break across two lines: each stands in a time element that does not wrap', async () => {
    let days = 0;
    for (const w of WORLDS()) {
      await setFeed(w);
      for (const [name, render] of await screens()) {
        const html = renderToStaticMarkup(render());
        for (const d of daysOf(html)) {
          days += 1;
          expect(d.text, `${w.id} ${name}`).toMatch(/^\d{4}-\d\d-\d\d$/);
          expect(d.iso, `${w.id} ${name}`).toBe(d.text);
          expect(d.attrs, `${w.id} ${name}`).toContain('whitespace-nowrap');
        }
      }
    }
    expect(days).toBeGreaterThan(0);
  });
  it('in the Empty state the screens have read too, and show the time', async () => {
    for (const w of empties) {
      await setFeed(w);
      for (const [name, render] of await screens()) {
        const html = renderToStaticMarkup(render());
        expect(plain(html), `${w.id} ${name}`).toContain('Read 2026-11-24 09:00 UTC');
      }
    }
  });
  it('while it waits, and when the read failed, no screen shows a time', async () => {
    for (const state of ['loading', 'error'] as const) {
      await setFeed(loadWorld('acme', 5), state);
      for (const [name, render] of await screens()) {
        const html = renderToStaticMarkup(render());
        expect(timesOf(html), `${state} ${name}`).toEqual([]);
        expect(plain(html), `${state} ${name}`).not.toMatch(/\bRead \d{4}-\d\d-\d\d/);
        expect(plain(html), `${state} ${name}`).not.toMatch(/\d{4}-\d\d-\d\d \d\d:\d\d UTC/);
      }
    }
  });
  it('the time comes from the answer, not from the clock of the browser', () => {
    for (const f of ['ui/ReadTime.tsx', 'lib/format.ts', 'screens/Todo.tsx', 'screens/History.tsx', 'screens/Trust.tsx', 'screens/Inventory.tsx', 'ui/Shell.tsx']) {
      const code = readFileSync(join(HERE, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
      expect(code, f).not.toMatch(/\bnew Date\(\s*\)|Date\.now\(|performance\.now/);
    }
  });
});
