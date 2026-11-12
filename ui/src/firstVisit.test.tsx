import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { setBundle, setScene, setViewState, VIEW_STATES } from './api/demoState';
import { feed, loadWorld, plain } from './testkit';

// What a first visitor of the demo is helped with. The help is demo only: the real build must
// not draw it. The checks of scripts/check-dist.mjs prove that on the two builds; here the same is
// proved on the components, by turning isDemo off.

const h = vi.hoisted(() => ({ demo: true }));

vi.mock('./api/client', async (importOriginal) => {
  const real = await importOriginal<typeof import('./api/client')>();
  const m = { ...real };
  Object.defineProperty(m, 'isDemo', { get: () => h.demo, enumerable: true });
  return m;
});
vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

afterEach(() => {
  h.demo = true;
  feed.state = 'ready';
  setViewState('loaded');
  setBundle('acme');
  setScene(1);
});

const SRC = new URL('./', import.meta.url).pathname;
const source = (f: string) => readFileSync(join(SRC, f), 'utf8');
const noStyle = (html: string) => html.replace(/<style[\s\S]*?<\/style>/g, '');
const text = (html: string) => plain(noStyle(html));

describe('Waiting is the purpose of the switch, and the screen says so', () => {
  it('the Waiting button hint says it lasts until another page state is chosen', () => {
    const waiting = VIEW_STATES.find((s) => s.value === 'waiting');
    expect(waiting?.hint).toMatch(/until you choose another page state/);
  });
  it('in the demo, the waiting screen says ritueel never answers, on purpose, and how to end the wait; only for Waiting', async () => {
    const { Waiting } = await import('./ui/Sec');
    setViewState('waiting');
    const waiting = text(renderToStaticMarkup(<Waiting what="the findings" />));
    expect(waiting).toContain('Reading the findings');
    expect(waiting).toContain('never answers, on purpose');
    expect(waiting).toContain('Choose another page state to end the wait.');
    for (const s of ['loaded', 'empty', 'failed'] as const) {
      setViewState(s);
      expect(text(renderToStaticMarkup(<Waiting what="the findings" />)), s).not.toContain('on purpose');
    }
  });
  it('the real build keeps the plain waiting screen', async () => {
    const { Waiting } = await import('./ui/Sec');
    h.demo = false;
    setViewState('waiting');
    const waiting = text(renderToStaticMarkup(<Waiting what="the findings" />));
    expect(waiting).toContain('Reading the findings');
    expect(waiting).not.toContain('on purpose');
  });
});

describe('the lede is in the demo and not in the real build', () => {
  it('To do in the demo has the lede in each read state and on both tabs', async () => {
    const { Todo } = await import('./screens/Todo');
    feed.world = loadWorld('acme', 1);
    for (const state of ['loading', 'error', 'ready'] as const) {
      feed.state = state;
      for (const tab of ['changes', 'findings'] as const) {
        const t = text(renderToStaticMarkup(<Todo tab={tab} />));
        expect(t, `${state} ${tab}`).toContain('ritueel helps you keep a root');
        expect(t, `${state} ${tab}`).toContain('a root that others trust');
      }
    }
  });
  it('To do in the real build has neither the lede nor anything of FirstVisit', async () => {
    const { Todo } = await import('./screens/Todo');
    h.demo = false;
    feed.world = loadWorld('acme', 1);
    for (const state of ['loading', 'error', 'ready'] as const) {
      feed.state = state;
      const t = text(renderToStaticMarkup(<Todo tab="changes" />));
      expect(t, state).not.toContain('helps you keep a root');
      expect(t, state).not.toContain('glossary');
    }
  });
  it('Todo.tsx draws the lede only behind isDemo, outside the data load, and nothing else imports FirstVisit', () => {
    const todo = source('screens/Todo.tsx');
    expect(todo).toMatch(/lede=\{isDemo \? <DemoLede \/> : undefined\}/);
    expect(todo.indexOf('<DemoLede />')).toBeLessThan(todo.indexOf('<Tabs'));
    for (const f of ['screens/Inventory.tsx', 'screens/History.tsx', 'screens/Trust.tsx', 'ui/Shell.tsx', 'ui/Cmd.tsx', 'ui/Sec.tsx', 'App.tsx']) expect(source(f), f).not.toMatch(/FirstVisit/);
  });
  it('the lede is two short paragraphs that name the root, the bar and the glossary', async () => {
    const { DemoLede } = await import('./ui/FirstVisit');
    const html = renderToStaticMarkup(<DemoLede />);
    expect(html.match(/<p\b/g)).toHaveLength(2);
    const t = text(html);
    expect(t).toMatch(/keep a root that others trust\./);
    expect(t).toContain('step through the five scenes of acme');
    expect(t).toContain('glossary');
    expect(html).not.toMatch(/<(input|textarea|form)\b/);
  });
});

describe('the demo bar', () => {
  it('names three controls, Example bundle, Scene (acme only) and Page state, and keeps its sentence and the way back', async () => {
    const { DemoBar, SITE_PICTURES_NOTE } = await import('./ui/DemoBar');
    const acme = text(renderToStaticMarkup(<DemoBar />));
    expect(acme).toContain('Example bundle');
    expect(acme).toContain('Scene');
    expect(acme).toContain('Page state');
    expect(acme).toContain('The data is made up, and ritueel is still in design. Nothing here acts.');
    expect(acme).toContain('Back to ritueel.id');
    expect(acme).toContain(SITE_PICTURES_NOTE);
    expect(SITE_PICTURES_NOTE).toContain('pictures on the site still show the older page');
    setBundle('globex');
    const globex = text(renderToStaticMarkup(<DemoBar />));
    expect(globex).toContain('Example bundle');
    expect(globex).toContain('Page state');
    expect(globex).not.toMatch(/\bScene\b/);
    // Below lg the link in the bar is hidden; the DEMO mark in the header and the footer link stay, so a phone has two ways back.
    const bar = source('ui/DemoBar.tsx');
    expect(bar).toMatch(/className="hidden items-center [^"]*lg:inline-flex" href=\{siteUrl\(\)\}>\s*Back to ritueel\.id/);
    const shell = source('ui/Shell.tsx');
    expect(shell).toContain('aria-label="This is a demo. Back to ritueel.id"');
    expect(shell.match(/Back to ritueel\.id/g)!.length).toBeGreaterThanOrEqual(2);
  });
  it('the note about the pictures of the site is in the demo bar only', () => {
    const users = ['ui/Shell.tsx', 'screens/Todo.tsx', 'screens/Inventory.tsx', 'screens/History.tsx', 'screens/Trust.tsx', 'ui/Sec.tsx'].filter((f) => /SITE_PICTURES_NOTE|pictures on the site/.test(source(f)));
    expect(users).toEqual([]);
    expect(source('ui/DemoBar.tsx')).toContain('export const SITE_PICTURES_NOTE');
  });
  it('the demo bar is drawn by the frame only in the demo build', () => {
    expect(source('ui/Shell.tsx')).toMatch(/\{isDemo \? <DemoBar \/> : null\}/);
  });
});

describe('the scene control', () => {
  it('has five buttons named Scene 1 of 5 to Scene 5 of 5, and a live line "Scene N of 5: <line>"', async () => {
    const { SceneSwitch } = await import('./ui/SceneSwitch');
    const { sceneLine } = await import('./api/scenes');
    for (let n = 1; n <= 5; n++) {
      setScene(n);
      const html = renderToStaticMarkup(<SceneSwitch />);
      for (let k = 1; k <= 5; k++) expect(html).toContain(`aria-label="Scene ${k} of 5"`);
      expect(html).toContain('role="status"');
      expect(text(html)).toContain(`Scene ${n} of 5: ${sceneLine(n)}`);
    }
  });
  it('is not drawn for globex and personal, nor in the Empty, Failed and Waiting states', async () => {
    const { SceneSwitch } = await import('./ui/SceneSwitch');
    for (const b of ['globex', 'personal'] as const) {
      setBundle(b);
      expect(renderToStaticMarkup(<SceneSwitch />), b).toBe('');
    }
    setBundle('acme');
    for (const s of ['empty', 'failed', 'waiting'] as const) {
      setViewState(s);
      expect(renderToStaticMarkup(<SceneSwitch />), s).toBe('');
    }
  });
});

describe('a command in the demo says the command line is not built yet', () => {
  it('under a command in the demo; the real build does not say it', async () => {
    const { Cmd } = await import('./ui/Cmd');
    const demo = renderToStaticMarkup(<Cmd>{'ritueel status'}</Cmd>);
    expect(demo).toMatch(/<p[^>]*role="note"[^>]*>\s*Example only\. The ritueel command line is not built yet\./);
    h.demo = false;
    expect(renderToStaticMarkup(<Cmd>{'ritueel status'}</Cmd>)).not.toContain('not built yet');
    expect(source('ui/Cmd.tsx')).toContain('Copied. This is a demo: the ritueel command line is not built yet, so a command is an example.');
  });
  it('a table of commands says it once, after the table, and a Cmd in it passes note={false}', async () => {
    const { Trust } = await import('./screens/Trust');
    feed.world = loadWorld('acme', 1);
    const t = text(renderToStaticMarkup(<Trust />));
    expect(t.match(/Example only\. The ritueel command line is not built yet\./g)).toHaveLength(1);
    h.demo = false;
    expect(text(renderToStaticMarkup(<Trust />))).not.toContain('not built yet');
  });
});

describe('the words of the page', () => {
  it('no source text tells the reader to mark something or to go to a screen that does not exist', () => {
    const files = ['screens/Inventory.tsx', 'screens/Todo.tsx', 'screens/History.tsx', 'screens/Trust.tsx', 'ui/Panel.tsx', 'ui/CeremonyPanel.tsx', 'ui/FirstVisit.tsx', 'ui/FindingCard.tsx', 'lib/words.ts'];
    for (const f of files) expect(source(f), f).not.toMatch(/Mark one|Cards screen|Roots screen|on the Cards screen|on the [A-Z][a-z]+ screen/);
  });
  it('everything new is at least 14 px: no text-xs or text-[0.75rem] in the lede or the scene control, and none in the demo bar except its DEMO mark', () => {
    const small = /text-xs|text-\[0\.7|text-\[1[01]px\]|text-\[12px\]/;
    expect(source('ui/FirstVisit.tsx')).not.toMatch(small);
    expect(source('ui/SceneSwitch.tsx')).not.toMatch(small);
    const bar = source('ui/DemoBar.tsx')
      .split('\n')
      .filter((line) => !line.includes('>DEMO<') && !/DEMO\s*$/.test(line) && !line.includes('tracking-wider'))
      .join('\n');
    expect(bar).not.toMatch(small);
    // The words the maintainer replaced.
    expect(source('ui/FirstVisit.tsx')).not.toMatch(/folder/i);
  });
});
