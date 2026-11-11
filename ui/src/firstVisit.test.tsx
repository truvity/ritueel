import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { fromJson } from '@bufbuild/protobuf';
import { GetSummaryResponseSchema } from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { setViewState, VIEW_STATES } from './api/demoState';

// What a first visitor of the demo is helped with, and the four defects the owner named
// (2026-11-11). The help is demo only: the real build must not draw it. The build checks in
// scripts/check-dist.mjs prove that on the two real bundles; here the same is proved on the
// components, by turning isDemo off.

const h = vi.hoisted(() => ({ demo: true, summary: { state: 'loading' } as Record<string, unknown> }));

vi.mock('./api/client', async (importOriginal) => {
  const real = await importOriginal<typeof import('./api/client')>();
  const m = { ...real };
  Object.defineProperty(m, 'isDemo', { get: () => h.demo, enumerable: true });
  return m;
});
vi.mock('./api/hooks', async (importOriginal) => {
  const real = await importOriginal<typeof import('./api/hooks')>();
  return { ...real, useSummary: () => h.summary };
});

afterEach(() => {
  h.demo = true;
  h.summary = { state: 'loading' };
  setViewState('loaded');
});

const SRC = new URL('./', import.meta.url).pathname;
const source = (f: string) => readFileSync(join(SRC, f), 'utf8');
const plain = (html: string) => html.split(/<[^>]*>/).join(' ').replace(/&#x27;/g, "'").replace(/\s+/g, ' ');

describe('defect 1: the step bar reaches Save', () => {
  it('wizardStage: choices are 2, a plan is 3, a saved plan is 4, and unsaving goes back to 3', async () => {
    const { wizardStage } = await import('./screens/Plan');
    expect(wizardStage({ answers: null, planReady: false, saved: false })).toBe(2);
    expect(wizardStage({ answers: [], planReady: false, saved: false })).toBe(3);
    expect(wizardStage({ answers: null, planReady: true, saved: false })).toBe(3);
    expect(wizardStage({ answers: null, planReady: true, saved: true })).toBe(4);
    expect(wizardStage({ answers: [], planReady: true, saved: true })).toBe(4);
    expect(wizardStage({ answers: [], planReady: true, saved: false })).toBe(3);
  });
  it('the bar at stage 4 marks Save as the current step and Goal, Choices and Plan as done', async () => {
    const { Stepper } = await import('./screens/Plan');
    const html = renderToStaticMarkup(<Stepper current={4} />);
    const items = [...html.matchAll(/<li\b([^>]*)>([\s\S]*?)<\/li>/g)];
    expect(items).toHaveLength(4);
    const state = items.map((m) => ({ current: /aria-current="step"/.test(m[1]), text: plain(m[2]) }));
    expect(state.map((s) => s.current)).toEqual([false, false, false, true]);
    expect(state[3].text).toContain('Save');
    expect(state[3].text).toContain('(you are here)');
    for (const i of [0, 1, 2]) expect(state[i].text, `item ${i + 1}`).toContain('(done)');
  });
  it('the bar at stage 3 does not yet mark Save', async () => {
    const { Stepper } = await import('./screens/Plan');
    const html = renderToStaticMarkup(<Stepper current={3} />);
    expect(html.match(/aria-current="step"/g)).toHaveLength(1);
    expect(plain(html)).toMatch(/Plan \(you are here\)\s+4 Save \(next\)/);
  });
  it('the save section tells the wizard when it is done, and when it leaves the screen', () => {
    // The click and the effect need a browser (scripts/e2e.mjs clicks "Save the plan" and reads the bar).
    // Here the wiring is read from the source: no DOM library is installed for the tests.
    const plan = source('screens/Plan.tsx');
    const save = plan.slice(plan.indexOf('function SavePlan'), plan.indexOf('const run = async'));
    expect(save).toMatch(/onSaved\?\.\(true\)/);
    expect(save).toMatch(/return \(\) => onSaved\?\.\(false\)/);
    expect(save).toMatch(/save\.state === 'done'/);
    expect(plan).toMatch(/<PlanView plan=\{r\.plan\} onSaved=\{setSaved\} \/>/);
    expect(plan).toMatch(/<Build intention=\{intention\} answers=\{answers\} onSaved=\{setSaved\} \/>/);
    expect(plan).toMatch(/wizardStage\(\{ answers, planReady, saved \}\)/);
  });
  it('PlanView still renders without onSaved (it is optional)', async () => {
    const { PlanView } = await import('./screens/Plan');
    expect(PlanView.length).toBeLessThanOrEqual(1);
    expect(source('screens/Plan.tsx')).toMatch(/onSaved\?: \(saved: boolean\) => void/);
  });
});

describe('defect 3: no text points to a control that does not exist', () => {
  it('no source text tells the reader to mark something or to go to a named screen', () => {
    const files = ['screens/Cards.tsx', 'screens/Plan.tsx', 'screens/Start.tsx', 'ui/FirstVisit.tsx', 'lib/finding.ts', 'lib/words.ts'];
    for (const f of files) expect(source(f), f).not.toMatch(/Mark one|on the Cards screen|on the [A-Z][a-z]+ screen/);
  });
});

describe('defect 4: Waiting is the purpose of the switch, and the screen says so', () => {
  it('the Waiting button hint says it lasts until another page state is chosen', () => {
    const waiting = VIEW_STATES.find((s) => s.value === 'waiting');
    expect(waiting?.hint).toMatch(/until you choose another page state/);
  });
  it('in the demo, the waiting screen says ritueel never answers, on purpose, and how to end the wait', async () => {
    const { Waiting } = await import('./ui/Sec');
    setViewState('waiting');
    const text = plain(renderToStaticMarkup(<Waiting what="the findings" />));
    expect(text).toContain('Reading the findings');
    expect(text).toContain('never answers, on purpose');
    expect(text).toContain('Choose another page state to end the wait.');
  });
  it('the note is only for the Waiting state', async () => {
    const { Waiting } = await import('./ui/Sec');
    for (const s of ['loaded', 'empty', 'failed'] as const) {
      setViewState(s);
      expect(plain(renderToStaticMarkup(<Waiting what="the findings" />)), s).not.toContain('on purpose');
    }
  });
  it('the real build keeps the old waiting screen without the demo note', async () => {
    const { Waiting } = await import('./ui/Sec');
    h.demo = false;
    setViewState('waiting');
    const text = plain(renderToStaticMarkup(<Waiting what="the findings" />));
    expect(text).toContain('Reading the findings');
    expect(text).not.toContain('on purpose');
  });
});

describe('first-visit help is in the demo and not in the real build', () => {
  it('the Start screen of the demo says what ritueel is, in each read state', async () => {
    const { Start } = await import('./screens/Start');
    const states: Record<string, Record<string, unknown>> = {
      waiting: { state: 'loading' },
      failed: { state: 'error', message: 'could not read', retry() {} },
    };
    for (const [name, res] of Object.entries(states)) {
      h.summary = res;
      const text = plain(renderToStaticMarkup(<Start />));
      expect(text, name).toContain('ritueel helps you keep a root');
      expect(text, name).toContain('Start here');
      expect(text, name).toContain('Everything on this page is made up.');
    }
  });
  it('the Start screen of the real build has neither the lede nor the Start-here box', async () => {
    const { Start } = await import('./screens/Start');
    h.demo = false;
    const text = plain(renderToStaticMarkup(<Start />));
    expect(text).not.toContain('helps you keep a root');
    expect(text).not.toContain('Start here');
    expect(text).toContain('This is the bundle where ritueel keeps the records of one trust domain.');
  });
  it('Start.tsx draws the demo-only parts only behind isDemo, and outside the data load', () => {
    const start = source('screens/Start.tsx');
    const fn = start.slice(start.indexOf('export function Start()'));
    expect(fn).toMatch(/isDemo \? \(\s*<DemoLede \/>/);
    expect(fn).toMatch(/\{isDemo \? <StartHere \/> : null\}/);
    expect(fn.indexOf('<StartHere />')).toBeLessThan(fn.indexOf('<Load'));
    // Nothing else imports the file, so the real build drops it.
    for (const f of ['screens/Plan.tsx', 'screens/Findings.tsx', 'ui/Shell.tsx', 'ui/Cmd.tsx', 'ui/Sec.tsx', 'App.tsx']) {
      expect(source(f), f).not.toMatch(/FirstVisit/);
    }
  });
  it('DemoLede names root, ceremony and history, each with its gloss, in one paragraph', async () => {
    const { DemoLede } = await import('./ui/FirstVisit');
    const html = renderToStaticMarkup(<DemoLede />);
    expect(html.match(/<p\b/g)).toHaveLength(1);
    const text = plain(html);
    expect(text).toMatch(/keep a root \(the key that everything else trusts\)/);
    expect(text).toMatch(/ceremony \(one sitting at a terminal where the root is used\)/);
    expect(text).toMatch(/history \(the write-once record of every ceremony\)/);
  });
  it('StartHere is a path of three links: Roots, Findings, Make a plan, in that order', async () => {
    const { StartHere } = await import('./ui/FirstVisit');
    const html = renderToStaticMarkup(<StartHere />);
    const ol = html.slice(html.indexOf('<ol'), html.indexOf('</ol>'));
    expect(ol.match(/<li\b/g)).toHaveLength(3);
    expect([...ol.matchAll(/<a [^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g)].map((m) => [m[1], plain(m[2]).trim()])).toEqual([
      ['#/roots', 'Roots'],
      ['#/findings', 'Findings'],
      ['#/plan', 'Make a plan'],
    ]);
    const text = plain(html);
    expect(text).toContain('Everything on this page is made up.');
    expect(text).toContain('The bar above has two demo switches. Example bundle changes the made-up keys');
    expect(text).toContain('a bundle is the directory that holds everything ritueel knows about one set of keys');
    expect(text).toContain('the ritueel command line is not built yet');
    // the path comes first and the switches are explained after it, so that on a phone the three links lie above the bottom bar
    expect(text.indexOf('Try these three, in order:')).toBeLessThan(text.indexOf('Everything on this page is made up.'));
    expect(text.indexOf('Make a plan')).toBeLessThan(text.indexOf('Example bundle changes'));
    expect(text.indexOf('Example bundle changes')).toBeLessThan(text.indexOf('Read what a root is'));
    expect(text).toContain('Page state shows each screen');
    expect(text).toContain('Read what a root is');
    expect(text).toContain('All the words');
    // public data only: the box never asks for a secret and holds no form control
    expect(html).not.toMatch(/<(input|textarea|form)\b/);
  });
  it('the demo bar names its two switches Page state and Example bundle (not the old labels)', () => {
    const shell = source('ui/Shell.tsx');
    expect(shell).toContain('Page state');
    expect(shell).toContain('Example bundle');
    expect(shell).not.toContain('Try the states');
    expect(shell).not.toContain('Try a bundle');
  });
  it('the demo bar keeps its sentence that the data is made up, and keeps the way back to the site on every width', () => {
    const shell = source('ui/Shell.tsx');
    expect(shell).toContain('The data is made up, and ritueel is still in design. Nothing here acts.');
    // Below lg the bar's own "Back to ritueel.id" link is hidden (it costs a 44 px line on a phone); the DEMO mark in the header
    // and the footer link remain, so a phone still has two ways back.
    expect(shell).toMatch(/className="hidden items-center [^"]*lg:inline-flex" href=\{siteUrl\(\)\}>\s*Back to ritueel\.id/);
    expect(shell).toContain('aria-label="This is a demo. Back to ritueel.id"');
    expect(shell.match(/Back to ritueel\.id/g)!.length).toBeGreaterThanOrEqual(3);
  });
  it('a command in the demo says the command line is not built; the real build does not', async () => {
    const { Cmd } = await import('./ui/Cmd');
    const demo = renderToStaticMarkup(<Cmd>{'ritueel status'}</Cmd>);
    expect(demo).toMatch(/<p[^>]*role="note"[^>]*>\s*Example only\. The ritueel command line is not built yet\./);
    h.demo = false;
    expect(renderToStaticMarkup(<Cmd>{'ritueel status'}</Cmd>)).not.toContain('not built yet');
    expect(source('ui/Cmd.tsx')).toContain('Copied. This is a demo: the ritueel command line is not built yet, so this command is an example.');
  });
  it('the Words box names its words in the summary and links to the whole glossary, in the demo only', async () => {
    const { Start } = await import('./screens/Start');
    const data = fromJson(GetSummaryResponseSchema, JSON.parse(source('fixtures/personal/inspect.get-summary.json')));
    h.summary = { state: 'ready', data };
    const demo = plain(renderToStaticMarkup(<Start />));
    expect(demo).toContain('Words on this page: root, bundle, ceremony, history and more');
    expect(demo).toContain('All the words');
    h.demo = false;
    const real = plain(renderToStaticMarkup(<Start />));
    expect(real).toContain('Words on this page');
    expect(real).not.toContain('ceremony, history and more');
    expect(real).not.toContain('All the words');
  });
  it('everything new is at least 14 px: no text-xs or text-[0.75rem] in the new component', () => {
    expect(source('ui/FirstVisit.tsx')).not.toMatch(/text-xs|text-\[0\.7|text-\[1[01]px\]|text-\[12px\]/);
    // the old word the maintainer replaced
    expect(source('ui/FirstVisit.tsx')).not.toMatch(/folder/i);
  });
});
