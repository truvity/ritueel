import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fromJson, type DescMessage, type JsonValue, type Message } from '@bufbuild/protobuf';
import {
  GetSummaryResponseSchema,
  ListCardsResponseSchema,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListRootsResponseSchema,
  ListTrustFilesResponseSchema,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { ListIntentionsResponseSchema, SavePlanResponseSchema, StartPlanResponseSchema } from './gen/ritueel/local/v1alpha1/plan_service_pb';

// Every string that comes from the folder is data. This test gives each screen a
// world in which EVERY string field ends in a bidirectional override, a joiner and
// a BEL (control) character, renders the screen, and fails if any of those
// characters reaches the markup raw, in a text node or in an attribute such as
// aria-label or title. A string a screen forgot to pass through T or safeString
// shows up here.

const BAD = String.fromCodePoint(0x202e, 0x200d, 0x0007);
const RANGES: [number, number][] = [[0, 8], [0xb, 0x1f], [0x7f, 0x9f], [0xad, 0xad], [0x61c, 0x61c], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0xfeff, 0xfeff]];
const hex = (n: number) => '\\u' + n.toString(16).padStart(4, '0');
const RAW = new RegExp('[' + RANGES.map(([a, b]) => (a === b ? hex(a) : hex(a) + '-' + hex(b))).join('') + ']');

const w = vi.hoisted(() => ({ d: {} as Record<string, any> }));

vi.mock('./api/hooks', async (importOriginal) => {
  const real = await importOriginal<typeof import('./api/hooks')>();
  const ready = (data: unknown) => ({ state: 'ready', data, reload() {} });
  return {
    ...real,
    useSummary: () => ready(w.d.summary),
    useFindings: (min = 0) => ready({ findings: w.d.findings.findings.filter((f: { severity: number }) => f.severity >= min) }),
    useRoots: () => ready(w.d.roots),
    useCards: () => ready(w.d.cards),
    useCeremonies: () => ready(w.d.ceremonies),
    useTrustFiles: () => ready(w.d.trust),
    useIntentions: () => ready(w.d.intentions),
    useGoalMap: () => new Map(w.d.intentions.options.map((o: { intention: number }) => [o.intention, o])),
    useCall: (key: string) => (key.startsWith('plan-') ? ready(key.startsWith('plan-start') ? w.d.questions : w.d.plan) : ready(w.d.command)),
  };
});

function mark(v: unknown): unknown {
  if (typeof v === 'string') return v + BAD;
  if (Array.isArray(v)) return v.map(mark);
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) o[k] = k === '$typeName' ? x : mark(x);
    return o;
  }
  return v;
}

const files = import.meta.glob('./fixtures/*.json', { eager: true, import: 'default' }) as Record<string, JsonValue>;
const parse = <S extends DescMessage>(schema: S, name: string) => mark(fromJson(schema, files[`./fixtures/${name}`])) as Message;

beforeAll(() => {
  w.d.summary = parse(GetSummaryResponseSchema, 'inspect.get-summary.json');
  w.d.findings = parse(ListFindingsResponseSchema, 'inspect.list-findings.json');
  w.d.roots = parse(ListRootsResponseSchema, 'inspect.list-roots.json');
  w.d.cards = parse(ListCardsResponseSchema, 'inspect.list-cards.json');
  w.d.ceremonies = parse(ListCeremoniesResponseSchema, 'inspect.list-ceremonies.json');
  w.d.trust = parse(ListTrustFilesResponseSchema, 'inspect.list-trust-files.json');
  w.d.intentions = parse(ListIntentionsResponseSchema, 'plan.list-intentions.json');
  w.d.questions = parse(StartPlanResponseSchema, 'plan.start-plan.renew-due.questions.json');
  w.d.plan = parse(StartPlanResponseSchema, 'plan.start-plan.renew-due.json');
  w.d.saved = parse(SavePlanResponseSchema, 'plan.save-plan.renew-due.json');
  w.d.command = { state: 'x' };
  w.d.command = 'ritueel plan' + BAD;
});

function offending(html: string): string[] {
  const seen = new Set<string>();
  for (const m of html.matchAll(new RegExp('(?:' + RAW.source + ')+', 'g'))) {
    const at = m.index ?? 0;
    seen.add(JSON.stringify(html.slice(Math.max(0, at - 36), at + 1).replace(/^[^<"=>]*/, '')));
  }
  return [...seen].slice(0, 12);
}

async function screens() {
  const { Start } = await import('./screens/Start');
  const { Findings } = await import('./screens/Findings');
  const { Roots } = await import('./screens/Roots');
  const { Key } = await import('./screens/Key');
  const { Cards } = await import('./screens/Cards');
  const { History } = await import('./screens/History');
  const { Trust } = await import('./screens/Trust');
  const { Plan, Questions, PlanView, Saved } = await import('./screens/Plan');
  const { NotFound } = await import('./screens/NotFound');
  const roots = w.d.roots.roots as { label: string }[];
  const cards = w.d.cards.cards as { serial: string }[];
  const cer = w.d.ceremonies.ceremonies as { id: string }[];
  const list: [string, () => ReactElement][] = [
    ['start', () => <Start />],
    ['findings', () => <Findings />],
    ['roots', () => <Roots />],
    ['cards', () => <Cards />],
    ['history', () => <History />],
    ['trust', () => <Trust />],
    ['plan goals', () => <Plan />],
    ['plan questions', () => <Plan goal="renew-due" />],
    ['plan questions component', () => <Questions questions={w.d.questions.questions} onSubmit={() => {}} />],
    ['plan preview', () => <PlanView plan={w.d.plan.plan} />],
    ['plan saved', () => <Saved data={w.d.saved} />],
    ['not found', () => <NotFound hash={'#/x/' + BAD} />],
    ['key route param', () => <Key root={'nope' + BAD} />],
    ['card route param', () => <Cards serial={'nope' + BAD} />],
    ['history route param', () => <History id={'nope' + BAD} />],
  ];
  for (const r of roots) list.push([`key ${r.label}`, () => <Key root={r.label} />]);
  for (const c of cards) list.push([`card ${c.serial}`, () => <Cards serial={c.serial} />]);
  for (const c of cer) list.push([`ceremony ${c.id}`, () => <History id={c.id} />]);
  return list;
}

describe('hostile text never reaches the markup raw', () => {
  it('the marker is a bidi override, a joiner and a control character', () => {
    expect(RAW.test(BAD)).toBe(true);
  });
  it('every screen, with every string of the world marked', async () => {
    const list = await screens();
    expect(list.length).toBeGreaterThan(20);
    const failures: string[] = [];
    let sawEscape = 0;
    for (const [name, render] of list) {
      const html = renderToStaticMarkup(render());
      const bad = offending(html);
      if (bad.length) for (const b of bad) console.log(`HOSTILE ${name} ${b}`);
      if (bad.length) failures.push(`${name}:\n   ${bad.join('\n   ')}`);
      if (html.includes('U+202E')) sawEscape += 1;
    }
    expect(failures).toEqual([]);
    // the marked world did reach the screens, drawn as escapes
    expect(sawEscape).toBeGreaterThan(15);
  });
});
