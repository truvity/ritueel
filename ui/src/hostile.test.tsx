import { describe, expect, it, vi } from 'vitest';
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
import { RunPlace } from './gen/ritueel/local/v1alpha1/common_pb';
import { ListIntentionsResponseSchema, SavePlanResponseSchema, StartPlanResponseSchema } from './gen/ritueel/local/v1alpha1/plan_service_pb';

// Every string that comes from the bundle is data. This test gives each screen a
// world (one for each example bundle: personal, acme and globex, so acme/B, the cloud
// root and an empty cards list are drawn too) in which EVERY string field ends in a bidirectional override, a joiner and
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
    // The real one reads the summary through its own useCall, which a mock of the module does not reach.
    // The name of the bundle goes into every root written as <bundle>/<label>, so it must be marked too.
    useBundleName: () => (w.d.summary.bundle?.name as string | undefined) || undefined,
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

// The fixtures sit in one directory for each example bundle. Each has the same call-named files, and
// the plan files are named by goal.
const files = import.meta.glob('./fixtures/*/*.json', { eager: true, import: 'default' }) as Record<string, JsonValue>;
const parse = <S extends DescMessage>(schema: S, bundle: string, name: string) => mark(fromJson(schema, files[`./fixtures/${bundle}/${name}`])) as Message;

const BUNDLES: { bundle: string; goal: string; roots: number; cards: number; ceremonies: number }[] = [
  { bundle: 'personal', goal: 'retire-subkeys', roots: 1, cards: 6, ceremonies: 1 },
  { bundle: 'acme', goal: 'renew-due', roots: 2, cards: 2, ceremonies: 10 },
  { bundle: 'globex', goal: 'adopt-key', roots: 1, cards: 0, ceremonies: 1 },
];

/** Mark every string of one bundle's world, so that any screen that forgot T or safeString shows up. */
function loadWorld(bundle: string, goal: string) {
  w.d.summary = parse(GetSummaryResponseSchema, bundle, 'inspect.get-summary.json');
  w.d.findings = parse(ListFindingsResponseSchema, bundle, 'inspect.list-findings.json');
  w.d.roots = parse(ListRootsResponseSchema, bundle, 'inspect.list-roots.json');
  w.d.cards = parse(ListCardsResponseSchema, bundle, 'inspect.list-cards.json');
  w.d.ceremonies = parse(ListCeremoniesResponseSchema, bundle, 'inspect.list-ceremonies.json');
  w.d.trust = parse(ListTrustFilesResponseSchema, bundle, 'inspect.list-trust-files.json');
  w.d.intentions = parse(ListIntentionsResponseSchema, bundle, 'plan.list-intentions.json');
  w.d.questions = parse(StartPlanResponseSchema, bundle, `plan.start-plan.${goal}.questions.json`);
  w.d.plan = parse(StartPlanResponseSchema, bundle, `plan.start-plan.${goal}.json`);
  w.d.saved = parse(SavePlanResponseSchema, bundle, `plan.save-plan.${goal}.json`);
  w.d.command = 'ritueel plan' + BAD;
}

function offending(html: string): string[] {
  const seen = new Set<string>();
  for (const m of html.matchAll(new RegExp('(?:' + RAW.source + ')+', 'g'))) {
    const at = m.index ?? 0;
    seen.add(JSON.stringify(html.slice(Math.max(0, at - 36), at + 1).replace(/^[^<"=>]*/, '')));
  }
  return [...seen].slice(0, 12);
}

async function screens(goal: string) {
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
    ['plan questions', () => <Plan goal={goal} />],
    ['plan questions component', () => <Questions questions={w.d.questions.questions} onSubmit={() => {}} />],
    ['plan preview', () => <PlanView plan={w.d.plan.plan} />],
    ['plan saved', () => <Saved data={w.d.saved} place={w.d.plan.plan.runPlace} />],
    ['plan saved, place unknown', () => <Saved data={w.d.saved} />],
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
  for (const { bundle, goal, roots, cards, ceremonies } of BUNDLES) {
    it(`every screen of the ${bundle} bundle, with every string of the world marked`, async () => {
      loadWorld(bundle, goal);
      // The world is the bundle it is said to be: the test would prove nothing on an empty one.
      expect(w.d.roots.roots).toHaveLength(roots);
      expect(w.d.cards.cards).toHaveLength(cards);
      expect(w.d.ceremonies.ceremonies).toHaveLength(ceremonies);
      const list = await screens(goal);
      // 16 fixed screens, and one for every root, card and ceremony of the bundle
      expect(list.length).toBeGreaterThanOrEqual(16 + roots + cards + ceremonies);
      const failures: string[] = [];
      let sawEscape = 0;
      for (const [name, render] of list) {
        const html = renderToStaticMarkup(render());
        const bad = offending(html);
        if (bad.length) for (const b of bad) console.log(`HOSTILE ${bundle} ${name} ${b}`);
        if (bad.length) failures.push(`${name}:\n   ${bad.join('\n   ')}`);
        if (html.includes('U+202E')) sawEscape += 1;
      }
      expect(failures).toEqual([]);
      // the marked world did reach the screens, drawn as escapes
      expect(sawEscape, `${bundle} screens that show an escape`).toBeGreaterThanOrEqual(Math.max(15, list.length - 4));
    });
  }

  it('the stick sentence follows where the plan runs, not whether files are listed', async () => {
    loadWorld('globex', 'adopt-key');
    const { Saved } = await import('./screens/Plan');
    const text = (el: ReactElement) => renderToStaticMarkup(el).split(/<[^>]*>/).join('');
    const empty = { ...w.d.saved, copyToStick: [] };
    const offline = text(<Saved data={empty} place={RunPlace.OFFLINE_SYSTEM} />);
    expect(offline).not.toContain('your workstation, the computer');
    expect(offline).not.toContain('No stick is needed');
    expect(offline).toContain('The plan lists nothing to copy');
    const unknown = text(<Saved data={empty} place={RunPlace.UNSPECIFIED} />);
    expect(unknown).not.toContain('No stick is needed');
    expect(unknown).toContain('does not say where it runs');
    const none = text(<Saved data={empty} />);
    expect(none).not.toContain('No stick is needed');
    const workstation = text(<Saved data={empty} place={RunPlace.WORKSTATION} />);
    expect(workstation).toContain('No stick is needed');
  });

  it('the marked name of the bundle reaches a root written bundle/label as an escape, never raw', async () => {
    loadWorld('acme', 'renew-due');
    const { Roots } = await import('./screens/Roots');
    const { Key } = await import('./screens/Key');
    for (const [name, el] of [['roots', <Roots />], ['key', <Key root="A" />]] as [string, ReactElement][]) {
      const html = renderToStaticMarkup(el);
      expect(offending(html), name).toEqual([]);
      // Each escape is a span of its own: read the text. acme/A, with the marker after "acme" and after "A".
      const text = html.split(/<[^>]*>/).join('');
      expect(text, name).toContain('acmeU+202EU+200DU+0007/AU+202EU+200DU+0007');
    }
  });
});
