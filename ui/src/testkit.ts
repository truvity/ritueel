// Helpers for the tests only. Nothing in the page imports this file, so no build
// carries it. It gives a test the made-up worlds of the demo (three bundles, and
// the five scenes of acme), a way to mark every string of a world, and the
// mock of the read hooks that the screen tests share.
import { createClient } from '@connectrpc/connect';
import { fromJson, type JsonValue } from '@bufbuild/protobuf';
import {
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  InspectService,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
  type GetInventoryResponse,
  type GetSummaryResponse,
  type ListCeremoniesResponse,
  type ListFindingsResponse,
  type ListTrustFilesResponse,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { applySceneNumber } from './api/scenes';
import { createDemoTransport } from './api/demo';
import { setBundle, setScene, setViewState, type DemoBundle } from './api/demoState';

/** The marker the hostile test appends to every string: a bidirectional override, a joiner and a BEL. */
export const BAD = String.fromCodePoint(0x202e, 0x200d, 0x0007);

export interface World {
  /** `acme`, `globex`, `personal`, or `acme scene N`. */
  id: string;
  bundle: DemoBundle;
  scene: number;
  summary: GetSummaryResponse;
  findings: ListFindingsResponse;
  inventory: GetInventoryResponse;
  ceremonies: ListCeremoniesResponse;
  trust: ListTrustFilesResponse;
}

export const BUNDLES: readonly DemoBundle[] = ['acme', 'globex', 'personal'];

/** The worlds every screen test walks: the three bundles, then scenes 2 to 5 of acme. */
export const WORLD_IDS: { id: string; bundle: DemoBundle; scene: number }[] = [
  { id: 'acme', bundle: 'acme', scene: 1 },
  { id: 'globex', bundle: 'globex', scene: 1 },
  { id: 'personal', bundle: 'personal', scene: 1 },
  ...[2, 3, 4, 5].map((scene) => ({ id: `acme scene ${scene}`, bundle: 'acme' as const, scene })),
];

const files = import.meta.glob('./fixtures/*/*.json', { eager: true, import: 'default' }) as Record<string, JsonValue>;

const CALLS = {
  GetSummary: 'get-summary',
  ListFindings: 'list-findings',
  GetInventory: 'get-inventory',
  ListCeremonies: 'list-ceremonies',
  ListTrustFiles: 'list-trust-files',
} as const;

/** The JSON of a base file, as the demo transport reads it. */
export function baseJson(bundle: DemoBundle, call: keyof typeof CALLS): JsonValue {
  const json = files[`./fixtures/${bundle}/inspect.${CALLS[call]}.json`];
  if (json === undefined) throw new Error(`no fixture for ${bundle} ${call}`);
  return json;
}

/** The answer of one call in a world: the base file, and for acme the patches of the scene. */
export function answerJson(bundle: DemoBundle, scene: number, call: keyof typeof CALLS): JsonValue {
  const base = baseJson(bundle, call);
  return bundle === 'acme' ? applySceneNumber(scene, call, base) : base;
}

export function loadWorld(bundle: DemoBundle, scene = 1): World {
  const json = (call: keyof typeof CALLS) => answerJson(bundle, scene, call);
  return {
    id: bundle === 'acme' && scene > 1 ? `acme scene ${scene}` : bundle,
    bundle,
    scene,
    summary: fromJson(GetSummaryResponseSchema, json('GetSummary')),
    findings: fromJson(ListFindingsResponseSchema, json('ListFindings')),
    inventory: fromJson(GetInventoryResponseSchema, json('GetInventory')),
    ceremonies: fromJson(ListCeremoniesResponseSchema, json('ListCeremonies')),
    trust: fromJson(ListTrustFilesResponseSchema, json('ListTrustFiles')),
  };
}

/**
 * The world as the demo transport answers it in the Empty page state: a bundle that holds
 * nothing. The answers are built by code in api/demo.ts, so they are asked of the transport.
 */
export async function emptyWorld(bundle: DemoBundle): Promise<World> {
  const inspect = createClient(InspectService, createDemoTransport());
  setBundle(bundle);
  setScene(1);
  setViewState('empty');
  try {
    return {
      id: `${bundle} empty`,
      bundle,
      scene: 1,
      summary: await inspect.getSummary({}),
      findings: await inspect.listFindings({}),
      inventory: await inspect.getInventory({}),
      ceremonies: await inspect.listCeremonies({}),
      trust: await inspect.listTrustFiles({}),
    };
  } finally {
    setViewState('loaded');
    setBundle('acme');
  }
}

export const WORLDS = (): World[] => WORLD_IDS.map((w) => loadWorld(w.bundle, w.scene));

/** The same world with the marker after every string. Numbers, bigints and enums stay. */
export function marked<T>(v: T, change: (s: string) => string = (s) => s + BAD): T {
  const mark = (x: unknown): unknown => {
    if (typeof x === 'string') return change(x);
    if (Array.isArray(x)) return x.map(mark);
    if (x && typeof x === 'object') {
      const o: Record<string, unknown> = {};
      for (const [k, y] of Object.entries(x)) o[k] = k === '$typeName' ? y : mark(y);
      return o;
    }
    return x;
  };
  return mark(v) as T;
}

export function markedWorld(w: World, change?: (s: string) => string): World {
  return { ...w, summary: marked(w.summary, change), findings: marked(w.findings, change), inventory: marked(w.inventory, change), ceremonies: marked(w.ceremonies, change), trust: marked(w.trust, change) };
}

/** What the mocked hooks answer. A test sets it before it renders a screen. */
export const feed: { world: World | undefined; state: 'ready' | 'loading' | 'error' } = { world: undefined, state: 'ready' };

/**
 * The hooks of a screen, answering from `feed`. The module mock of a test file
 * calls this with the real module: `vi.mock('./api/hooks', async (orig) =>
 * (await import('./testkit')).hooksMock(await orig()))`.
 */
export function hooksMock<H extends object>(real: H): H {
  const answer = <T>(pick: (w: World) => T) => {
    if (feed.state === 'loading') return { state: 'loading' as const };
    if (feed.state === 'error') return { state: 'error' as const, message: 'could not read', retry() {} };
    return { state: 'ready' as const, data: pick(feed.world as World), reload() {} };
  };
  return {
    ...real,
    useSummary: () => answer((w) => w.summary),
    useFindings: (min = 0) => answer((w) => ({ ...w.findings, findings: w.findings.findings.filter((f) => f.severity >= min) })),
    useInventory: () => answer((w) => w.inventory),
    useCeremonies: () => answer((w) => w.ceremonies),
    useTrustFiles: () => answer((w) => w.trust),
    useBundleName: () => (feed.world?.summary.bundle?.name as string | undefined) || undefined,
  };
}

/** The text of some markup: tags removed, entities of the quote and the ampersand read back, spaces folded. */
export function plain(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/g, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Every `name="value"` attribute of one start tag, as a map. */
export function attrsOf(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(/([a-zA-Z:-]+)="([^"]*)"/g)) out[m[1]] = m[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&#x27;/g, "'");
  return out;
}
