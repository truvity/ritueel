// Demo mode: an in-memory ConnectRPC transport. The handlers answer from the
// fixture files of the contract (the same messages the real service sends).
// There is no server and no network. Every call is a read; the contract has no
// call that writes. The transport answers for one bundle at a time, chosen by
// the switch in the demo bar (api/demoState.ts): the contract has no call that
// names a bundle, and the name of the bundle comes from GetSummary in the same
// way.
//
// Each bundle has five files, one for each call, named
// fixtures/<bundle>/inspect.<call in kebab case>.json, each the protobuf JSON
// of the response. The bundle acme also has five scenes (api/scenes.ts): a
// scene is the base file plus its own patches, and the answer carries the time
// of the scene. The other bundles have no scene. Every name, serial,
// fingerprint and date of the fixtures is made up; the names of the example
// company are those of docs/reference/bundle.md.
//
// The demo also shows the four states of a read. The switch in the demo bar
// (api/demoState.ts) makes the transport answer as an empty bundle, fail, or
// not answer yet. The empty answers are built here, not read from files, and
// ignore the scene.
import { Code, ConnectError, createRouterTransport, type Transport } from '@connectrpc/connect';
import { create, fromJson, type DescMessage, type JsonValue, type MessageShape } from '@bufbuild/protobuf';
import { ChainState, HistoryStatusSchema, Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  ChangeCountsSchema,
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  InspectService,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import type { BundleContents } from '../lib/route';
import { getBundle, getScene, getViewState, provideBundleContents, whenViewStateChanges } from './demoState';
import { applyScene, SCENE_COUNT } from './scenes';

/** The five calls, with the kebab-case word that names the fixture file of each. */
const FILES = {
  GetSummary: 'get-summary',
  ListFindings: 'list-findings',
  GetInventory: 'get-inventory',
  ListCeremonies: 'list-ceremonies',
  ListTrustFiles: 'list-trust-files',
} as const;
type Call = keyof typeof FILES;

// One directory of fixtures for each example bundle (acme, globex, personal).
// The glob also finds acme/scenes.json; only the call files are read as answers.
const files = import.meta.glob('../fixtures/*/*.json', { eager: true, import: 'default' }) as Record<string, JsonValue>;

/** The JSON of the base file of a call, for the open bundle. No scene is applied. */
function baseJson(call: Call): JsonValue {
  const path = `../fixtures/${getBundle()}/inspect.${FILES[call]}.json`;
  const hit = files[path];
  if (hit === undefined) throw new ConnectError(`demo: fixture ${path} is missing`, Code.Internal);
  return hit;
}

function parseBase<S extends DescMessage>(schema: S, call: Call): MessageShape<S> {
  return fromJson(schema, baseJson(call));
}

/** The answer of a call for the open bundle. Only acme has scenes: its base file gets the patches of the scene shown. */
function answer<S extends DescMessage>(schema: S, call: Call): MessageShape<S> {
  if (getBundle() !== 'acme') return parseBase(schema, call);
  if (getScene() > SCENE_COUNT) throw new ConnectError(`demo: scene ${getScene()} does not exist`, Code.Internal);
  return fromJson(schema, applyScene(call, baseJson(call)));
}

/** The made-up reason a failed read gives, built from the path of the current bundle. */
export function failedMessage(): string {
  const path = parseBase(GetSummaryResponseSchema, 'GetSummary').bundle?.path ?? '~/ritueel';
  return `ritueel could not read the bundle at ${path}. The reason, made up for this demo: the history could not be opened.`;
}

/**
 * The four states of a read. The failed and waiting answers are the same for
 * every call; "empty" has its own answer per call (the empty bundle).
 */
async function gate<T>(loaded: () => T | Promise<T>, empty: () => T): Promise<T> {
  const state = getViewState();
  if (state === 'failed') throw new ConnectError(failedMessage(), Code.Unavailable);
  if (state === 'waiting') {
    await whenViewStateChanges();
    throw new ConnectError('The wait ended because the demo state changed.', Code.Canceled);
  }
  return state === 'empty' ? empty() : loaded();
}

// ---- the empty bundle, built from the loaded one so the two never drift ------

/** The history of a bundle with no record: the first ceremony writes the first one. */
function emptyHistory() {
  return create(HistoryStatusSchema, {
    recordCount: 0,
    chainState: ChainState.NOT_CHECKED,
    message: 'The history has no records yet. The first ceremony writes the first record.',
  });
}

function emptySummary() {
  const full = parseBase(GetSummaryResponseSchema, 'GetSummary');
  return create(GetSummaryResponseSchema, {
    bundle: full.bundle,
    readAt: full.readAt,
    demo: true,
    programVersion: full.programVersion,
    history: emptyHistory(),
    changes: create(ChangeCountsSchema, {}),
    ceremoniesWithoutRecord: 0,
    trustSequence: 0,
  });
}

/** The time of the base read, for the answers of the empty bundle. */
function emptyReadAt() {
  return parseBase(GetSummaryResponseSchema, 'GetSummary').readAt;
}

/**
 * What the open bundle holds, for the bundle switch and the scene switch: they
 * keep the screen, and a detail view falls back only if the bundle (or the
 * scene) has no such object or ceremony. Read from the same answers the
 * transport gives, in the page state shown now.
 */
function bundleContents(): BundleContents {
  // The empty state holds no object and no ceremony.
  if (getViewState() === 'empty') return { objects: [], ceremonies: [] };
  const inv = answer(GetInventoryResponseSchema, 'GetInventory');
  const objects = [
    ...inv.cards.map((c) => `card/${c.name}`),
    ...inv.roots.map((r) => `root/${r.name}`),
    ...inv.keys.map((k) => `key/${k.fingerprint}`),
    ...inv.userIds.map((u) => `userid/${u.id}`),
    ...inv.delegations.map((d) => `delegation/${d.name}`),
    ...inv.certifications.map((c) => `certification/${c.id}`),
    ...inv.requests.map((r) => `request/${r.stem}`),
  ];
  return { objects, ceremonies: answer(ListCeremoniesResponseSchema, 'ListCeremonies').ceremonies.map((c) => c.id) };
}
provideBundleContents(bundleContents);

export function createDemoTransport(): Transport {
  return createRouterTransport(({ service }) => {
    service(InspectService, {
      getSummary: () => gate(() => answer(GetSummaryResponseSchema, 'GetSummary'), emptySummary),
      listFindings: (req) =>
        gate(
          () => {
            const all = answer(ListFindingsResponseSchema, 'ListFindings');
            // min_severity is applied here, not by the file.
            const min = req.minSeverity === Severity.UNSPECIFIED ? 0 : req.minSeverity;
            return create(ListFindingsResponseSchema, { findings: all.findings.filter((f) => f.severity >= min), readAt: all.readAt });
          },
          () => create(ListFindingsResponseSchema, { readAt: emptyReadAt() }),
        ),
      getInventory: () => gate(() => answer(GetInventoryResponseSchema, 'GetInventory'), () => create(GetInventoryResponseSchema, { readAt: emptyReadAt() })),
      listCeremonies: () =>
        gate(
          () => answer(ListCeremoniesResponseSchema, 'ListCeremonies'),
          () => create(ListCeremoniesResponseSchema, { history: emptyHistory(), readAt: emptyReadAt() }),
        ),
      listTrustFiles: () => gate(() => answer(ListTrustFilesResponseSchema, 'ListTrustFiles'), () => create(ListTrustFilesResponseSchema, { readAt: emptyReadAt() })),
    });
  });
}
