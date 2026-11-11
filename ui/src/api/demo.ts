// Demo mode: an in-memory ConnectRPC transport. The handlers answer from the
// fixture files of the contract (the same messages the real service sends).
// There is no server and no network. Every handler is a read, except the one
// write of the contract, SavePlan: it answers from its fixture, which says
// written=false and that this is a demo, and nothing is written anywhere.
//
// The demo also shows the four states of a read. The switch in the demo bar
// (api/demoState.ts) makes the transport answer as an empty folder, fail, or
// not answer yet.
import { Code, ConnectError, createRouterTransport, type Transport } from '@connectrpc/connect';
import { create, fromJson, type DescMessage, type JsonValue, type MessageShape } from '@bufbuild/protobuf';
import { ChainState, Intention, LedgerStatusSchema, Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  CountsSchema,
  FindingCountSchema,
  GetSummaryResponseSchema,
  InspectService,
  ListCardsResponseSchema,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListRootsResponseSchema,
  ListTrustFilesResponseSchema,
  SetupStepSchema,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import {
  ListIntentionsResponseSchema,
  PlanService,
  SavePlanResponseSchema,
  StartPlanResponseSchema,
  type SavePlanRequest,
  type StartPlanRequest,
} from '../gen/ritueel/local/v1alpha1/plan_service_pb';
import { getViewState, whenViewStateChanges } from './demoState';

const files = import.meta.glob('../fixtures/*.json', { eager: true, import: 'default' }) as Record<string, JsonValue>;

function load(name: string): JsonValue {
  const hit = files[`../fixtures/${name}`];
  if (hit === undefined) throw new ConnectError(`demo: fixture ${name} is missing`, Code.Internal);
  return hit;
}

function parse<S extends DescMessage>(schema: S, name: string): MessageShape<S> {
  return fromJson(schema, load(name));
}

interface ManifestEntry {
  service: string;
  method: string;
  when?: { intention?: string; answers?: 'none' | 'any'; planId?: string };
  file: string;
}

const manifest = (load('manifest.json') as unknown as { responses: ManifestEntry[] }).responses;

const INTENTION_NAMES: Record<number, string> = {
  [Intention.RENEW_DUE]: 'INTENTION_RENEW_DUE',
  [Intention.ADOPT_KEY]: 'INTENTION_ADOPT_KEY',
  [Intention.REPLACE_SUBKEYS]: 'INTENTION_REPLACE_SUBKEYS',
  [Intention.ADD_CARD]: 'INTENTION_ADD_CARD',
  [Intention.REPLACE_CARD]: 'INTENTION_REPLACE_CARD',
};

function pick(method: string, test: (when: NonNullable<ManifestEntry['when']>) => boolean): string {
  const hit = manifest.find((e) => e.method === method && e.when && test(e.when));
  if (!hit) {
    // A call that matches no entry fails loudly, as the contract asks.
    throw new ConnectError(`The demo has no recorded answer for this ${method} request.`, Code.Unimplemented);
  }
  return hit.file;
}

export const FAILED_MESSAGE =
  'ritueel could not read the folder at ~/ritueel. The reason, made up for this demo: the ledger file could not be opened.';

/**
 * The four states of a read. The failed and waiting answers are the same for
 * every call; "empty" has its own answer per call (the empty folder).
 */
async function gate<T>(loaded: () => T | Promise<T>, empty: () => T): Promise<T> {
  const state = getViewState();
  if (state === 'failed') throw new ConnectError(FAILED_MESSAGE, Code.Unavailable);
  if (state === 'waiting') {
    await whenViewStateChanges();
    throw new ConnectError('The wait ended because the demo state changed.', Code.Canceled);
  }
  return state === 'empty' ? empty() : loaded();
}

// ---- the empty folder, built from the loaded one so the two never drift ------

const SEVERITIES = [Severity.CRITICAL, Severity.ALERT, Severity.NOTICE, Severity.INFO];

function emptySummary() {
  const full = parse(GetSummaryResponseSchema, 'inspect.get-summary.json');
  return create(GetSummaryResponseSchema, {
    folder: full.folder,
    asOf: full.asOf,
    demo: true,
    programVersion: full.programVersion,
    ledger: create(LedgerStatusSchema, {
      recordCount: 0,
      chainState: ChainState.NOT_CHECKED,
      message: 'The ledger has no records yet. The first ceremony writes the first record.',
    }),
    due: [],
    findingCounts: SEVERITIES.map((severity) => create(FindingCountSchema, { severity, count: 0 })),
    counts: create(CountsSchema, {}),
    pendingPlans: [],
    setupSteps: full.setupSteps.map((s) =>
      create(SetupStepSchema, {
        ...s,
        done: s.id === 'folder',
        // The loaded folder's sentences name its keys and cards: an empty folder has none.
        detail: s.id === 'cards' ? 'No cards are registered yet.' : s.id === 'first-plan' ? 'Start by adopting the key you already have.' : s.id === 'public-key' ? 'Only the public half is ever needed here.' : s.detail,
      }),
    ),
  });
}

function emptyIntentions() {
  const full = parse(ListIntentionsResponseSchema, 'plan.list-intentions.json');
  const reasons: Partial<Record<Intention, string>> = {
    [Intention.RENEW_DUE]: 'Nothing is due, because the folder holds no keys yet.',
    [Intention.REPLACE_SUBKEYS]: 'There are no subkeys to retire yet.',
  };
  return create(ListIntentionsResponseSchema, {
    options: full.options.map((o) => {
      if (o.intention === Intention.ADOPT_KEY) {
        return { ...o, applicable: true, recommended: true, recommendedReason: 'The folder holds no key yet. Adopt the one you already have.' };
      }
      const why = reasons[o.intention];
      return why ? { ...o, applicable: false, recommended: false, notApplicableReason: why } : o;
    }),
  });
}

export function createDemoTransport(): Transport {
  return createRouterTransport(({ service }) => {
    service(InspectService, {
      getSummary: () => gate(() => parse(GetSummaryResponseSchema, 'inspect.get-summary.json'), emptySummary),
      listFindings: (req) =>
        gate(
          () => {
            const all = parse(ListFindingsResponseSchema, 'inspect.list-findings.json');
            // min_severity is applied here, not by the file.
            const min = req.minSeverity === Severity.UNSPECIFIED ? 0 : req.minSeverity;
            return { findings: all.findings.filter((f) => f.severity >= min) };
          },
          () => create(ListFindingsResponseSchema, {}),
        ),
      listRoots: () => gate(() => parse(ListRootsResponseSchema, 'inspect.list-roots.json'), () => create(ListRootsResponseSchema, {})),
      listCeremonies: () =>
        gate(
          () => parse(ListCeremoniesResponseSchema, 'inspect.list-ceremonies.json'),
          () => create(ListCeremoniesResponseSchema, { ledger: emptySummary().ledger }),
        ),
      listCards: () => gate(() => parse(ListCardsResponseSchema, 'inspect.list-cards.json'), () => create(ListCardsResponseSchema, {})),
      listTrustFiles: () => gate(() => parse(ListTrustFilesResponseSchema, 'inspect.list-trust-files.json'), () => create(ListTrustFilesResponseSchema, {})),
    });
    service(PlanService, {
      listIntentions: () => gate(() => parse(ListIntentionsResponseSchema, 'plan.list-intentions.json'), emptyIntentions),
      startPlan: (req: StartPlanRequest) => {
        const build = () => {
          const name = INTENTION_NAMES[req.intention] ?? '';
          const hasAnswers = req.answers.length > 0;
          const file = pick('StartPlan', (w) => w.intention === name && (w.answers === undefined || (w.answers === 'any') === hasAnswers));
          return parse(StartPlanResponseSchema, file);
        };
        return gate(build, build);
      },
      savePlan: (req: SavePlanRequest) => {
        // The one call that would act. The demo answers, writes nothing, and says so.
        const build = () => parse(SavePlanResponseSchema, pick('SavePlan', (w) => w.planId === req.planId));
        return gate(build, build);
      },
    });
  });
}
