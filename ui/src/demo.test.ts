import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { fromJson, type DescMessage } from '@bufbuild/protobuf';
import { Intention, RunPlace, Severity, Store } from './gen/ritueel/local/v1alpha1/common_pb';
import {
  CardKind,
  GetSummaryResponseSchema,
  InspectService,
  ListCardsResponseSchema,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListRootsResponseSchema,
  ListTrustFilesResponseSchema,
  SlotUse,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { ListIntentionsResponseSchema, PlanService, SavePlanResponseSchema, StartPlanResponseSchema } from './gen/ritueel/local/v1alpha1/plan_service_pb';
import { createDemoTransport } from './api/demo';
import { CARD_KIND_WORD } from './lib/words';
import { INTENTION_SLUG } from './lib/finding';
import { CAPS } from './lib/caps';
import { COMMAND_CAP, DEFAULT_CAP, FINGERPRINT_CAP } from './lib/safe';
import { parseHash, type Route } from './lib/route';
import { DEMO_BUNDLES, getBundle, setBundle, setViewState, type DemoBundle } from './api/demoState';

const t = createDemoTransport();
const inspect = createClient(InspectService, t);
const plans = createClient(PlanService, t);

const BUNDLES: DemoBundle[] = ['personal', 'acme', 'globex'];

afterEach(() => {
  setViewState('loaded');
  setBundle('personal');
});

describe('every call of the contract answers', () => {
  it('InspectService: every method answers with no argument', async () => {
    for (const m of InspectService.methods) {
      const call = (inspect as unknown as Record<string, (r: object) => Promise<unknown>>)[m.localName];
      await expect(call({}), m.name).resolves.toBeDefined();
    }
  });
  it('PlanService: ListIntentions answers, StartPlan answers for every goal, SavePlan answers for every plan', async () => {
    expect((await plans.listIntentions({})).options).toHaveLength(5);
    for (const b of BUNDLES) {
      setBundle(b);
      expect((await plans.listIntentions({})).options, b).toHaveLength(5);
      for (const i of [Intention.RENEW_DUE, Intention.ADOPT_KEY, Intention.RETIRE_SUBKEYS, Intention.ADD_CARD, Intention.REPLACE_CARD]) {
        const r = await plans.startPlan({ intention: i });
        expect(r.questions.length + (r.plan ? 1 : 0) + (r.refusal ? 1 : 0), `${b} intention ${i}`).toBeGreaterThan(0);
      }
    }
  });
  it('the services list every method this test knows (a new call must get a test)', () => {
    expect(InspectService.methods.map((m) => m.name).sort()).toEqual(['GetSummary', 'ListCards', 'ListCeremonies', 'ListFindings', 'ListRoots', 'ListTrustFiles']);
    expect(PlanService.methods.map((m) => m.name).sort()).toEqual(['ListIntentions', 'SavePlan', 'StartPlan']);
    // In this contract no call lists or selects a bundle (which bundle the process serves is not decided by the records, record 0010).
    // The switch of the demo is chrome around the transport, never part of the contract.
    const all = [...InspectService.methods, ...PlanService.methods].map((m) => m.name);
    expect(all.filter((n) => /bundle/i.test(n))).toEqual([]);
  });
});

// What each example bundle holds. One bundle is one trust domain, with its own history, roots and cards.
const WORLD: Record<DemoBundle, { name: string; path: string; due: number; records: number; findings: number; alert: number; roots: number; delegated: number; cards: number; ceremonies: number; trustFiles: number }> = {
  personal: { name: 'personal', path: '~/ritueel/personal', due: 0, records: 1, findings: 8, alert: 3, roots: 1, delegated: 0, cards: 6, ceremonies: 1, trustFiles: 2 },
  acme: { name: 'acme', path: '~/ritueel/acme', due: 3, records: 10, findings: 1, alert: 0, roots: 2, delegated: 2, cards: 2, ceremonies: 10, trustFiles: 6 },
  globex: { name: 'globex', path: '~/ritueel/globex', due: 0, records: 1, findings: 1, alert: 0, roots: 1, delegated: 0, cards: 0, ceremonies: 1, trustFiles: 5 },
};

describe('the fixtures tell the made-up world, one bundle at a time', () => {
  it('starts on the personal bundle', () => {
    expect(getBundle()).toBe('personal');
    expect(DEMO_BUNDLES.map((b) => b.value)).toEqual(BUNDLES);
  });
  for (const b of BUNDLES) {
    const w = WORLD[b];
    describe(b, () => {
      it('summary: its name, path, due list, history and counts, a demo', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        expect(s.demo).toBe(true);
        expect(s.bundle?.name).toBe(w.name);
        expect(s.bundle?.path).toBe(w.path);
        expect(s.due).toHaveLength(w.due);
        expect(s.history?.recordCount).toBe(w.records);
        expect(s.counts?.roots).toBe(w.roots);
        expect(s.counts?.delegatedKeys).toBe(w.delegated);
        expect(s.counts?.cards).toBe(w.cards);
        expect(s.counts?.trustFiles).toBe(w.trustFiles);
      });
      it('findings: all of them, and min_severity is applied by the transport', async () => {
        setBundle(b);
        expect((await inspect.listFindings({})).findings).toHaveLength(w.findings);
        expect((await inspect.listFindings({ minSeverity: Severity.ALERT })).findings).toHaveLength(w.alert);
      });
      it('roots, cards, ceremonies, trust files, and the numbers of the summary agree with them', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        const roots = (await inspect.listRoots({})).roots;
        const cards = (await inspect.listCards({})).cards;
        expect(roots).toHaveLength(w.roots);
        expect(cards).toHaveLength(w.cards);
        expect((await inspect.listCeremonies({})).ceremonies).toHaveLength(w.ceremonies);
        expect((await inspect.listTrustFiles({})).files).toHaveLength(w.trustFiles);
        expect(s.counts?.roots).toBe(roots.length);
        expect(s.counts?.cards).toBe(cards.length);
        // A root is written <bundle>/<label>: labels are letters, A first, and unique inside the bundle.
        expect(roots.map((r) => r.label)).toEqual(['A', 'B', 'C'].slice(0, w.roots));
      });
      it('the history head of the summary is the last record of the ceremonies list', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        const c = await inspect.listCeremonies({});
        expect(c.history?.recordCount).toBe(c.ceremonies.length);
        expect(c.history?.lastRecordId).toBe(s.history?.lastRecordId);
        expect(c.ceremonies.map((x) => x.id)).toContain(s.history?.lastRecordId);
        // A record is named like a plan: the time in UTC, a hyphen, the command.
        for (const x of c.ceremonies) expect(x.id).toMatch(/^[0-9]{8}T[0-9]{6}Z-[a-z0-9]+(-[a-z0-9]+)*$/);
      });
    });
  }

  it('switching the bundle changes every answer, and the contract has no call for it', async () => {
    const names = [];
    for (const b of BUNDLES) {
      setBundle(b);
      names.push((await inspect.getSummary({})).bundle?.name);
    }
    expect(names).toEqual(['personal', 'acme', 'globex']);
    setBundle('acme');
    expect((await inspect.listRoots({})).roots).toHaveLength(2);
    setBundle('globex');
    expect((await inspect.listRoots({})).roots).toHaveLength(1);
    expect((await inspect.listCards({})).cards).toHaveLength(0);
  });

  it('a bundle that has no card says so: a cloud root needs none', async () => {
    setBundle('globex');
    const goals = (await plans.listIntentions({})).options;
    expect(goals.find((g) => g.intention === Intention.ADD_CARD)?.applicable).toBe(false);
    expect((await inspect.getSummary({})).setupSteps.map((x) => x.id)).not.toContain('cards');
  });

  it('keeps the cards and roots of the bundles apart: no serial, fingerprint or digest is shared', async () => {
    const seen = new Map<string, DemoBundle>();
    const note = (kind: string, value: string | undefined, b: DemoBundle) => {
      if (!value) return;
      expect(seen.get(`${kind} ${value}`), `${kind} ${value} in ${b}`).toBeUndefined();
      seen.set(`${kind} ${value}`, b);
    };
    for (const b of BUNDLES) {
      setBundle(b);
      for (const c of (await inspect.listCards({})).cards) note('serial', c.serial, b);
      for (const r of (await inspect.listRoots({})).roots) {
        for (const k of r.keys) note('root fingerprint', k.fingerprint, b);
        for (const k of r.delegatedKeys) {
          note('delegated fingerprint', k.fingerprint, b);
          note('certified by', k.certifiedBy, b);
        }
        for (const set of r.certificate?.subkeySets ?? []) for (const k of set.subkeys) note('subkey', k.fingerprint, b);
      }
    }
  });

  it('goals: each bundle says what applies to it', async () => {
    const want: Record<DemoBundle, Partial<Record<Intention, { applicable: boolean; recommended?: boolean }>>> = {
      personal: {
        [Intention.RENEW_DUE]: { applicable: false },
        [Intention.RETIRE_SUBKEYS]: { applicable: true, recommended: true },
        [Intention.ADOPT_KEY]: { applicable: false },
        [Intention.ADD_CARD]: { applicable: false },
        [Intention.REPLACE_CARD]: { applicable: false },
      },
      acme: {
        [Intention.RENEW_DUE]: { applicable: true, recommended: true },
        [Intention.RETIRE_SUBKEYS]: { applicable: false },
        [Intention.ADOPT_KEY]: { applicable: false },
        [Intention.ADD_CARD]: { applicable: false },
        [Intention.REPLACE_CARD]: { applicable: false },
      },
      globex: {
        [Intention.RENEW_DUE]: { applicable: false },
        [Intention.RETIRE_SUBKEYS]: { applicable: false },
        [Intention.ADOPT_KEY]: { applicable: true, recommended: true },
        [Intention.ADD_CARD]: { applicable: false },
        [Intention.REPLACE_CARD]: { applicable: false },
      },
    };
    for (const b of BUNDLES) {
      setBundle(b);
      const goals = (await plans.listIntentions({})).options;
      for (const [i, e] of Object.entries(want[b])) {
        const g = goals.find((x) => x.intention === Number(i));
        expect(g?.applicable, `${b} ${Intention[Number(i)]}`).toBe(e.applicable);
        expect(g?.recommended, `${b} ${Intention[Number(i)]} recommended`).toBe(e.recommended ?? false);
        // A goal that does not apply says why.
        if (!e.applicable) expect(g?.notApplicableReason, `${b} ${Intention[Number(i)]} reason`).not.toBe('');
      }
    }
  });
});

// The plan each bundle can save: its id is the ceremony name, so it is unique inside the bundle,
// which is where a plan is saved. runPlace says where the plan runs.
const SAVED: Record<DemoBundle, { id: string; place: RunPlace; stick: boolean }> = {
  acme: { id: '20261111T090000Z-due', place: RunPlace.WORKSTATION, stick: false },
  personal: { id: '20261111T090000Z-personal-subkey-revoke', place: RunPlace.OFFLINE_SYSTEM, stick: true },
  globex: { id: '20261111T090000Z-root-add', place: RunPlace.WORKSTATION, stick: false },
};

describe('a call that would act answers that this is a demo', () => {
  it('a plan is built in memory with its digest and command, in the bundle that has such a goal', async () => {
    setBundle('acme');
    const q = await plans.startPlan({ intention: Intention.RENEW_DUE });
    expect(q.questions.length).toBeGreaterThan(0);
    const p = await plans.startPlan({ intention: Intention.RENEW_DUE, answers: q.questions.map((x) => ({ questionId: x.id, optionIds: x.defaultOptionIds })) });
    expect(p.plan?.digest).toMatch(/deadbeef$/);
    expect(p.plan?.runCommand).toContain(' run history/');
    expect(p.plan?.runCommand).toContain('/plan.json --confirm ');
    expect(p.plan?.savePath).toMatch(/^history\/[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+\/plan\.json$/);
    expect(p.plan?.runPlace).toBe(RunPlace.WORKSTATION);
  });
  it('every plan says where it runs: the offline system for a key file, the workstation for a root on cards or in the cloud', async () => {
    for (const [b, goal, place] of [
      ['personal', Intention.RETIRE_SUBKEYS, RunPlace.OFFLINE_SYSTEM],
      ['acme', Intention.RENEW_DUE, RunPlace.WORKSTATION],
      ['globex', Intention.ADOPT_KEY, RunPlace.WORKSTATION],
    ] as const) {
      setBundle(b);
      const q = await plans.startPlan({ intention: goal });
      const p = await plans.startPlan({ intention: goal, answers: q.questions.map((x) => ({ questionId: x.id, optionIds: x.defaultOptionIds })) });
      expect(p.plan?.runPlace, b).toBe(place);
      // The plan, the saved plan and the id of the bundle agree with each other.
      expect(p.plan?.id, b).toBe(SAVED[b].id);
      expect(p.plan?.savePath, b).toBe(`history/${SAVED[b].id}/plan.json`);
    }
  });
  it('a goal of one bundle is not applicable in another: the not-now refusal answers', async () => {
    setBundle('personal');
    const r = await plans.startPlan({ intention: Intention.RENEW_DUE });
    expect(r.plan).toBeUndefined();
    expect(r.questions).toHaveLength(0);
    expect(r.refusal).toBe('This goal does not apply to this bundle now. The goals screen says why.');
    setBundle('globex');
    expect((await plans.startPlan({ intention: Intention.RETIRE_SUBKEYS })).refusal).toMatch(/does not apply to this bundle/);
    setBundle('acme');
    expect((await plans.startPlan({ intention: Intention.ADOPT_KEY })).refusal).toMatch(/does not apply to this bundle/);
  });
  it('SavePlan writes nothing and says it is a demo, for the plan of every bundle', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const { id, place, stick } = SAVED[b];
      const saved = await plans.savePlan({ planId: id, digest: '' });
      expect(saved.written, id).toBe(false);
      expect(saved.notice, id).toMatch(/demo/i);
      expect(saved.notice, id).toMatch(/nothing was written/i);
      expect(saved.planFilePreview.length).toBeGreaterThan(20);
      // The plan is saved inside the bundle, where the engine writes any plan.
      expect(saved.bundlePath, id).toBe(`~/ritueel/${b}`);
      expect(saved.path, id).toBe(`history/${id}/plan.json`);
      // The run command names the bundle (--dir), as docs/reference/cli.md has it.
      expect(saved.runCommand, id).toBe(`ritueel --dir ~/ritueel/${b} run history/${id}/plan.json --confirm ${saved.digest}`);
      expect(saved.digest, id).toMatch(/^[0-9a-f]{64}$/);
      expect(saved.planFilePreview, id).toContain(`"ceremony": "${id}"`);
      // The USB stick is a step only where the plan runs on the offline system.
      expect(saved.copyToStick.length > 0, `${id} stick (${RunPlace[place]})`).toBe(stick);
      expect(saved.bring.length, id).toBeGreaterThan(0);
      expect(saved.whenBack, id).not.toBe('');
    }
  });
  it('a plan id answers only in the bundle that holds the plan', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      for (const other of BUNDLES.filter((x) => x !== b)) {
        await expect(plans.savePlan({ planId: SAVED[other].id, digest: '' }), `${SAVED[other].id} in ${b}`).rejects.toThrow(/no recorded answer/);
      }
    }
  });
  it('a goal that does not apply because it needs a card is refused with its reason', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      expect((await plans.startPlan({ intention: Intention.ADD_CARD })).refusal, b).toMatch(/demo/i);
      expect((await plans.startPlan({ intention: Intention.REPLACE_CARD })).refusal, b).toMatch(/demo/i);
    }
  });
  it('a call that matches no fixture fails loudly', async () => {
    await expect(plans.savePlan({ planId: 'nope', digest: '' })).rejects.toThrow(/no recorded answer/);
  });
});

describe('the four states of a read', () => {
  it('empty: a bundle that holds nothing, for every example bundle, with its name kept', async () => {
    setViewState('empty');
    for (const b of BUNDLES) {
      setBundle(b);
      const s = await inspect.getSummary({});
      expect(s.bundle?.name, b).toBe(WORLD[b].name);
      expect(s.counts?.roots, b).toBe(0);
      expect(s.due, b).toHaveLength(0);
      expect(s.history?.recordCount, b).toBe(0);
      expect(s.setupSteps.filter((x) => x.done), b).toHaveLength(1);
      expect(s.setupSteps.find((x) => x.done)?.id, b).toBe('bundle');
      expect((await inspect.listFindings({})).findings, b).toHaveLength(0);
      expect((await inspect.listRoots({})).roots, b).toHaveLength(0);
      expect((await inspect.listCards({})).cards, b).toHaveLength(0);
      expect((await inspect.listCeremonies({})).ceremonies, b).toHaveLength(0);
      expect((await inspect.listTrustFiles({})).files, b).toHaveLength(0);
      const goals = (await plans.listIntentions({})).options;
      expect(goals.find((g) => g.intention === Intention.ADOPT_KEY)?.recommended, b).toBe(true);
      expect(goals.find((g) => g.intention === Intention.RENEW_DUE)?.applicable, b).toBe(false);
      expect(goals.find((g) => g.intention === Intention.RETIRE_SUBKEYS)?.applicable, b).toBe(false);
      // The goal the empty bundle recommends must lead somewhere, in every example bundle: not to
      // "this goal does not apply" (the goals screen says it applies).
      const questions = await plans.startPlan({ intention: Intention.ADOPT_KEY });
      expect(questions.refusal, b).toBe('');
      expect(questions.questions.length, b).toBeGreaterThan(0);
      const adopt = await plans.startPlan({ intention: Intention.ADOPT_KEY, answers: [{ questionId: 'use', optionIds: ['root'] }] });
      expect(adopt.plan?.runPlace, b).toBe(RunPlace.WORKSTATION);
      const saved = await plans.savePlan({ planId: adopt.plan?.id ?? '', digest: adopt.plan?.digest ?? '' });
      expect(saved.path, b).toBe(`history/${adopt.plan?.id}/plan.json`);
      const here = (await inspect.getSummary({})).bundle?.path;
      expect(saved.bundlePath, b).toBe(here);
      // The commands of the shared answer name the open bundle, never the example one.
      expect(adopt.plan?.runCommand, b).toContain(`--dir ${here} run `);
      expect(adopt.plan?.equivalentCommand, b).toContain(`--dir ${here} init `);
      expect(adopt.plan?.runCommand, b).not.toContain('ritueel/example');
    }
  });
  it('failed: every read fails with an error, never an empty answer, and names the bundle it could not read', async () => {
    setViewState('failed');
    for (const b of BUNDLES) {
      setBundle(b);
      for (const call of [() => inspect.getSummary({}), () => inspect.listFindings({}), () => inspect.listRoots({}), () => inspect.listCards({}), () => inspect.listCeremonies({}), () => inspect.listTrustFiles({}), () => plans.listIntentions({}), () => plans.savePlan({ planId: SAVED[b].id, digest: '' })]) {
        const err = await call().then(
          () => undefined,
          (e: unknown) => e,
        );
        expect(err).toBeInstanceOf(ConnectError);
        expect((err as ConnectError).code).toBe(Code.Unavailable);
        expect((err as ConnectError).message, b).toContain(`could not read the bundle at ${WORLD[b].path}`);
      }
    }
  });
  it('waiting: no answer until the state changes', async () => {
    setViewState('waiting');
    const pending = inspect.getSummary({}).then(
      () => 'answered',
      () => 'ended',
    );
    const first = await Promise.race([pending, new Promise((r) => setTimeout(() => r('still waiting'), 60))]);
    expect(first).toBe('still waiting');
    setViewState('loaded');
    expect(await pending).toBe('ended');
  });
});

describe('the empty state answers by itself, never with the loaded bundle (defect 2)', () => {
  const LOADED_PLAN_IDS = Object.values(SAVED).map((x) => x.id);
  const GOALS = [Intention.RENEW_DUE, Intention.ADOPT_KEY, Intention.RETIRE_SUBKEYS, Intention.ADD_CARD, Intention.REPLACE_CARD];
  it('StartPlan answers a goal with the common answer or a refusal, never with a plan of the loaded bundle', async () => {
    setViewState('empty');
    for (const b of BUNDLES) {
      setBundle(b);
      for (const goal of GOALS) {
        for (const answers of [undefined, [{ questionId: 'use', optionIds: ['root'] }]]) {
          const r = await plans.startPlan({ intention: goal, answers });
          const where = `${b} ${Intention[goal]} ${answers ? 'with' : 'without'} answers`;
          expect(LOADED_PLAN_IDS, where).not.toContain(r.plan?.id ?? '');
          expect(JSON.stringify(r, (_k, v) => (typeof v === 'bigint' ? String(v) : v)), where).not.toMatch(/personal-subkey-revoke|20261111T090000Z-(due|root-add)/);
          if (goal === Intention.ADOPT_KEY) expect(r.refusal, where).toBe('');
          else {
            expect(r.plan, where).toBeUndefined();
            expect(r.questions, where).toHaveLength(0);
            expect(r.refusal, where).not.toBe('');
          }
        }
      }
    }
  });
  it('the goals that need a card are refused as the card refusal, in the empty bundle', async () => {
    setViewState('empty');
    for (const b of BUNDLES) {
      setBundle(b);
      for (const goal of [Intention.ADD_CARD, Intention.REPLACE_CARD]) {
        expect((await plans.startPlan({ intention: goal })).refusal, `${b} ${Intention[goal]}`).toBe('This goal needs a card connected to this computer. The demo has none.');
      }
    }
  });
  it('a goal the empty switch does not name fails loudly, as the contract asks', async () => {
    setViewState('empty');
    const err = await plans.startPlan({ intention: Intention.UNSPECIFIED }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ConnectError);
    expect((err as ConnectError).code).toBe(Code.Unimplemented);
    expect((err as ConnectError).message).toMatch(/no recorded answer for this StartPlan request/);
  });
  it('SavePlan of a plan of a loaded bundle is not answered in the empty state; the common adoption plan is', async () => {
    setViewState('empty');
    for (const b of BUNDLES) {
      setBundle(b);
      for (const [other, w] of Object.entries(SAVED)) {
        const err = await plans.savePlan({ planId: w.id, digest: '' }).then(
          () => undefined,
          (e: unknown) => e,
        );
        expect(err, `${other} plan in empty ${b}`).toBeInstanceOf(ConnectError);
        expect((err as ConnectError).code, `${other} plan in empty ${b}`).toBe(Code.Unimplemented);
        expect((err as ConnectError).message).toMatch(/no recorded answer for this SavePlan request/);
      }
      const adopt = await plans.startPlan({ intention: Intention.ADOPT_KEY, answers: [{ questionId: 'use', optionIds: ['root'] }] });
      await expect(plans.savePlan({ planId: adopt.plan?.id ?? '', digest: adopt.plan?.digest ?? '' }), b).resolves.toBeDefined();
    }
  });
  it('the empty goals screen gives the two card goals reasons that fit a bundle with no card', async () => {
    setViewState('empty');
    for (const b of BUNDLES) {
      setBundle(b);
      const goals = (await plans.listIntentions({})).options;
      const add = goals.find((g) => g.intention === Intention.ADD_CARD);
      const replace = goals.find((g) => g.intention === Intention.REPLACE_CARD);
      expect(add?.applicable, b).toBe(false);
      expect(replace?.applicable, b).toBe(false);
      expect(add?.notApplicableReason, b).toBe('No card is registered yet, and the demo has no card to connect.');
      expect(replace?.notApplicableReason, b).toBe('The bundle holds no card yet.');
    }
  });
});

describe('no text points to a control that does not exist (defect 3)', () => {
  it('every goal reason of every bundle, in every state, is free of an instruction to mark or to go to a screen', async () => {
    for (const state of ['loaded', 'empty'] as const) {
      setViewState(state);
      for (const b of BUNDLES) {
        setBundle(b);
        for (const g of (await plans.listIntentions({})).options) {
          expect(g.notApplicableReason, `${state} ${b} ${Intention[g.intention]}`).not.toMatch(/\bMark\b|Cards screen|\bon the [A-Za-z ]+ screen/i);
        }
      }
    }
  });
  it('the replace-card reason reads the same in the three loaded bundles', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const g = (await plans.listIntentions({})).options.find((x) => x.intention === Intention.REPLACE_CARD);
      expect(g?.notApplicableReason, b).toBe('No card in this bundle is lost or retired.');
    }
  });
  it('no fixture holds the dead pointer', () => {
    const HERE = new URL('./', import.meta.url).pathname;
    const walk = (dir: string): string[] =>
      readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : /\.json$/.test(e.name) ? [`${dir}/${e.name}`] : []));
    const hits = walk('fixtures').filter((f) => /Mark one|Cards screen|on the [A-Za-z ]+ screen/.test(readFileSync(join(HERE, f), 'utf8')));
    expect(hits).toEqual([]);
  });
});

describe('the words of the maintainer stay', () => {
  const HERE = new URL('./', import.meta.url).pathname;
  const OLD_WORDS = /folder|ceremony machine|offline machine|\bdaily\b|pending\/|hardware.key sign-in/i;
  function files(dir: string, ext: RegExp): string[] {
    return readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? files(`${dir}/${e.name}`, ext) : ext.test(e.name) ? [`${dir}/${e.name}`] : [],
    );
  }
  it('no fixture or screen uses a word the maintainer replaced', () => {
    const hits: string[] = [];
    for (const f of [...files('fixtures', /\.json$/), ...files('screens', /\.tsx$/), ...files('lib', /\.ts$/), ...files('ui', /\.tsx$/)]) {
      // "sub-folder" is the word the history's own page uses for history/<ceremony>/.
      const text = readFileSync(join(HERE, f), 'utf8').replace(/sub-folder/gi, '');
      const m = OLD_WORDS.exec(text);
      if (m) hits.push(`${f}: ${m[0]}`);
      // A saved plan is history/<ceremony>/plan.json; there is no file called *.plan.
      if (f.startsWith('fixtures/') && /\.plan\b/.test(text)) hits.push(`${f}: .plan`);
    }
    expect(hits).toEqual([]);
  });
  // The words the ten records replaced (0006 rule 5, 0001, 0008, glossary): the history, not the
  // ledger; trust files in trust/<number>/, not products; requests/<name>/, not answers/; and no
  // staff key, certifier, card helper, board card or yearly command (0008, 0003, 0005); and no Unix
  // socket, random port, hardware-key rule, old ADR number or unpublished site page (0010, 0004).
  const OLD_WORDS_OF_THE_RECORDS = /ledger|trust products?|\bproducts\b|\banswers\/|staff|certifier|card helper|board card|yearly (command|intention)|unix socket|random port|hardware.key|ADR[ -]?00|ritueel\.id\/(reference|decisions|tools)\//i;
  it('no fixture, screen, contract or README uses a word the ten records replaced', () => {
    const PROTO = '../../proto/ritueel/local/v1alpha1/';
    const sources = [
      ...[...files('fixtures', /\.json$/), ...files('screens', /\.tsx$/), ...files('lib', /\.ts$/), ...files('ui', /\.tsx$/)].map((f) => join(HERE, f)),
      ...['common.proto', 'inspect_service.proto', 'plan_service.proto'].map((n) => join(HERE, PROTO, n)),
      join(HERE, '../README.md'),
      join(HERE, '../../proto/README.md'),
      join(HERE, 'api/client.ts'),
    ];
    const hits: string[] = [];
    for (const f of sources) {
      const m = OLD_WORDS_OF_THE_RECORDS.exec(readFileSync(f, 'utf8'));
      if (m) hits.push(`${f}: ${m[0]}`);
    }
    expect(hits).toEqual([]);
  });
});

describe('every kind of card has a word', () => {
  it('root, day-to-day, server and rehearsal each read as a card', () => {
    const kinds = Object.values(CardKind).filter((v): v is CardKind => typeof v === 'number' && v !== CardKind.UNSPECIFIED);
    expect(kinds).toHaveLength(4);
    for (const k of kinds) expect(CARD_KIND_WORD[k], CardKind[k]).toMatch(/\bcard$/);
    expect(CARD_KIND_WORD[CardKind.SERVER]).toBe('Server card');
  });
});

describe('the commands in the made-up answers follow docs/reference/cli.md', () => {
  const HERE = new URL('./', import.meta.url).pathname;
  const CLI = readFileSync(join(HERE, '../../docs/reference/cli.md'), 'utf8');
  // What the page proposes and cli.md does not have yet. They are listed for the maintainer
  // (the report of the change that added this test); a command or a flag not here and not in
  // cli.md fails the test.
  const PROPOSED_COMMANDS = ['personal subkey revoke', 'personal primary extend', 'personal primary add', 'personal userid revoke'];
  const PROPOSED_FLAGS = ['--key', '--expires-in'];

  /** The flags the reference lists for every command, in rows that begin with the flag. */
  const GLOBAL_FLAGS = new Set([...CLI.matchAll(/^\| `(--[a-z][a-z-]*)/gm)].map((m) => m[1]));

  /** Every `ritueel ...` code span of the reference, cut at the first word that is not a lower-case command word. */
  const known = new Set<string>();
  for (const m of CLI.matchAll(/`ritueel ([^`]*)`/g)) {
    const words: string[] = [];
    for (const w of m[1].split(' ')) {
      if (!/^[a-z][a-z-]*$/.test(w)) break;
      words.push(w);
    }
    if (words.length > 0) known.add(words.join(' '));
  }

  function commandsOf(v: unknown, out: string[] = []): string[] {
    if (Array.isArray(v)) v.forEach((x) => commandsOf(x, out));
    else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        if (typeof x === 'string' && /Command$/.test(k)) out.push(x);
        else commandsOf(x, out);
      }
    }
    return out;
  }
  function fixtureFiles(dir: string): string[] {
    return readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? fixtureFiles(`${dir}/${e.name}`) : e.name.endsWith('.json') ? [`${dir}/${e.name}`] : []));
  }
  const commands = fixtureFiles('fixtures').flatMap((f) => commandsOf(JSON.parse(readFileSync(join(HERE, f), 'utf8'))).map((c) => ({ f, c })));

  it('has commands to check (an empty walk proves nothing)', () => {
    expect(known.has('run') && known.has('due') && known.has('ca-bundle build') && known.has('card adopt') && known.has('card check')).toBe(true);
    expect(commands.length).toBeGreaterThan(30);
  });
  it('every command is one cli.md has, or a listed proposal', () => {
    const bad: string[] = [];
    for (const { f, c } of commands) {
      const m = /^ritueel (?:--dir \S+ )?(.*)$/.exec(c);
      if (!m) {
        bad.push(`${f}: ${c}`);
        continue;
      }
      const words: string[] = [];
      for (const w of m[1].split(' ')) {
        if (!/^[a-z][a-z-]*$/.test(w)) break;
        words.push(w);
      }
      const name = words.join(' ');
      if (!known.has(name) && !PROPOSED_COMMANDS.includes(name)) bad.push(`${f}: ${name}: ${c}`);
      // A flag must be a flag of the whole reference (its table of flags) or be on a line of the command itself.
      if (PROPOSED_COMMANDS.includes(name)) continue; // every flag of a proposed command is a proposal too
      const own = CLI.split('\n').filter((line) => line.includes(`\`ritueel ${name}`));
      for (const flag of c.match(/--[a-z][a-z-]*/g) ?? []) {
        if (PROPOSED_FLAGS.includes(flag) || GLOBAL_FLAGS.has(flag)) continue;
        if (!own.some((line) => new RegExp(`${flag}(?![a-z-])`).test(line))) bad.push(`${f}: ${flag}: ${c}`);
      }
    }
    expect(bad).toEqual([]);
  });
  it('a command that runs a plan names the bundle, a verifier does not, and due plans without --plan-only', () => {
    for (const { f, c } of commands) {
      if (/^ritueel (--dir \S+ )?run /.test(c)) expect(c, f).toMatch(/^ritueel --dir ~\/ritueel\/[a-z]+ run [^ ]+ --confirm [0-9a-f]{64}$/);
      if (/ (root-list|ssh-ca-keys|crl) verify /.test(c)) expect(c, f).not.toContain('--dir');
      if (/ due( |$)/.test(c)) expect(c, f).not.toContain('--plan-only');
    }
  });
  it('the trust file of the CA is called the CA bundle, and a personal bundle has no root list', async () => {
    for (const { f, c } of commands) expect(c, f).not.toMatch(/ritueel bundle |--bundle\b/);
    setBundle('personal');
    const files = (await inspect.listTrustFiles({})).files;
    expect(files.map((x) => x.path.split('.').pop()).sort()).toEqual(['asc', 'pgp']);
  });
});

describe('where a ceremony runs, and how many signatures a plan makes (record 0005)', () => {
  const HERE = new URL('./', import.meta.url).pathname;
  const readJson = (f: string) => JSON.parse(readFileSync(join(HERE, 'fixtures', f), 'utf8'));
  type PlanJson = { id: string; runPlace: string; signingStore?: string; testRoot?: boolean; signatureCount?: number; touchCount?: number; steps: { ordinal: number; signatureCount?: number; requirements?: string[] }[] };
  const planFiles = ['personal', 'acme', 'globex', 'common']
    .flatMap((b) => readdirSync(join(HERE, 'fixtures', b)).filter((n) => /^plan\.start-plan\.[a-z-]+\.json$/.test(n) && !/not-now|refused|questions/.test(n)).map((n) => `${b}/${n}`));
  const plansOf = planFiles.map((f) => ({ f, plan: readJson(f).plan as PlanJson }));

  it('has plans to check (an empty walk proves nothing)', () => {
    expect(plansOf.map((x) => x.f).sort()).toEqual(['acme/plan.start-plan.renew-due.json', 'common/plan.start-plan.adopt-key.json', 'globex/plan.start-plan.adopt-key.json', 'personal/plan.start-plan.retire-subkeys.json']);
  });
  it('the signatures of a plan are the sum of its steps, and the touches follow the store', () => {
    for (const { f, plan } of plansOf) {
      const sum = plan.steps.reduce((n, st) => n + (st.signatureCount ?? 0), 0);
      expect(plan.signatureCount, f).toBe(sum);
      expect(sum, f).toBeGreaterThan(0);
      if (plan.signingStore === 'STORE_ROOT_CARDS') expect(plan.touchCount, f).toBe(plan.signatureCount);
      if (plan.signingStore === 'STORE_CLOUD_KMS') expect(plan.touchCount ?? 0, f).toBe(0);
      if (plan.signingStore === 'STORE_SOFTWARE_FILE') expect(plan.touchCount, f).toBe(1);
    }
  });
  it('the plan of acme asks for a touch in every step that signs, and for none in a step that does not', () => {
    const plan = readJson('acme/plan.start-plan.renew-due.json').plan as PlanJson;
    for (const st of plan.steps) expect(st.requirements?.includes('REQUIREMENT_TOUCH') ?? false, `step ${st.ordinal}`).toBe((st.signatureCount ?? 0) > 0);
  });
  it('a key file is used in the offline system, a root on cards or in the cloud on the workstation', () => {
    for (const { f, plan } of plansOf) {
      const want = plan.signingStore === 'STORE_SOFTWARE_FILE' && !plan.testRoot ? 'RUN_PLACE_OFFLINE_SYSTEM' : 'RUN_PLACE_WORKSTATION';
      expect(plan.runPlace, f).toBe(want);
      expect(['STORE_SOFTWARE_FILE', 'STORE_ROOT_CARDS', 'STORE_CLOUD_KMS'], f).toContain(plan.signingStore);
    }
  });
  it('the plan as the transport answers it carries the same numbers', async () => {
    setBundle('acme');
    const q = await plans.startPlan({ intention: Intention.RENEW_DUE });
    const p = await plans.startPlan({ intention: Intention.RENEW_DUE, answers: q.questions.map((x) => ({ questionId: x.id, optionIds: x.defaultOptionIds })) });
    expect(p.plan?.signingStore).toBe(Store.ROOT_CARDS);
    expect(p.plan?.signatureCount).toBe(7);
    expect(p.plan?.touchCount).toBe(7);
    expect(p.plan?.cardSerials).toEqual(['00000012']);
  });
  it('every ceremony says where it ran, and acme shows both places', async () => {
    const seen = new Map<DemoBundle, Set<RunPlace>>();
    for (const b of BUNDLES) {
      setBundle(b);
      const list = (await inspect.listCeremonies({})).ceremonies;
      for (const c of list) {
        expect(c.runPlace, `${b} ${c.id}`).not.toBe(RunPlace.UNSPECIFIED);
        seen.set(b, (seen.get(b) ?? new Set()).add(c.runPlace));
      }
    }
    expect([...(seen.get('acme') ?? [])].sort()).toEqual([RunPlace.OFFLINE_SYSTEM, RunPlace.WORKSTATION]);
    // The first record of acme made the roots in the offline system; the later ones ran on the workstation.
    setBundle('acme');
    const acme = (await inspect.listCeremonies({})).ceremonies;
    expect(acme.filter((c) => c.runPlace === RunPlace.OFFLINE_SYSTEM).map((c) => c.id)).toEqual(['20231202T142000Z-init']);
  });
  it('no trust file ends .rpm or .deb (the release pipeline builds the package), and every path is in a numbered set', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      for (const f of (await inspect.listTrustFiles({})).files) {
        expect(f.path, `${b} ${f.name}`).not.toMatch(/\.(rpm|deb)$/);
        expect(f.path, `${b} ${f.name}`).toMatch(/^trust\/[0-9]+\//);
      }
    }
  });
  it('the personal root cards share their pair: row 3 is declared as another bundle, row 4 of card two is occupied by nobody', async () => {
    setBundle('personal');
    const cards = (await inspect.listCards({})).cards.filter((c) => c.kind === CardKind.ROOT);
    expect(cards.map((c) => c.serial)).toEqual(['00000001', '00000002']);
    for (const c of cards) {
      const row3 = c.piv?.rows.find((r) => r.number === 3);
      expect(row3?.slots.length, c.serial).toBe(4);
      for (const sl of row3?.slots ?? []) {
        expect([SlotUse.OTHER_BUNDLE, SlotUse.UNSPECIFIED], `${c.serial} ${sl.id}`).toContain(sl.use);
        expect(sl.publicKeySha256, `${c.serial} ${sl.id}`).toBe('');
        if (sl.use === SlotUse.OTHER_BUNDLE) expect(sl.rootLabel, `${c.serial} ${sl.id}`).toBe('');
      }
      expect(row3?.slots.some((sl) => sl.use === SlotUse.OTHER_BUNDLE), c.serial).toBe(true);
    }
    const row4 = cards[1].piv?.rows.find((r) => r.number === 4);
    expect(row4?.slots.some((sl) => sl.use === SlotUse.UNSPECIFIED && sl.state !== 0 && sl.purpose.includes('no bundle declares')), 'row 4 of 00000002').toBe(true);
    expect(cards[0].piv?.rows.find((r) => r.number === 4)?.slots.every((sl) => sl.purpose === ''), 'row 4 of 00000001').toBe(true);
  });
  it('the finding undeclared-row exists in the personal bundle only', async () => {
    const where: DemoBundle[] = [];
    for (const b of BUNDLES) {
      setBundle(b);
      if ((await inspect.listFindings({})).findings.some((f) => f.id === 'undeclared-row')) where.push(b);
    }
    expect(where).toEqual(['personal']);
  });
});

describe('the dates of the acme bundle follow the pages', () => {
  const HERE = new URL('./', import.meta.url).pathname;
  const read = (name: string) => JSON.parse(readFileSync(join(HERE, 'fixtures/acme', name), 'utf8'));
  /** The date a number of calendar months after a day, the last day of the month if it has none. */
  function plusMonths(day: string, months: number): string {
    const [y, m, d] = day.split('-').map(Number);
    const last = new Date(Date.UTC(y, m - 1 + months + 1, 0)).getUTCDate();
    return new Date(Date.UTC(y, m - 1 + months, Math.min(d, last))).toISOString().slice(0, 10);
  }
  // The newest ceremony that wrote a trust sequence with a root's card is the last time that root signed.
  const ceremonies = read('inspect.list-ceremonies.json').ceremonies as { id: string; cardSerials: string[]; trustSequence?: number }[];
  const lastSigned = (serial: string) => {
    const hit = ceremonies.filter((c) => c.trustSequence !== undefined && c.cardSerials.length === 1 && c.cardSerials[0] === serial).map((c) => c.id.slice(0, 8))[0];
    return `${hit.slice(0, 4)}-${hit.slice(4, 6)}-${hit.slice(6, 8)}`;
  };

  it('a root certificate lives 36 months from the last ceremony that signed with the root', () => {
    for (const r of read('inspect.list-roots.json').roots as { label: string; cardSerials: string[]; keys: { kind: string; expiresAt?: string }[] }[]) {
      const want = plusMonths(lastSigned(r.cardSerials[0]), 36);
      for (const k of r.keys.filter((x) => x.expiresAt)) expect(k.expiresAt!.slice(0, 10), `${r.label} ${k.kind}`).toBe(want);
    }
  });
  it('a CRL stays current 25 months from the ceremony of the root that signed it', () => {
    const files = read('inspect.list-trust-files.json').files as { name: string; validUntil?: string }[];
    const until = (n: string) => files.find((f) => f.name === n)!.validUntil!.slice(0, 10);
    expect(until('crl-A.pem')).toBe(plusMonths(lastSigned('00000011'), 25));
    expect(until('crl-B.pem')).toBe(plusMonths(lastSigned('00000012'), 25));
  });
  it('the CRL of the globex bundle stays current 25 months from the day it was made (record 0006, rule 26)', () => {
    const files = JSON.parse(readFileSync(join(HERE, 'fixtures/globex', 'inspect.list-trust-files.json'), 'utf8')).files as { name: string; kind: string; builtAt: string; validUntil?: string }[];
    const crls = files.filter((f) => f.kind === 'TRUST_FILE_KIND_CRL');
    expect(crls.length).toBeGreaterThan(0);
    for (const f of crls) expect(f.validUntil!.slice(0, 10), f.name).toBe(plusMonths(f.builtAt.slice(0, 10), 25));
  });
});

describe('switching the example bundle keeps the screen', () => {
  // The tests run in Node, which has no window: this is the page's address bar. A fallback must replace the
  // history entry (`replace`, logged in `writes`); assigning the hash would push an entry (logged in `pushes`).
  let bar: string;
  let writes: string[];
  let pushes: string[];
  beforeEach(() => {
    bar = '';
    writes = [];
    pushes = [];
    vi.stubGlobal('window', {
      location: {
        get hash() {
          return bar;
        },
        set hash(v: string) {
          pushes.push(v);
          bar = v.startsWith('#') ? v : `#${v}`;
        },
        replace(v: string) {
          writes.push(v);
          bar = v.startsWith('#') ? v : `#${v}`;
        },
      },
    });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Be on `hash` in bundle `from`, switch to `to`, and say what the address bar shows and whether it was written. */
  function switchFrom(from: DemoBundle, hash: string, to: DemoBundle) {
    setBundle(from);
    bar = hash;
    writes = [];
    pushes = [];
    setBundle(to);
    expect(pushes, `${from} to ${to} on ${hash}: no history entry is pushed`).toEqual([]);
    return { hash: bar, writes: [...writes] };
  }

  /** What the bundle shown now holds, asked of the transport as the screens ask it. Independent of the code under test. */
  async function held() {
    return {
      roots: (await inspect.listRoots({})).roots.map((r) => r.label),
      cards: (await inspect.listCards({})).cards.map((c) => c.serial),
      records: (await inspect.listCeremonies({})).ceremonies.map((c) => c.id),
      goals: (await plans.listIntentions({})).options.filter((o) => o.applicable).map((o) => INTENTION_SLUG[o.intention]),
    };
  }
  /** True if the address names a screen that the bundle shown now can draw: a list, or a detail view of something it holds. */
  async function showable(hash: string): Promise<boolean> {
    const r: Route = parseHash(hash);
    const h = await held();
    switch (r.name) {
      case 'key':
        return h.roots.includes(r.root);
      case 'cards':
        return r.serial === undefined || h.cards.includes(r.serial);
      case 'history':
        return r.id === undefined || h.records.includes(r.id);
      case 'plan':
        return r.goal === undefined || h.goals.includes(r.goal);
      case 'notfound':
        return false;
      default:
        return true;
    }
  }

  const SCREENS = ['#/start', '#/findings', '#/roots', '#/cards', '#/history', '#/trust', '#/plan'];

  it('every screen stays, for every pair of bundles, and the address is not written', () => {
    for (const from of BUNDLES)
      for (const to of BUNDLES)
        for (const screen of SCREENS) {
          const got = switchFrom(from, screen, to);
          expect(got.hash, `${from} to ${to} on ${screen}`).toBe(screen);
          expect(got.writes, `${from} to ${to} on ${screen}`).toEqual([]);
        }
  });
  it('an empty address, a spelling without the slash and a hash that names nothing are left as they are', () => {
    for (const hash of ['', '#', '#/', '#plan', '#/nope', '#/cards/a/b'])
      for (const to of ['acme', 'globex'] as const) {
        const got = switchFrom('personal', hash, to);
        expect(got, `${JSON.stringify(hash)} to ${to}`).toEqual({ hash, writes: [] });
      }
  });
  it('a card falls back to the Cards list when the new bundle has no card with that serial', () => {
    expect(switchFrom('personal', '#/cards/00000001', 'acme')).toEqual({ hash: '#/cards', writes: ['#/cards'] });
    expect(switchFrom('acme', '#/cards/00000011', 'personal')).toEqual({ hash: '#/cards', writes: ['#/cards'] });
    expect(switchFrom('acme', '#/cards/00000012', 'globex')).toEqual({ hash: '#/cards', writes: ['#/cards'] });
    // the demo's bundles share no serial (the pure function covers the case where one is shared)
    for (const [from, serials] of [['personal', ['00000001', '00000006']], ['acme', ['00000011', '00000012']]] as const)
      for (const to of BUNDLES.filter((b) => b !== from))
        for (const sn of serials) expect(switchFrom(from, `#/cards/${sn}`, to).hash, `${from} ${sn} to ${to}`).toBe('#/cards');
  });
  it('a history record falls back to History', () => {
    expect(switchFrom('personal', '#/history/20261103T142000Z-init', 'acme')).toEqual({ hash: '#/history', writes: ['#/history'] });
    expect(switchFrom('acme', '#/history/20231202T142000Z-init', 'globex')).toEqual({ hash: '#/history', writes: ['#/history'] });
    expect(switchFrom('globex', '#/history/20260915T142000Z-init', 'personal')).toEqual({ hash: '#/history', writes: ['#/history'] });
  });
  it('a root stays if the new bundle has a root with that letter, and goes to Roots if not', () => {
    // A is in all three bundles, B only in acme
    for (const from of BUNDLES)
      for (const to of BUNDLES) expect(switchFrom(from, '#/key/A', to), `${from} to ${to}`).toEqual({ hash: '#/key/A', writes: [] });
    expect(switchFrom('acme', '#/key/B', 'personal')).toEqual({ hash: '#/roots', writes: ['#/roots'] });
    expect(switchFrom('acme', '#/key/B', 'globex')).toEqual({ hash: '#/roots', writes: ['#/roots'] });
    expect(switchFrom('acme', '#/key/B', 'acme').hash).toBe('#/key/B');
    // the bare #/key means the root A
    expect(switchFrom('personal', '#/key', 'globex')).toEqual({ hash: '#/key', writes: [] });
  });
  it('the wizard of a goal stays if the new bundle offers the goal, and goes to the goals if not', () => {
    // offered: personal retire-subkeys, acme renew-due, globex adopt-key
    expect(switchFrom('personal', '#/plan/retire-subkeys', 'acme')).toEqual({ hash: '#/plan', writes: ['#/plan'] });
    expect(switchFrom('acme', '#/plan/renew-due', 'personal')).toEqual({ hash: '#/plan', writes: ['#/plan'] });
    expect(switchFrom('acme', '#/plan/renew-due', 'globex')).toEqual({ hash: '#/plan', writes: ['#/plan'] });
    expect(switchFrom('globex', '#/plan/adopt-key', 'acme')).toEqual({ hash: '#/plan', writes: ['#/plan'] });
    // a goal that applies to no bundle, and one this page does not know
    expect(switchFrom('personal', '#/plan/add-card', 'acme').hash).toBe('#/plan');
    expect(switchFrom('personal', '#/plan/no-such-goal', 'globex').hash).toBe('#/plan');
  });
  it('nothing ever ends on an address that the new bundle cannot show', async () => {
    const goals = ['renew-due', 'retire-subkeys', 'adopt-key', 'add-card', 'replace-card', 'no-such-goal'];
    for (const from of BUNDLES) {
      setBundle(from);
      const h = await held();
      const details = [
        ...h.roots.map((r) => `#/key/${r}`),
        ...h.cards.map((c) => `#/cards/${c}`),
        ...h.records.map((r) => `#/history/${r}`),
        ...goals.map((g) => `#/plan/${g}`),
        '#/key/Z',
        '#/cards/99999999',
        '#/history/20000101T000000Z-none',
      ];
      for (const to of BUNDLES.filter((b) => b !== from)) {
        for (const hash of [...SCREENS, ...details]) {
          const got = switchFrom(from, hash, to);
          expect(await showable(got.hash), `${from} ${hash} to ${to} ended on ${got.hash}`).toBe(true);
          // the address is written only when the route had to fall back
          expect(got.writes.length, `${from} ${hash} to ${to}`).toBe(got.hash === hash ? 0 : 1);
        }
      }
    }
  });
  it('in the Failed and Waiting page states the detail views of the loaded bundle stay, the others fall back', () => {
    for (const state of ['failed', 'waiting'] as const) {
      setViewState(state);
      expect(switchFrom('personal', '#/key/A', 'acme'), state).toEqual({ hash: '#/key/A', writes: [] });
      expect(switchFrom('acme', '#/key/B', 'globex'), state).toEqual({ hash: '#/roots', writes: ['#/roots'] });
      expect(switchFrom('personal', '#/cards/00000001', 'acme'), state).toEqual({ hash: '#/cards', writes: ['#/cards'] });
      expect(switchFrom('personal', '#/plan/retire-subkeys', 'acme'), state).toEqual({ hash: '#/plan', writes: ['#/plan'] });
      expect(switchFrom('globex', '#/plan/adopt-key', 'acme'), state).toEqual({ hash: '#/plan', writes: ['#/plan'] });
      expect(switchFrom('personal', '#/history/20261103T142000Z-init', 'acme'), state).toEqual({ hash: '#/history', writes: ['#/history'] });
      expect(switchFrom('personal', '#/trust', 'acme'), state).toEqual({ hash: '#/trust', writes: [] });
    }
  });
  it('before the demo transport has said what a bundle holds, the address is left alone', async () => {
    vi.resetModules();
    const fresh = await import('./api/demoState');
    bar = '#/key/A';
    fresh.setBundle('acme');
    expect({ hash: bar, writes, pushes }).toEqual({ hash: '#/key/A', writes: [], pushes: [] });
    // once it is provided, the same switch falls back where it must
    fresh.provideBundleContents(() => ({ roots: [], cards: [], records: [], goals: [] }));
    fresh.setBundle('globex');
    expect({ hash: bar, writes }).toEqual({ hash: '#/roots', writes: ['#/roots'] });
  });
  it('a fixture that cannot be read keeps the address and still tells the listeners', async () => {
    vi.resetModules();
    const fresh = await import('./api/demoState');
    fresh.provideBundleContents(() => {
      throw new Error('missing fixture');
    });
    let told = 0;
    fresh.subscribeBundle(() => told++);
    bar = '#/key/A';
    fresh.setBundle('acme');
    expect({ hash: bar, writes, told, bundle: fresh.getBundle() }).toEqual({ hash: '#/key/A', writes: [], told: 1, bundle: 'acme' });
  });
  it('in the Empty page state nothing is held, so every detail view falls back and only adopting a key stays', () => {
    setViewState('empty');
    for (const to of BUNDLES.filter((b) => b !== 'personal')) {
      expect(switchFrom('personal', '#/cards/00000001', to).hash).toBe('#/cards');
      expect(switchFrom('personal', '#/key/A', to).hash).toBe('#/roots');
      expect(switchFrom('personal', '#/history/20261103T142000Z-init', to).hash).toBe('#/history');
      expect(switchFrom('personal', '#/plan/renew-due', to).hash).toBe('#/plan');
      expect(switchFrom('personal', '#/plan/adopt-key', to).hash).toBe('#/plan/adopt-key');
      expect(switchFrom('personal', '#/roots', to).hash).toBe('#/roots');
    }
  });
});

// ---- the example texts fit the page's own limits ----------------------------------------------
//
// The page cuts a text from the bundle at a limit and writes "(cut: the text is longer than N
// characters)" (lib/safe.ts). That guard is for text no one wrote for this page. The texts of the
// demo are written for it, so none of them may run into it. The limits are the ones the screens
// use (lib/caps.ts, lib/safe.ts); nothing here copies a number.

const FIXTURE_SCHEMAS: [string, DescMessage][] = [
  ['inspect.get-summary', GetSummaryResponseSchema],
  ['inspect.list-cards', ListCardsResponseSchema],
  ['inspect.list-ceremonies', ListCeremoniesResponseSchema],
  ['inspect.list-findings', ListFindingsResponseSchema],
  ['inspect.list-roots', ListRootsResponseSchema],
  ['inspect.list-trust-files', ListTrustFilesResponseSchema],
  ['plan.list-intentions', ListIntentionsResponseSchema],
  ['plan.save-plan', SavePlanResponseSchema],
  ['plan.start-plan', StartPlanResponseSchema],
];

/** Commands go through Cmd (shown whole and copied only under COMMAND_CAP). */
const COMMAND_FIELDS = new Set([
  'Plan.run_command',
  'Plan.equivalent_command',
  'SavePlanResponse.run_command',
  'Finding.fix_command',
  'TrustFile.verify_command',
  'TrustFile.rebuild_command',
]);

/** The limit of one text: the smallest limit of the places that draw the field. */
function limitOf(key: string): number {
  if (COMMAND_FIELDS.has(key)) return COMMAND_CAP;
  const field = key.split('.')[1] ?? '';
  if (/fingerprint|digest|sha256/.test(field)) return FINGERPRINT_CAP;
  const own = Object.entries(CAPS)
    .filter(([k]) => k.split('#')[0] === key)
    .map(([, n]) => n);
  return own.length > 0 ? Math.min(...own) : DEFAULT_CAP;
}

function* textsOf(d: DescMessage, m: Record<string, unknown>): Generator<[string, string]> {
  for (const f of d.fields) {
    const v = m[f.localName];
    const items = f.fieldKind === 'list' ? (v as unknown[]) : f.fieldKind === 'map' ? [] : [v];
    for (const x of items) {
      if (f.fieldKind === 'message' || (f.fieldKind === 'list' && f.listKind === 'message')) {
        if (x && f.message) yield* textsOf(f.message, x as Record<string, unknown>);
      } else if (typeof x === 'string' && x.length > 0) {
        const key = `${d.name}.${f.name}`;
        // The file excerpt is drawn one line at a time.
        if (key === 'SavePlanResponse.plan_file_preview') for (const line of x.split('\n')) yield [key, line];
        else yield [key, x];
      }
    }
  }
}

function* fieldsOf(d: DescMessage, seen = new Set<string>()): Generator<string> {
  if (seen.has(d.typeName)) return;
  seen.add(d.typeName);
  for (const f of d.fields) {
    yield `${d.name}.${f.name}`;
    if (f.message) yield* fieldsOf(f.message, seen);
  }
}

describe('the example texts fit the limits of the page', () => {
  const dir = join(__dirname, 'fixtures');
  const pathOf = (b: string) => (JSON.parse(readFileSync(join(dir, b, 'inspect.get-summary.json'), 'utf8')) as { bundle: { path: string } }).bundle.path;

  it('no text of any fixture of any bundle is longer than the limit of the place that shows it', () => {
    const tooLong: string[] = [];
    let checked = 0;
    for (const sub of readdirSync(dir)) {
      for (const file of readdirSync(join(dir, sub))) {
        if (file === 'manifest.json') continue;
        const hit = FIXTURE_SCHEMAS.find(([prefix]) => file.startsWith(prefix));
        expect(hit, `${sub}/${file} has a schema in this test`).toBeDefined();
        if (!hit) continue;
        const raw = readFileSync(join(dir, sub, file), 'utf8');
        // The answers in common/ name the open bundle's place: check them with each place put in.
        const variants = sub === 'common' ? BUNDLES.map((b) => raw.split('~/ritueel/example').join(pathOf(b))) : [raw];
        for (const text of variants) {
          const msg = fromJson(hit[1], JSON.parse(text)) as unknown as Record<string, unknown>;
          for (const [key, value] of textsOf(hit[1], msg)) {
            checked += 1;
            const cap = limitOf(key);
            if ([...value].length > cap) tooLong.push(`${sub}/${file} ${key}: ${[...value].length} characters, limit ${cap}, begins "${value.slice(0, 40)}"`);
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(1000);
    expect([...new Set(tooLong)]).toEqual([]);
  });

  it('every limit in the table belongs to a field of the contract', () => {
    const real = new Set<string>();
    for (const [, schema] of FIXTURE_SCHEMAS) for (const k of fieldsOf(schema)) real.add(k);
    const stale = Object.keys(CAPS).filter((k) => !real.has(k.split('#')[0]!));
    expect(stale).toEqual([]);
  });
});
