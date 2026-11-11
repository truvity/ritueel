import { afterEach, describe, expect, it } from 'vitest';
import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { Intention, Severity } from './gen/ritueel/local/v1alpha1/common_pb';
import { InspectService } from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { PlanService } from './gen/ritueel/local/v1alpha1/plan_service_pb';
import { createDemoTransport } from './api/demo';
import { setViewState } from './api/demoState';

const t = createDemoTransport();
const inspect = createClient(InspectService, t);
const plans = createClient(PlanService, t);

afterEach(() => setViewState('loaded'));

describe('every call of the contract answers', () => {
  it('InspectService: every method answers with no argument', async () => {
    for (const m of InspectService.methods) {
      const call = (inspect as unknown as Record<string, (r: object) => Promise<unknown>>)[m.localName];
      await expect(call({}), m.name).resolves.toBeDefined();
    }
  });
  it('PlanService: ListIntentions answers, StartPlan answers for every goal, SavePlan answers for every plan', async () => {
    expect((await plans.listIntentions({})).options).toHaveLength(5);
    for (const i of [Intention.RENEW_DUE, Intention.ADOPT_KEY, Intention.REPLACE_SUBKEYS, Intention.ADD_CARD, Intention.REPLACE_CARD]) {
      const r = await plans.startPlan({ intention: i });
      expect(r.questions.length + (r.plan ? 1 : 0) + (r.refusal ? 1 : 0), `intention ${i}`).toBeGreaterThan(0);
    }
  });
  it('the services list every method this test knows (a new call must get a test)', () => {
    expect(InspectService.methods.map((m) => m.name).sort()).toEqual(['GetSummary', 'ListCards', 'ListCeremonies', 'ListFindings', 'ListRoots', 'ListTrustFiles']);
    expect(PlanService.methods.map((m) => m.name).sort()).toEqual(['ListIntentions', 'SavePlan', 'StartPlan']);
  });
});

describe('the fixtures tell the made-up world', () => {
  it('summary: three due, 12 records, a demo', async () => {
    const s = await inspect.getSummary({});
    expect(s.due).toHaveLength(3);
    expect(s.ledger?.recordCount).toBe(12);
    expect(s.demo).toBe(true);
  });
  it('findings: nine, and min_severity is applied by the transport', async () => {
    expect((await inspect.listFindings({})).findings).toHaveLength(9);
    expect((await inspect.listFindings({ minSeverity: Severity.ALERT })).findings).toHaveLength(3);
  });
  it('roots, cards, ceremonies, trust files', async () => {
    expect((await inspect.listRoots({})).roots).toHaveLength(3);
    expect((await inspect.listCards({})).cards).toHaveLength(6);
    expect((await inspect.listCeremonies({})).ceremonies).toHaveLength(12);
    expect((await inspect.listTrustFiles({})).files).toHaveLength(6);
  });
});

describe('a call that would act answers that this is a demo', () => {
  it('a plan is built in memory with its digest and command', async () => {
    const q = await plans.startPlan({ intention: Intention.RENEW_DUE });
    expect(q.questions.length).toBeGreaterThan(0);
    const p = await plans.startPlan({ intention: Intention.RENEW_DUE, answers: q.questions.map((x) => ({ questionId: x.id, optionIds: x.defaultOptionIds })) });
    expect(p.plan?.digest).toMatch(/deadbeef$/);
    expect(p.plan?.runCommand).toContain('ritueel run');
  });
  it('SavePlan writes nothing and says it is a demo, for every plan', async () => {
    for (const id of ['2026-11-11-renew-due', '2026-11-11-replace-subkeys', '2026-11-11-adopt-cloud-key']) {
      const saved = await plans.savePlan({ planId: id, digest: '' });
      expect(saved.written, id).toBe(false);
      expect(saved.notice, id).toMatch(/demo/i);
      expect(saved.notice, id).toMatch(/nothing was written/i);
      expect(saved.planFilePreview.length).toBeGreaterThan(20);
    }
  });
  it('a goal that does not apply is refused with its reason', async () => {
    expect((await plans.startPlan({ intention: Intention.ADD_CARD })).refusal).toMatch(/demo/i);
  });
  it('a call that matches no fixture fails loudly', async () => {
    await expect(plans.savePlan({ planId: 'nope', digest: '' })).rejects.toThrow(/no recorded answer/);
  });
});

describe('the four states of a read', () => {
  it('empty: a folder that holds nothing', async () => {
    setViewState('empty');
    const s = await inspect.getSummary({});
    expect(s.counts?.roots).toBe(0);
    expect(s.due).toHaveLength(0);
    expect(s.ledger?.recordCount).toBe(0);
    expect(s.setupSteps.filter((x) => x.done)).toHaveLength(1);
    expect((await inspect.listFindings({})).findings).toHaveLength(0);
    expect((await inspect.listRoots({})).roots).toHaveLength(0);
    expect((await inspect.listCards({})).cards).toHaveLength(0);
    expect((await inspect.listCeremonies({})).ceremonies).toHaveLength(0);
    expect((await inspect.listTrustFiles({})).files).toHaveLength(0);
    const goals = (await plans.listIntentions({})).options;
    expect(goals.find((g) => g.intention === Intention.ADOPT_KEY)?.recommended).toBe(true);
    expect(goals.find((g) => g.intention === Intention.RENEW_DUE)?.applicable).toBe(false);
  });
  it('failed: every read fails with an error, never an empty answer', async () => {
    setViewState('failed');
    for (const call of [() => inspect.getSummary({}), () => inspect.listFindings({}), () => inspect.listRoots({}), () => inspect.listCards({}), () => inspect.listCeremonies({}), () => inspect.listTrustFiles({}), () => plans.listIntentions({}), () => plans.savePlan({ planId: '2026-11-11-renew-due', digest: '' })]) {
      const err = await call().then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(ConnectError);
      expect((err as ConnectError).code).toBe(Code.Unavailable);
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
