import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { Intention, Severity } from './gen/ritueel/local/v1alpha1/common_pb';
import { CardKind, InspectService } from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { PlanService, RunPlace } from './gen/ritueel/local/v1alpha1/plan_service_pb';
import { createDemoTransport } from './api/demo';
import { CARD_KIND_WORD } from './lib/words';
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
    // The process serves the one bundle it was started on: no call lists or selects a bundle.
    // The switch of the demo is chrome around the transport, never part of the contract.
    const all = [...InspectService.methods, ...PlanService.methods].map((m) => m.name);
    expect(all.filter((n) => /bundle/i.test(n))).toEqual([]);
  });
});

// What each example bundle holds. One bundle is one trust domain, with its own ledger, roots and cards.
const WORLD: Record<DemoBundle, { name: string; path: string; due: number; records: number; findings: number; alert: number; roots: number; delegated: number; cards: number; ceremonies: number; trustFiles: number }> = {
  personal: { name: 'personal', path: '~/ritueel/personal', due: 0, records: 1, findings: 7, alert: 3, roots: 1, delegated: 0, cards: 6, ceremonies: 1, trustFiles: 2 },
  acme: { name: 'acme', path: '~/ritueel/acme', due: 3, records: 10, findings: 1, alert: 0, roots: 2, delegated: 2, cards: 2, ceremonies: 10, trustFiles: 7 },
  globex: { name: 'globex', path: '~/ritueel/globex', due: 0, records: 1, findings: 1, alert: 0, roots: 1, delegated: 0, cards: 0, ceremonies: 1, trustFiles: 2 },
};

describe('the fixtures tell the made-up world, one bundle at a time', () => {
  it('starts on the personal bundle', () => {
    expect(getBundle()).toBe('personal');
    expect(DEMO_BUNDLES.map((b) => b.value)).toEqual(BUNDLES);
  });
  for (const b of BUNDLES) {
    const w = WORLD[b];
    describe(b, () => {
      it('summary: its name, path, due list, ledger and counts, a demo', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        expect(s.demo).toBe(true);
        expect(s.bundle?.name).toBe(w.name);
        expect(s.bundle?.path).toBe(w.path);
        expect(s.due).toHaveLength(w.due);
        expect(s.ledger?.recordCount).toBe(w.records);
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
      it('the ledger head of the summary is the last record of the ceremonies list', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        const c = await inspect.listCeremonies({});
        expect(c.ledger?.recordCount).toBe(c.ceremonies.length);
        expect(c.ledger?.lastRecordId).toBe(s.ledger?.lastRecordId);
        expect(c.ceremonies.map((x) => x.id)).toContain(s.ledger?.lastRecordId);
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
  acme: { id: '20261111T090000Z-due', place: RunPlace.OFFLINE_SYSTEM, stick: true },
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
    expect(p.plan?.runCommand).toContain(' run ledger/');
    expect(p.plan?.runCommand).toContain('/plan.json --confirm ');
    expect(p.plan?.savePath).toMatch(/^ledger\/[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+\/plan\.json$/);
    expect(p.plan?.runPlace).toBe(RunPlace.OFFLINE_SYSTEM);
  });
  it('every plan says where it runs: the offline system for cards and key files, the workstation for a cloud root', async () => {
    for (const [b, goal, place] of [
      ['personal', Intention.RETIRE_SUBKEYS, RunPlace.OFFLINE_SYSTEM],
      ['acme', Intention.RENEW_DUE, RunPlace.OFFLINE_SYSTEM],
      ['globex', Intention.ADOPT_KEY, RunPlace.WORKSTATION],
    ] as const) {
      setBundle(b);
      const q = await plans.startPlan({ intention: goal });
      const p = await plans.startPlan({ intention: goal, answers: q.questions.map((x) => ({ questionId: x.id, optionIds: x.defaultOptionIds })) });
      expect(p.plan?.runPlace, b).toBe(place);
      // The plan, the saved plan and the id of the bundle agree with each other.
      expect(p.plan?.id, b).toBe(SAVED[b].id);
      expect(p.plan?.savePath, b).toBe(`ledger/${SAVED[b].id}/plan.json`);
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
      expect(saved.path, id).toBe(`ledger/${id}/plan.json`);
      // The run command names the bundle (--dir), as docs/reference/cli.md has it.
      expect(saved.runCommand, id).toBe(`ritueel --dir ~/ritueel/${b} run ledger/${id}/plan.json --confirm ${saved.digest}`);
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
      expect(s.ledger?.recordCount, b).toBe(0);
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
      expect(saved.path, b).toBe(`ledger/${adopt.plan?.id}/plan.json`);
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

describe('the words of the owner stay', () => {
  const HERE = new URL('./', import.meta.url).pathname;
  const OLD_WORDS = /folder|ceremony machine|offline machine|\bdaily\b|pending\/|hardware.key sign-in/i;
  function files(dir: string, ext: RegExp): string[] {
    return readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? files(`${dir}/${e.name}`, ext) : ext.test(e.name) ? [`${dir}/${e.name}`] : [],
    );
  }
  it('no fixture or screen uses a word the owner replaced', () => {
    const hits: string[] = [];
    for (const f of [...files('fixtures', /\.json$/), ...files('screens', /\.tsx$/), ...files('lib', /\.ts$/), ...files('ui', /\.tsx$/)]) {
      // "sub-folder" is the word the ledger's own page uses for ledger/<ceremony>/.
      const text = readFileSync(join(HERE, f), 'utf8').replace(/sub-folder/gi, '');
      const m = OLD_WORDS.exec(text);
      if (m) hits.push(`${f}: ${m[0]}`);
      // A saved plan is ledger/<ceremony>/plan.json; there is no file called *.plan.
      if (f.startsWith('fixtures/') && /\.plan\b/.test(text)) hits.push(`${f}: .plan`);
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
      for (const flag of c.match(/--[a-z][a-z-]*/g) ?? []) {
        if (PROPOSED_FLAGS.includes(flag)) continue;
        if (!new RegExp(`${flag}(?![a-z-])`).test(CLI)) bad.push(`${f}: ${flag}: ${c}`);
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
