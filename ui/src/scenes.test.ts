import { afterEach, describe, expect, it } from 'vitest';
import { createClient } from '@connectrpc/connect';
import { fromJson, type DescMessage } from '@bufbuild/protobuf';
import { timestampDate } from '@bufbuild/protobuf/wkt';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ObjectKind, Severity } from './gen/ritueel/local/v1alpha1/common_pb';
import {
  CeremonyState,
  ChangeKind,
  ChangeState,
  CertificationKind,
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  InspectService,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { createDemoTransport } from './api/demo';
import { applySceneNumber, SCENE_COUNT, SCENES, sceneLine, sceneReadAt } from './api/scenes';
import { setBundle, setScene, setViewState } from './api/demoState';
import { SceneSwitch } from './ui/SceneSwitch';
import { baseJson, loadWorld, plain } from './testkit';

// The five scenes of acme: one change seen at five moments. A scene is the base files plus its
// own patches. The checks follow the plan: what each patch may name, what each scene adds, and
// that the numbers of the summary agree with the lists in every scene.

const CALLS = ['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles'] as const;
const SCHEMA: Record<(typeof CALLS)[number], DescMessage> = {
  GetSummary: GetSummaryResponseSchema,
  ListFindings: ListFindingsResponseSchema,
  GetInventory: GetInventoryResponseSchema,
  ListCeremonies: ListCeremoniesResponseSchema,
  ListTrustFiles: ListTrustFilesResponseSchema,
};
const NEW = '20261124T100400Z-apply-7d41e9b3';
const day = (ts: Parameters<typeof timestampDate>[0] | undefined) => (ts ? timestampDate(ts).toISOString() : '');

afterEach(() => {
  setViewState('loaded');
  setBundle('acme');
  setScene(1);
});

describe('scenes.json', () => {
  it('has five scenes numbered 1 to 5, each with a line of at most 120 characters and a time of read', () => {
    expect(SCENE_COUNT).toBe(5);
    expect(SCENES.map((s) => s.scene)).toEqual([1, 2, 3, 4, 5]);
    for (const s of SCENES) {
      expect(s.line.length, `scene ${s.scene}`).toBeGreaterThan(10);
      expect(s.line.length, `scene ${s.scene}`).toBeLessThanOrEqual(120);
      expect(Number.isNaN(Date.parse(s.readAt)), `scene ${s.scene} readAt`).toBe(false);
    }
    expect(SCENES[0].patches, 'scene 1 is the base files').toEqual([]);
    expect(SCENES.slice(1).every((s) => s.patches.length > 0)).toBe(true);
    // The times run forward within the day of the demo.
    expect(SCENES.map((s) => s.readAt)).toEqual(['2026-11-24T09:00:00Z', '2026-11-24T09:40:00Z', '2026-11-24T10:05:00Z', '2026-11-24T10:30:00Z', '2026-11-24T11:10:00Z']);
    expect(sceneLine(3)).toBe(SCENES[2].line);
    expect(sceneReadAt(4)).toBe('2026-11-24T10:30:00Z');
  });
  it('says what was done outside the page in plain words, and names no digest', () => {
    for (const s of SCENES) {
      expect(s.line, `scene ${s.scene}`).not.toMatch(/[0-9a-f]{16}/);
      expect(s.line, `scene ${s.scene}`).not.toMatch(/\b(click|press|button)\b/i);
    }
  });
});

describe('a patch names only what the base answer has', () => {
  it('every patch names a call and fields of that call, and every list is a list field of the answer', () => {
    for (const s of SCENES)
      for (const p of s.patches) {
        const schema = SCHEMA[p.call as (typeof CALLS)[number]];
        expect(schema, `scene ${s.scene}: ${p.call}`).toBeDefined();
        for (const name of Object.keys(p.set ?? {})) {
          const f = schema.fields.find((x) => x.jsonName === name);
          expect(f, `scene ${s.scene}: ${p.call} has ${name}`).toBeDefined();
          expect(f?.fieldKind, `scene ${s.scene}: ${name} is not a list`).not.toBe('list');
          expect(name, 'readAt is the time of the scene').not.toBe('readAt');
        }
        for (const [name, op] of Object.entries(p.lists ?? {})) {
          const f = schema.fields.find((x) => x.jsonName === name);
          expect(f?.fieldKind, `scene ${s.scene}: ${p.call} has the list ${name}`).toBe('list');
          expect(Object.keys(op).filter((k) => ['replace', 'prepend', 'append'].includes(k)), `scene ${s.scene}: ${name}`).toHaveLength(1);
        }
      }
  });
  it('a scene that does not exist, or a call that is not one, is an error', () => {
    const base = baseJson('acme', 'GetSummary');
    expect(() => applySceneNumber(0, 'GetSummary', base)).toThrow(/scene 0/);
    expect(() => applySceneNumber(6, 'GetSummary', base)).toThrow(/scene 6/);
    expect(() => applySceneNumber(2, 'SavePlan', base)).toThrow(/not a call/);
  });
  it('applying a scene copies: the base answer is never changed', () => {
    for (const call of CALLS) {
      const before = JSON.stringify(baseJson('acme', call));
      for (let n = 1; n <= 5; n++) applySceneNumber(n, call, baseJson('acme', call));
      expect(JSON.stringify(baseJson('acme', call)), call).toBe(before);
    }
  });
  it('every answer of every scene parses with the generated schema and carries the time of the scene', () => {
    for (let n = 1; n <= 5; n++)
      for (const call of CALLS) {
        const json = applySceneNumber(n, call, baseJson('acme', call));
        const msg = fromJson(SCHEMA[call], json) as unknown as { readAt?: Parameters<typeof timestampDate>[0] };
        expect(day(msg.readAt), `scene ${n} ${call}`).toBe(new Date(sceneReadAt(n)).toISOString());
      }
  });
});

describe('the numbers of the summary agree with the lists in every scene', () => {
  for (let n = 1; n <= 5; n++) {
    it(`scene ${n}`, () => {
      const w = loadWorld('acme', n);
      const count = (state: ChangeState) => w.inventory.changes.filter((c) => c.state === state).length;
      expect(w.summary.changes?.ready ?? 0).toBe(count(ChangeState.READY));
      expect(w.summary.changes?.waits ?? 0).toBe(count(ChangeState.WAITS));
      for (const sev of [Severity.NOTICE, Severity.ALERT, Severity.CRITICAL])
        expect(w.summary.findingCounts.find((c) => c.severity === sev)?.count ?? 0, `severity ${sev}`).toBe(w.findings.findings.filter((f) => f.severity === sev).length);
      expect(w.summary.ceremoniesWithoutRecord).toBe(w.ceremonies.ceremonies.filter((c) => c.state === CeremonyState.PLANNED || c.state === CeremonyState.STARTED).length);
      expect(w.summary.trustSequence).toBe(w.trust.trustSequence);
      expect(w.summary.history?.recordCount).toBe(w.ceremonies.ceremonies.filter((c) => c.recordSha256 !== '').length);
      expect(w.summary.history?.endRecordSha256).toBe(w.ceremonies.ceremonies.find((c) => c.state === CeremonyState.RECORDED)?.recordSha256);
      expect(w.summary.applyCommand === '', 'an empty apply command means no change is ready').toBe((w.summary.changes?.ready ?? 0) === 0);
    });
  }
  it('scene 2: three changes are ready and one waits; scene 3: three plans have no record; scene 4: one critical finding and one notice; scene 5: set 14, 15 records, one change waits', () => {
    const w = (n: number) => loadWorld('acme', n);
    expect([w(2).summary.changes?.ready, w(2).summary.changes?.waits]).toEqual([3, 1]);
    expect(w(3).summary.ceremoniesWithoutRecord).toBe(3);
    const counts = (n: number) => Object.fromEntries(w(n).summary.findingCounts.map((c) => [Severity[c.severity], c.count]));
    expect(counts(4)).toEqual({ CRITICAL: 1, NOTICE: 1 });
    expect(w(5).summary.trustSequence).toBe(14);
    expect(w(5).summary.history?.recordCount).toBe(15);
    expect([w(5).summary.changes?.ready ?? 0, w(5).summary.changes?.waits]).toEqual([0, 1]);
  });
});

describe('the new ceremony, in the scenes 3 to 5', () => {
  const find = (n: number) => loadWorld('acme', n).ceremonies.ceremonies.find((c) => c.id === NEW);
  it('does not exist in scenes 1 and 2', () => {
    expect(find(1)).toBeUndefined();
    expect(find(2)).toBeUndefined();
  });
  it('is planned in scene 3, started in scene 4 with a close command, and recorded in scene 5 with a publish command', () => {
    const planned = find(3)!;
    expect(planned.state).toBe(CeremonyState.PLANNED);
    expect(planned.stale, 'a plan just made is not stale').toBe(false);
    expect(planned.recordSha256).toBe('');
    const started = find(4)!;
    expect(started.state).toBe(CeremonyState.STARTED);
    expect(started.closeCommand).toBe(`ritueel close ${NEW} --reason TEXT`);
    expect(started.recordSha256).toBe('');
    const recorded = find(5)!;
    expect(recorded.state).toBe(CeremonyState.RECORDED);
    expect(recorded.publishCommand).toBe('ritueel publish');
    expect(recorded.recordSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(recorded.trustSetName).toBe('14-7d41e9b3');
  });
  it('applies three certifications and leaves out the renewal of acme-release, with a reason', () => {
    for (const n of [3, 4, 5]) {
      const c = find(n)!;
      expect(c.applied.map((a) => a.kind), `scene ${n}`).toEqual([ChangeKind.CERTIFY, ChangeKind.CERTIFY, ChangeKind.CERTIFY]);
      expect(c.leftOut, `scene ${n}`).toHaveLength(1);
      expect(c.leftOut[0].object?.id).toBe('acme-release');
      expect(c.leftOut[0].kind).toBe(ChangeKind.RENEW);
      expect(c.leftOut[0].reason.length).toBeGreaterThan(10);
      expect(c.planSha256).toBe('7d41e9b3'.repeat(8));
    }
  });
  it('in scene 5 the chain is longer by one and the new record names the one before', () => {
    const list = loadWorld('acme', 5).ceremonies.ceremonies;
    expect(list[0].id).toBe(NEW);
    expect(list[0].prevRecordSha256).toBe(list[1].recordSha256);
    expect(loadWorld('acme', 5).summary.history?.endRecordSha256).toBe(list[0].recordSha256);
  });
});

describe('the user IDs and the certifications', () => {
  it('a user ID is added in scene 2 and stays; in scene 5 it is certified and three new certifications exist', () => {
    const base = loadWorld('acme', 1).inventory;
    for (const n of [2, 3, 4, 5]) expect(loadWorld('acme', n).inventory.userIds.length, `scene ${n}`).toBe(base.userIds.length + 3);
    const s5 = loadWorld('acme', 5).inventory;
    const added = s5.userIds.filter((u) => !base.userIds.some((b) => b.id === u.id));
    expect(added).toHaveLength(3);
    for (const u of added) expect(u.certified, u.id).toBe(true);
    const fresh = s5.certifications.filter((c) => !base.certifications.some((b) => b.id === c.id));
    expect(fresh).toHaveLength(3);
    for (const c of fresh) {
      expect(c.kind, c.id).toBe(CertificationKind.PRIMARY_SELF_SIGNATURE);
      expect(c.subject?.kind, c.id).toBe(ObjectKind.USER_ID);
      expect(added.map((u) => u.id), c.id).toContain(c.subject?.id);
      expect(c.ceremonyId, c.id).toBe(NEW);
    }
    // Before the ceremony ended, the user IDs were not certified.
    for (const n of [2, 3, 4]) for (const u of loadWorld('acme', n).inventory.userIds.filter((x) => added.some((a) => a.id === x.id))) expect(u.certified, `scene ${n} ${u.id}`).toBe(false);
  });
  it('the keys of scene 5 are the base keys, and only touchedBy differs (a patch replaces the whole list, so it must not drift)', () => {
    const strip = (keys: { toJson?: unknown }[]) => JSON.parse(JSON.stringify(keys, (k, v) => (k === 'touchedBy' ? undefined : typeof v === 'bigint' ? v.toString() : v)));
    const base = loadWorld('acme', 1).inventory.keys;
    const s5 = loadWorld('acme', 5).inventory.keys;
    expect(strip(s5 as never)).toEqual(strip(base as never));
    const touched = s5.filter((k) => k.touchedBy.some((t) => t.id === NEW));
    expect(touched).toHaveLength(3);
    expect(touched.every((k) => k.kind === 2 /* OPENPGP */ && k.role === 1 /* ROOT_KEY */)).toBe(true);
  });
  it('the changes follow the moment: three certify changes in the plan in scenes 3 and 4, none in scene 5', () => {
    for (const n of [3, 4]) {
      const inCeremony = loadWorld('acme', n).inventory.changes.filter((c) => c.inCeremony === NEW);
      expect(inCeremony, `scene ${n}`).toHaveLength(3);
      expect(inCeremony.every((c) => c.kind === ChangeKind.CERTIFY), `scene ${n}`).toBe(true);
    }
    expect(loadWorld('acme', 5).inventory.changes.map((c) => c.object?.id)).toEqual(['acme-release']);
  });
  it('the commands of the scenes are the ones the plan gives', () => {
    expect(loadWorld('acme', 2).summary.applyCommand).toBe('ritueel apply --allow-missing acme-release');
    expect(loadWorld('acme', 3).summary.applyCommand).toBe('ritueel apply --allow-missing acme-release');
    expect(loadWorld('acme', 5).summary.applyCommand).toBe('');
    expect(loadWorld('acme', 4).findings.findings.find((f) => f.id === 'f-2')?.fixCommand).toBe(`ritueel close ${NEW} --reason TEXT`);
  });
});

describe('the control', () => {
  const inspect = createClient(InspectService, createDemoTransport());
  it('setScene(n) for 1 to 5 changes the answer of the transport, and 6 and 0 are refused', async () => {
    const seen: (string | undefined)[] = [];
    for (let n = 1; n <= 5; n++) {
      expect(setScene(n)).toBe(true);
      seen.push(day((await inspect.getSummary({})).readAt));
    }
    expect(seen).toEqual(SCENES.map((s) => new Date(s.readAt).toISOString()));
    expect(setScene(6)).toBe(false);
    expect(setScene(0)).toBe(false);
    expect(day((await inspect.getSummary({})).readAt)).toBe(new Date(SCENES[4].readAt).toISOString());
  });
  it('the live line reads "Scene N of 5: <line>" for acme in the loaded state', () => {
    for (let n = 1; n <= 5; n++) {
      setScene(n);
      const html = renderToStaticMarkup(createElement(SceneSwitch));
      expect(html).toContain('data-testid="scene-line"');
      expect(html).toContain('role="status"');
      expect(plain(html)).toContain(`Scene ${n} of 5: ${sceneLine(n).replace(/'/g, "'")}`.replace(/\s+/g, ' '));
      for (let k = 1; k <= 5; k++) expect(html, `button ${k}`).toContain(`aria-label="Scene ${k} of 5"`);
    }
  });
  it('is not drawn for globex and personal, nor in the Empty, Failed and Waiting states', () => {
    for (const b of ['globex', 'personal'] as const) {
      setBundle(b);
      expect(renderToStaticMarkup(createElement(SceneSwitch)), b).toBe('');
    }
    setBundle('acme');
    for (const state of ['empty', 'failed', 'waiting'] as const) {
      setViewState(state);
      expect(renderToStaticMarkup(createElement(SceneSwitch)), state).toBe('');
    }
  });
});

describe('a started ceremony and a recorded one differ in what the page can offer', () => {
  it('only the started one has a close command, only the recorded one a publish command', () => {
    for (let n = 1; n <= 5; n++)
      for (const c of loadWorld('acme', n).ceremonies.ceremonies) {
        if (c.closeCommand) expect(c.state, `${c.id}`).toBe(CeremonyState.STARTED);
        if (c.publishCommand) expect(c.state, `${c.id}`).toBe(CeremonyState.RECORDED);
      }
  });
});
