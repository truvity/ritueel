import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { fromJson, type DescMessage } from '@bufbuild/protobuf';
import { timestampDate } from '@bufbuild/protobuf/wkt';
import { CeremonyCommand, ChainState, ObjectKind, RunPlace, Severity, Store } from './gen/ritueel/local/v1alpha1/common_pb';
import * as inspectPb from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import * as commonPb from './gen/ritueel/local/v1alpha1/common_pb';
import {
  CardKind,
  CeremonyOutcome,
  CeremonyState,
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  InspectService,
  KeyKind,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
  SlotUse,
  TrustFileKind,
  type GetInventoryResponse,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { createDemoTransport } from './api/demo';
import { applySceneNumber } from './api/scenes';
import { CARD_KIND_WORD } from './lib/words';
import { CAPS } from './lib/caps';
import { COMMAND_CAP, DEFAULT_CAP, FINGERPRINT_CAP } from './lib/safe';
import { parseHash, type ObjectSlug, type Route } from './lib/route';
import { DEMO_BUNDLES, getBundle, getScene, setBundle, setScene, setViewState, type DemoBundle } from './api/demoState';
import { baseJson, loadWorld, WORLDS, type World } from './testkit';

// The made-up world of the demo, checked from outside: the transport answers as the
// contract says, the numbers of the summary agree with the lists, the example company
// is the one of docs/reference/bundle.md, and the dates and commands follow the records.

const inspect = createClient(InspectService, createDemoTransport());
const BUNDLES: DemoBundle[] = ['acme', 'globex', 'personal'];
const HERE = new URL('./', import.meta.url).pathname;
const read = (path: string) => readFileSync(join(HERE, path), 'utf8');

afterEach(() => {
  setViewState('loaded');
  setBundle('acme');
  setScene(1);
});

const day = (ts: Parameters<typeof timestampDate>[0] | undefined) => (ts ? timestampDate(ts).toISOString().slice(0, 10) : '');
const daysApart = (a: string, b: string) => Math.round((Date.parse(b) - Date.parse(a)) / 86_400_000);
const monthsApart = (a: string, b: string) => (Number(b.slice(0, 4)) - Number(a.slice(0, 4))) * 12 + Number(b.slice(5, 7)) - Number(a.slice(5, 7));

/** All five answers of the bundle shown now, as the page reads them. */
async function world(): Promise<World> {
  return {
    id: getBundle(),
    bundle: getBundle(),
    scene: getScene(),
    summary: await inspect.getSummary({}),
    findings: await inspect.listFindings({}),
    inventory: await inspect.getInventory({}),
    ceremonies: await inspect.listCeremonies({}),
    trust: await inspect.listTrustFiles({}),
  };
}

describe('every call of the contract answers', () => {
  it('the five methods answer in the loaded and in the empty page state, for each bundle', async () => {
    for (const b of BUNDLES)
      for (const state of ['loaded', 'empty'] as const) {
        setBundle(b);
        setViewState(state);
        for (const m of InspectService.methods) {
          const call = (inspect as unknown as Record<string, (r: object) => Promise<unknown>>)[m.localName];
          await expect(call({}), `${b} ${state} ${m.name}`).resolves.toBeDefined();
        }
      }
  });
  it('the list of methods is the one this test knows (a new call must get a test)', () => {
    expect(InspectService.methods.map((m) => m.name)).toEqual(['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles']);
    // No call lists or selects a bundle: the switch of the demo is chrome around the transport.
    expect(InspectService.methods.filter((m) => /bundle|plan|scene/i.test(m.name))).toEqual([]);
  });
});

describe('the demo starts on acme, scene 1', () => {
  it('starts on acme, in scene 1, and the bundles come in this order', () => {
    expect(getBundle()).toBe('acme');
    expect(getScene()).toBe(1);
    expect(DEMO_BUNDLES.map((b) => b.value)).toEqual(['acme', 'globex', 'personal']);
  });
});

const WORLD: Record<DemoBundle, { kind: number; records: number; trust: number }> = {
  acme: { kind: 1, records: 14, trust: 13 },
  globex: { kind: 1, records: 2, trust: 2 },
  personal: { kind: 2, records: 3, trust: 3 },
};

describe('the fixtures tell the made-up world, one bundle at a time', () => {
  for (const b of BUNDLES) {
    describe(b, () => {
      it('the summary names the bundle, its path and kind, the fixed read time, and says it is a demo', async () => {
        setBundle(b);
        const s = await inspect.getSummary({});
        expect(s.demo).toBe(true);
        expect(s.bundle?.name).toBe(b);
        expect(s.bundle?.path).toBe(`~/ritueel/${b}`);
        expect(s.bundle?.kind).toBe(WORLD[b].kind);
        expect(timestampDate(s.readAt!).toISOString()).toBe('2026-11-24T09:00:00.000Z');
        expect(s.history?.recordCount).toBe(WORLD[b].records);
        expect(s.trustSequence).toBe(WORLD[b].trust);
      });
      it('the numbers of the summary agree with the lists', async () => {
        setBundle(b);
        const w = await world();
        const count = (state: inspectPb.ChangeState) => w.inventory.changes.filter((c) => c.state === state).length;
        expect(w.summary.changes?.ready ?? 0).toBe(count(inspectPb.ChangeState.READY));
        expect(w.summary.changes?.waits ?? 0).toBe(count(inspectPb.ChangeState.WAITS));
        for (const sev of [Severity.NOTICE, Severity.ALERT, Severity.CRITICAL])
          expect(w.summary.findingCounts.find((c) => c.severity === sev)?.count ?? 0, `severity ${sev}`).toBe(w.findings.findings.filter((f) => f.severity === sev).length);
        expect(w.summary.ceremoniesWithoutRecord).toBe(w.ceremonies.ceremonies.filter((c) => c.state === CeremonyState.PLANNED || c.state === CeremonyState.STARTED).length);
        expect(w.summary.trustSequence).toBe(w.trust.trustSequence);
        expect(w.trust.setName).toMatch(new RegExp(`^${w.trust.trustSequence}-[0-9a-f]{8}$`));
        const recorded = w.ceremonies.ceremonies.filter((c) => c.recordSha256 !== '');
        expect(w.summary.history?.recordCount).toBe(recorded.length);
        expect(w.ceremonies.history?.recordCount).toBe(recorded.length);
        const newest = w.ceremonies.ceremonies.find((c) => c.state === CeremonyState.RECORDED);
        expect(w.summary.history?.endRecordSha256).toBe(newest?.recordSha256);
        expect(w.summary.history?.lastRecordId).toBe(newest?.id);
        expect(w.summary.applyCommand === '', 'an empty apply command means no change is ready').toBe((w.summary.changes?.ready ?? 0) === 0);
      });
    });
  }

  it('the history is a chain: each record names the digest of the one before', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const recorded = (await inspect.listCeremonies({})).ceremonies.filter((c) => c.recordSha256 !== '').reverse(); // oldest first
      expect(recorded.length, b).toBeGreaterThan(0);
      expect(recorded[0].prevRecordSha256, `${b}: the first record has none`).toBe('');
      for (let i = 1; i < recorded.length; i++) expect(recorded[i].prevRecordSha256, `${b} record ${i}`).toBe(recorded[i - 1].recordSha256);
      const named = new Set(recorded.map((c) => c.prevRecordSha256).filter(Boolean));
      expect(recorded.filter((c) => !named.has(c.recordSha256)), `${b}: one record is the end`).toHaveLength(1);
    }
  });

  it('a ceremony has an id of the shape TIME-apply-8hex or TIME-close-8hex, and a plan carries its eight characters', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      for (const c of (await inspect.listCeremonies({})).ceremonies) {
        const m = /^(\d{8})T\d{6}Z-(apply|close)-([0-9a-f]{8})$/.exec(c.id);
        expect(m, `${b} ${c.id}`).not.toBeNull();
        expect(c.command === CeremonyCommand.APPLY ? 'apply' : 'close', c.id).toBe(m![2]);
        if (c.planSha256) {
          expect(c.planSha256, c.id).toBe(m![3].repeat(8));
          if (c.trustSetName) expect(c.trustSetName, c.id).toBe(`${c.trustSequence}-${m![3]}`);
        }
        expect(day(c.plannedAt).replaceAll('-', ''), `${c.id}: the time of the id is the day of the plan`).toBe(m![1]);
      }
    }
  });

  it('the four ceremony states are consistent', async () => {
    const seen = new Set<CeremonyState>();
    for (const b of BUNDLES) {
      setBundle(b);
      for (let scene = 1; scene <= (b === 'acme' ? 5 : 1); scene++) {
        setScene(scene);
        const list = (await inspect.listCeremonies({})).ceremonies;
        for (const c of list) {
          seen.add(c.state);
          const where = `${b} scene ${scene} ${c.id}`;
          if (c.state === CeremonyState.PLANNED) expect(c.recordSha256, where).toBe('');
          if (c.state === CeremonyState.STARTED) {
            expect(c.startedAt, where).toBeDefined();
            expect(c.recordSha256, where).toBe('');
          }
          if (c.state === CeremonyState.RECORDED) {
            expect(c.recordSha256, where).not.toBe('');
            expect([CeremonyOutcome.COMPLETED, CeremonyOutcome.DECLINED, CeremonyOutcome.CLOSED], where).toContain(c.outcome);
            if (c.command === CeremonyCommand.CLOSE) expect(c.outcome, where).toBe(CeremonyOutcome.CLOSED);
          }
          if (c.state === CeremonyState.CLOSED) {
            const by = list.find((x) => x.id === c.closedBy);
            expect(by, `${where}: closed_by names a ceremony of the list`).toBeDefined();
            expect(by?.closes, where).toBe(c.id);
          }
          if (c.stale) expect(c.state, `${where}: only a plan is stale`).toBe(CeremonyState.PLANNED);
        }
      }
    }
    expect([...seen].sort()).toEqual([CeremonyState.PLANNED, CeremonyState.STARTED, CeremonyState.RECORDED, CeremonyState.CLOSED].sort());
  });

  it('acme copies docs/reference/bundle.md', async () => {
    setBundle('acme');
    const w = await world();
    const inv = w.inventory;
    expect(inv.roots.map((r) => r.name).sort()).toEqual(['acme-release', 'acme-ssh', 'acme-tls']);
    expect(inv.cards.map((c) => c.name).sort()).toEqual(['day-ana', 'root-a', 'root-b']);
    expect(inv.delegations.map((d) => d.name).sort()).toEqual(['acme-ca', 'acme-release']);
    expect(inv.requests.map((r) => r.stem)).toContain('acme-ca-2027');
    expect(w.ceremonies.ceremonies.map((c) => c.id)).toContain('20261120T100000Z-apply-3fa9c1d2');
    expect(w.trust.setName).toBe('13-3fa9c1d2');
    const bundle = read('../../docs/reference/bundle.md');
    for (const name of ['root-a', 'root-b', 'day-ana', 'acme-tls', 'acme-release', 'acme-ssh', 'acme-ca', 'acme-ca-2027', '13-3fa9c1d2', '20261120T100000Z-apply-3fa9c1d2']) expect(bundle, name).toContain(name);
    const keyA = inv.keys.find((k) => k.root === 'acme-release' && k.label === 'A');
    const uid = inv.userIds.find((u) => u.key === keyA?.fingerprint);
    expect(uid?.text).toBe('Example Release Root A <release@example.com>');
  });

  it('the shape of acme: three roots of three kinds with keys A, B and C, placed as the page says', async () => {
    setBundle('acme');
    const { inventory: inv } = await world();
    expect(inv.roots.map((r) => r.kind).sort()).toEqual([KeyKind.X509, KeyKind.OPENPGP, KeyKind.SSH_CA]);
    for (const r of inv.roots) {
      const keys = inv.keys.filter((k) => k.root === r.name && k.role === inspectPb.KeyRole.ROOT_KEY);
      expect(keys.map((k) => k.label).sort(), r.name).toEqual(['A', 'B', 'C']);
      const place = (label: string) => keys.find((k) => k.label === label)?.place;
      expect(place('A')?.card, r.name).toBe('root-a');
      expect(place('B')?.card, r.name).toBe('root-b');
      expect(place('C')?.store, r.name).toBe(Store.AWS_KMS);
      expect(place('C')?.replicaRegion, `${r.name}: the cloud key has a replica Region`).not.toBe('');
    }
    // Slots 82, 83 and 84 of the second row of each root card hold the keys of the three roots.
    for (const card of ['root-a', 'root-b']) {
      const c = inv.cards.find((x) => x.name === card)!;
      const slots = c.piv?.rows.flatMap((row) => row.slots) ?? [];
      for (const id of ['82', '83', '84']) {
        const slot = slots.find((s) => s.id === id);
        expect(slot, `${card} slot ${id}`).toBeDefined();
        expect(slot?.state, `${card} slot ${id}`).toBe(inspectPb.SlotState.USED);
      }
      for (const [id, use] of [['82', SlotUse.X509_ROOT], ['84', SlotUse.SSH_CA]] as const) {
        const slot = slots.find((s) => s.id === id)!;
        expect(slot.use, `${card} slot ${id}`).toBe(use);
        const key = inv.keys.find((k) => k.place?.card === card && k.place.slot === id);
        expect(slot.publicKeySha256, `${card} slot ${id}: the digest is the fingerprint of the key`).toBe(key?.fingerprint);
      }
    }
    const kms = inv.keys.filter((k) => k.role === inspectPb.KeyRole.DELEGATED_KEY);
    expect(kms).toHaveLength(2);
    for (const k of kms) expect(k.place?.store, k.delegation).toBe(Store.AWS_KMS);
    expect(kms.find((k) => k.delegation === 'acme-release')?.place?.keyRef).toContain('111122223333');
    expect(kms.find((k) => k.delegation === 'acme-ca')?.place?.keyRef).toContain('444455556666');
    expect(inv.keys.filter((k) => k.place?.card === 'day-ana'), 'no key on day-ana').toEqual([]);
    for (const k of inv.keys) {
      if (k.kind === KeyKind.SSH_CA) expect(k.expiresAt, `${k.root} ${k.label}: an SSH CA key has no expiry`).toBeUndefined();
      else expect(k.expiresAt, `${k.root} ${k.label}`).toBeDefined();
    }
    // No account number outside the three the page uses.
    const all = (['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles'] as const).map((c) => JSON.stringify(baseJson('acme', c))).join('\n');
    const accounts = new Set((JSON.stringify(all).match(/\b\d{12}\b/g) ?? []).filter((n) => !/^0000/.test(n)));
    for (const a of accounts) expect(['123456789012', '111122223333', '444455556666'], a).toContain(a);
  });

  // A cloud key's provider and account are fields of the contract, so the page never reads them out of the ARN.
  // The fixture is where the two could disagree, so a test compares them: the account and the Region of a key
  // are the ones inside its ARN and its replica's ARN, in every example bundle and every scene.
  it('a cloud key names its provider and its account, and the account is the one inside its ARNs', () => {
    const arn = /^arn:aws:kms:([a-z0-9-]+):(\d{12}):key\/[0-9a-z-]+$/;
    let checked = 0;
    for (const w of WORLDS()) {
      for (const k of w.inventory.keys) {
        const p = k.place;
        if (p?.store !== Store.AWS_KMS) {
          expect(p?.account ?? '', `${w.id} ${k.fingerprint}: only a cloud key has an account`).toBe('');
          expect(p?.provider, `${w.id} ${k.fingerprint}: only a cloud key has a provider`).toBe(commonPb.CloudProvider.UNSPECIFIED);
          continue;
        }
        checked += 1;
        const at = `${w.id} ${k.label || k.delegation}`;
        expect(p.provider, `${at}: provider`).toBe(commonPb.CloudProvider.AWS);
        const primary = arn.exec(p.keyRef);
        expect(primary, `${at}: key_ref is an ARN`).not.toBeNull();
        expect(p.account, `${at}: the account is the one inside key_ref`).toBe(primary?.[2]);
        expect(p.region, `${at}: the Region is the one inside key_ref`).toBe(primary?.[1]);
        if (p.replicaRef) {
          const replica = arn.exec(p.replicaRef);
          expect(replica, `${at}: replica_ref is an ARN`).not.toBeNull();
          expect(p.account, `${at}: the replica is in the same account`).toBe(replica?.[2]);
          expect(p.replicaRegion, `${at}: the replica Region is the one inside replica_ref`).toBe(replica?.[1]);
        }
      }
    }
    expect(checked).toBeGreaterThan(8);
  });

  it('a root key is never lost: no enum of the contract has a value named LOST', () => {
    const names: string[] = [];
    for (const mod of [inspectPb, commonPb]) for (const [name, value] of Object.entries(mod)) if (value && typeof value === 'object' && !('typeName' in value) && /^[A-Z]/.test(name) && Object.values(value).some((v) => typeof v === 'number')) names.push(...Object.keys(value).filter((k) => /lost/i.test(k)));
    expect(names).toEqual([]);
    const proto = read('../../proto/ritueel/local/v1alpha1/inspect_service.proto') + read('../../proto/ritueel/local/v1alpha1/common.proto');
    expect(proto.match(/^\s*[A-Z_]*LOST\b.*=\s*\d+;/gm) ?? []).toEqual([]);
  });

  it('dates of acme: the end of acme-release, a certificate and a CRL keep their lengths', async () => {
    setBundle('acme');
    const w = await world();
    const read0 = day(w.summary.readAt);
    const certs = w.inventory.certifications;
    // The renewal that waits is for acme-release; the certificate it involves ends 60 days after the read.
    const renewal = w.inventory.changes.find((c) => c.object?.id === 'acme-release');
    const ending = certs.find((c) => c.id === renewal?.involves[0]?.id);
    expect(daysApart(read0, day(ending?.validUntil))).toBe(60);
    for (const c of certs.filter((x) => x.kind === inspectPb.CertificationKind.ROOT_CERTIFICATE)) expect(monthsApart(day(c.validFrom), day(c.validUntil)), c.id).toBe(36);
    for (const c of certs.filter((x) => x.kind === inspectPb.CertificationKind.INTERMEDIATE_CERTIFICATE)) expect(monthsApart(day(c.validFrom), day(c.validUntil)), c.id).toBe(13);
    // A CRL stays current 25 months from the day it was built (record 0006, rule 26).
    const crls = w.trust.files.filter((f) => f.kind === TrustFileKind.CRL);
    expect(crls.length).toBeGreaterThan(0);
    for (const f of crls) expect(monthsApart(day(f.builtAt), day(f.validUntil)), f.name).toBe(25);
    // The trust set grows at least once a year.
    const sets = w.ceremonies.ceremonies.filter((c) => c.trustSequence > 0 && c.state === CeremonyState.RECORDED).reverse();
    for (let i = 1; i < sets.length; i++) {
      if (sets[i].trustSequence === sets[i - 1].trustSequence) continue;
      expect(monthsApart(day(sets[i - 1].plannedAt), day(sets[i].plannedAt)), `${sets[i - 1].id} to ${sets[i].id}`).toBeLessThan(13);
    }
  });

  it('dates of globex and personal', async () => {
    setBundle('globex');
    const g = await world();
    expect(daysApart(day(g.summary.readAt), day(g.summary.nextDate?.endsAt))).toBe(361);
    expect(daysApart(day(g.summary.nextDate?.dueFrom), day(g.summary.nextDate?.endsAt))).toBe(60);
    expect(g.summary.nextDate?.object?.id).toBe('globex-ca');
    for (const f of g.trust.files.filter((x) => x.kind === TrustFileKind.CRL)) expect(monthsApart(day(f.builtAt), day(f.validUntil)), f.name).toBe(25);
    setBundle('personal');
    const p = await world();
    const primary = p.inventory.keys.find((k) => k.role === inspectPb.KeyRole.ROOT_KEY)!;
    expect(daysApart(day(p.summary.readAt), day(primary.expiresAt))).toBe(747);
    expect(p.findings.findings.filter((f) => f.object?.id === primary.fingerprint), 'the primary has no finding').toEqual([]);
    const subkeys = p.inventory.keys.filter((k) => k.role === inspectPb.KeyRole.DELEGATED_KEY);
    expect(subkeys.length).toBeGreaterThan(0);
    for (const k of subkeys) {
      expect(daysApart(day(p.summary.readAt), day(k.expiresAt)), k.fingerprint).toBe(47);
      expect(day(k.expiresAt), k.fingerprint).toBe('2027-01-10');
      expect(p.inventory.requests.some((r) => r.key === k.fingerprint), `a request for ${k.fingerprint}`).toBe(true);
    }
    // Each subkey is bound for 13 months, from 2025-12-10 to 2027-01-10.
    const bindings = p.inventory.certifications.filter((c) => c.kind === inspectPb.CertificationKind.SUBKEY_BINDING);
    expect(bindings).toHaveLength(subkeys.length);
    for (const c of bindings) {
      expect(day(c.validFrom), c.id).toBe('2025-12-10');
      expect(day(c.validUntil), c.id).toBe('2027-01-10');
    }
  });

  it('the touches follow the store, and each bundle runs where its keys are', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      for (const c of (await inspect.listCeremonies({})).ceremonies) {
        if (c.cards.length === 0) expect(c.touchCount, `${b} ${c.id}`).toBe(0);
        expect(c.touchCount, `${b} ${c.id}`).toBeLessThanOrEqual(c.signatureCount);
        if (b === 'globex') expect(c.touchCount, c.id).toBe(0);
        if (b === 'personal' && c.ranOn !== RunPlace.UNSPECIFIED) expect(c.ranOn, c.id).toBe(RunPlace.OFFLINE_SYSTEM);
        if (b === 'acme' && c.ranOn !== RunPlace.UNSPECIFIED) expect(c.ranOn, c.id).toBe(RunPlace.WORKSTATION);
      }
    }
  });

  it('the bundles are apart: no serial, fingerprint or digest is shared', async () => {
    const seen = new Map<string, string>();
    const clash: string[] = [];
    const note = (b: string, v: string) => {
      if (!v) return;
      const had = seen.get(v);
      if (had && had !== b) clash.push(`${v} in ${had} and ${b}`);
      seen.set(v, b);
    };
    for (const b of BUNDLES) {
      setBundle(b);
      const w = await world();
      w.inventory.cards.forEach((c) => note(b, c.serial));
      w.inventory.keys.forEach((k) => note(b, k.fingerprint));
      w.ceremonies.ceremonies.forEach((c) => [c.planSha256, c.recordSha256].forEach((d) => note(b, d)));
      w.trust.files.forEach((f) => note(b, f.sha256));
    }
    expect(clash).toEqual([]);
  });

  it('a company has a root list and a CA bundle, a person has neither, and no file is a package', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const w = await world();
      const kinds = w.trust.files.map((f) => f.kind);
      if (b === 'personal') {
        expect(kinds, b).not.toContain(TrustFileKind.ROOT_LIST);
        expect(kinds, b).not.toContain(TrustFileKind.CA_BUNDLE);
        expect(w.inventory.roots.some((r) => r.kind === KeyKind.X509)).toBe(false);
        expect(w.inventory.roots.filter((r) => r.kind === KeyKind.OPENPGP)).toHaveLength(1);
        for (const f of w.trust.files) expect(f.verifyCommand, `${f.path}: no root list to check it against`).toBe('');
      } else {
        expect(kinds, b).toContain(TrustFileKind.ROOT_LIST);
        expect(kinds, b).toContain(TrustFileKind.CA_BUNDLE);
      }
      for (const f of w.trust.files) {
        expect(f.path, f.path).not.toMatch(/\.(rpm|deb)$/);
        expect(f.path.startsWith(`trust/${w.trust.setName}/`), f.path).toBe(true);
      }
    }
  });
});

describe('the four states of a read', () => {
  it('empty: every call answers with nothing in it, keeps the name, path and kind, and the history has no record', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const full = await inspect.getSummary({});
      setViewState('empty');
      const s = await inspect.getSummary({});
      expect(s.bundle?.name, b).toBe(b);
      expect(s.bundle?.path, b).toBe(full.bundle?.path);
      expect(s.bundle?.kind, b).toBe(full.bundle?.kind);
      expect(s.history?.recordCount, b).toBe(0);
      expect(s.changes?.ready ?? 0).toBe(0);
      expect(s.changes?.waits ?? 0).toBe(0);
      expect(s.trustSequence).toBe(0);
      expect(s.findingCounts).toEqual([]);
      expect((await inspect.listFindings({})).findings).toEqual([]);
      const inv = await inspect.getInventory({});
      for (const list of [inv.cards, inv.roots, inv.keys, inv.userIds, inv.delegations, inv.certifications, inv.requests, inv.changes]) expect(list).toEqual([]);
      const c = await inspect.listCeremonies({});
      expect(c.ceremonies).toEqual([]);
      expect(c.history?.recordCount).toBe(0);
      expect((await inspect.listTrustFiles({})).files).toEqual([]);
      setViewState('loaded');
    }
  });
  it('failed: every call fails with an error that names the path of the bundle, never an empty answer', async () => {
    setViewState('failed');
    for (const b of BUNDLES) {
      setBundle(b);
      for (const m of InspectService.methods) {
        const call = (inspect as unknown as Record<string, (r: object) => Promise<unknown>>)[m.localName];
        const err = await call({}).then(
          () => undefined,
          (e: unknown) => e,
        );
        expect(err, `${b} ${m.name}`).toBeInstanceOf(ConnectError);
        expect((err as ConnectError).code).toBe(Code.Unavailable);
        expect((err as ConnectError).rawMessage).toContain(`~/ritueel/${b}`);
      }
    }
  });
  it('waiting: no answer until the state changes, and then the call ends', async () => {
    setViewState('waiting');
    let settled = false;
    const pending = inspect.getSummary({}).then(
      () => (settled = true),
      () => (settled = true),
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(settled).toBe(false);
    setViewState('loaded');
    await pending;
    expect(settled).toBe(true);
  });
  it('switching the bundle changes every answer, and the Empty state ignores the scene', async () => {
    const names: (string | undefined)[] = [];
    for (const b of BUNDLES) {
      setBundle(b);
      names.push((await inspect.getSummary({})).bundle?.name);
    }
    expect(names).toEqual(BUNDLES);
    setBundle('acme');
    setScene(5);
    const loaded = await inspect.getSummary({});
    expect(loaded.trustSequence).toBe(14);
    setViewState('empty');
    expect((await inspect.getSummary({})).trustSequence).toBe(0);
    expect((await inspect.getSummary({})).readAt).toEqual(baseSummaryReadAt());
  });
});

function baseSummaryReadAt() {
  return fromJson(GetSummaryResponseSchema, baseJson('acme', 'GetSummary')).readAt;
}

describe('the words of the maintainer stay', () => {
  function files(dir: string, ext: RegExp): string[] {
    return readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(`${dir}/${e.name}`, ext) : ext.test(e.name) && !/\.test\.tsx?$/.test(e.name) && e.name !== 'testkit.ts' ? [`${dir}/${e.name}`] : []));
  }
  const SOURCES = [...files('fixtures', /\.json$/), ...files('screens', /\.tsx$/), ...files('lib', /\.ts$/), ...files('ui', /\.tsx$/)];

  // "folder" is allowed only as "ceremony folder" or "sub-folder". The rest are the words the records replaced.
  const OLD_WORDS = /ceremony machine|offline machine|\bdaily\b|pending\/|hardware.key sign-in|(?<!ceremony )(?<!sub-)\bfolder\b/i;
  it('no fixture or screen uses a word the maintainer replaced', () => {
    const hits: string[] = [];
    for (const f of SOURCES) {
      const m = OLD_WORDS.exec(read(f));
      if (m) hits.push(`${f}: ${m[0]}`);
      // A saved plan is history/<ceremony>/plan.json; there is no file called *.plan.
      if (f.startsWith('fixtures/') && /\.plan\b/.test(read(f))) hits.push(`${f}: .plan`);
    }
    expect(hits).toEqual([]);
  });

  // The words the page dropped with the plan screen. A README may name them once, in its section "What went".
  const DROPPED = /\b(SavePlan|StartPlan|ListIntentions|PlanService|Make a plan|Save the plan|wizard goal|due item|setup step)\b/;
  /** The text of a README without the section that says what went. */
  function withoutWhatWent(text: string): string {
    return text.replace(/^(#{1,6}) What went[^\n]*\n[\s\S]*?(?=^#{1,6} |(?![\s\S]))/m, '');
  }
  it('no source, contract or README uses a word the page dropped, except where the README says what went', () => {
    const hits: string[] = [];
    const proto = readdirSync(join(HERE, '../../proto/ritueel/local/v1alpha1')).map((n) => join(HERE, '../../proto/ritueel/local/v1alpha1', n));
    for (const f of [...SOURCES.map((x) => join(HERE, x)), ...proto, join(HERE, 'api/client.ts'), join(HERE, 'api/hooks.ts')]) {
      const m = DROPPED.exec(readFileSync(f, 'utf8'));
      if (m) hits.push(`${f}: ${m[0]}`);
    }
    for (const f of [join(HERE, '../README.md'), join(HERE, '../../proto/README.md')]) {
      const text = readFileSync(f, 'utf8');
      const m = DROPPED.exec(withoutWhatWent(text));
      if (m) hits.push(`${f}: ${m[0]}`);
      // The section exists and names each dropped word at most once.
      const section = /^#{1,6} What went[^\n]*\n([\s\S]*?)(?=^#{1,6} |(?![\s\S]))/m.exec(text)?.[1] ?? '';
      expect(section, `${f} has a section "What went"`).not.toBe('');
      for (const w of ['PlanService', 'SavePlan', 'StartPlan', 'ListIntentions']) expect((section.match(new RegExp(`\\b${w}\\b`, 'g')) ?? []).length, `${f}: ${w}`).toBeLessThanOrEqual(1);
    }
    expect(hits).toEqual([]);
  });

  // The words the ten records replaced (0006 rule 5, 0001, 0008, glossary): the history, not the ledger; trust files in
  // trust/<number>/, not products; requests/<name>/, not answers/; no staff key, certifier, card helper, board card or
  // yearly command (0008, 0003, 0005); no Unix socket, random port, hardware-key rule, old ADR number or unpublished page.
  const OLD_WORDS_OF_THE_RECORDS = /ledger|trust products?|\bproducts\b|\banswers\/|staff|certifier|card helper|board card|yearly (command|intention)|unix socket|random port|hardware.key|ADR[ -]?00|ritueel\.id\/(reference|decisions|tools)\//i;
  it('no fixture, screen, contract or README uses a word the ten records replaced', () => {
    const PROTO = '../../proto/ritueel/local/v1alpha1/';
    const sources = [...SOURCES.map((f) => join(HERE, f)), ...['common.proto', 'inspect_service.proto'].map((n) => join(HERE, PROTO, n)), join(HERE, '../README.md'), join(HERE, '../../proto/README.md'), join(HERE, 'api/client.ts')];
    const hits: string[] = [];
    for (const f of sources) {
      // docs/reference/bundle.md names the role of the read account example-certifier-read; the fixture copies that one name.
      const text = readFileSync(f, 'utf8').split('example-certifier-read').join('');
      const m = OLD_WORDS_OF_THE_RECORDS.exec(text);
      if (m) hits.push(`${f}: ${m[0]}`);
    }
    expect(hits).toEqual([]);
  });
});

describe('every kind of card has a word', () => {
  it('root, day-to-day, rehearsal and server each read as a card', () => {
    const kinds = Object.values(CardKind).filter((v): v is CardKind => typeof v === 'number' && v !== CardKind.UNSPECIFIED);
    expect(kinds).toHaveLength(4);
    for (const k of kinds) expect(CARD_KIND_WORD[k], CardKind[k]).toMatch(/\bcard$/);
    expect(Object.values(CARD_KIND_WORD).sort()).toEqual(['day-to-day card', 'rehearsal card', 'root card', 'server card']);
  });
});

// ---- the commands follow docs/reference/cli.md ------------------------------------------------

describe('the commands follow docs/reference/cli.md', () => {
  const CLI = read('../../docs/reference/cli.md');
  // The thirteen words of the reference: the first word after `ritueel` in the rows of its first table.
  const WORDS = [...new Set([...CLI.matchAll(/^\| `ritueel ([a-z]+)/gm)].map((m) => m[1]))];
  // What the page shows and the reference does not have yet, per command word. It is listed for the maintainer
  // (proto/ and ui/ comments say [proposed]); a flag that is not on a line of its own command, not in the table of
  // flags every ceremony shares, and not here fails. Empty today: every flag of the fixtures is in the reference.
  const PROPOSED_FLAGS: Record<string, string[]> = {};
  /** The flags the reference lists for every command, in rows that begin with the flag. */
  const GLOBAL_FLAGS = new Set([...CLI.matchAll(/^\| `(--[a-z][a-z-]*)/gm)].map((m) => m[1]));
  /** The lines of the reference that hold a command of this word, for example `ritueel verify root-list`. */
  const ownLines = (word: string) => CLI.split('\n').filter((line) => line.includes(`\`ritueel ${word}`) || line.includes(`\`ritueel --dir DIR ${word}`));

  /** Every command string of the fixtures and of the patched answers: each field named *_command, and TrustFile.verify_command. */
  function commandsOf(v: unknown, out: string[] = []): string[] {
    if (Array.isArray(v)) v.forEach((x) => commandsOf(x, out));
    else if (v && typeof v === 'object')
      for (const [k, x] of Object.entries(v)) {
        if (typeof x === 'string' && /command$/i.test(k) && x.startsWith('ritueel')) out.push(x);
        else commandsOf(x, out);
      }
    return out;
  }
  function fixtureFiles(dir: string): string[] {
    return readdirSync(join(HERE, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? fixtureFiles(`${dir}/${e.name}`) : e.name.endsWith('.json') ? [`${dir}/${e.name}`] : []));
  }
  const fromFixtures = fixtureFiles('fixtures').flatMap((f) => commandsOf(JSON.parse(read(f))).map((c) => ({ where: f, c })));
  const fromScenes = [1, 2, 3, 4, 5].flatMap((n) =>
    (['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles'] as const).flatMap((call) => commandsOf(applySceneNumber(n, call, baseJson('acme', call))).map((c) => ({ where: `acme scene ${n} ${call}`, c }))),
  );
  /** The commands the screens write themselves: a `Cmd` child, or a string that begins with `ritueel` and a command word. */
  function commandsOfSource(): { where: string; c: string }[] {
    const out: { where: string; c: string }[] = [];
    for (const f of [...files('screens'), ...files('ui'), ...files('lib')]) {
      const text = read(f);
      for (const m of text.matchAll(/<Cmd\b[^>]*>\s*\{?[`']?(ritueel [^<`'}]*)/g)) out.push({ where: f, c: m[1].trim() });
      for (const m of text.matchAll(/[`'"](ritueel [a-z][^`'"]*)[`'"]/g)) if (WORDS.includes(m[1].split(' ')[1])) out.push({ where: f, c: m[1] });
    }
    return out;
  }
  function files(dir: string): string[] {
    return readdirSync(join(HERE, dir)).filter((n) => /\.tsx?$/.test(n) && !/\.test\./.test(n) && n !== 'testkit.ts').map((n) => `${dir}/${n}`);
  }
  const all = [...fromFixtures, ...fromScenes, ...commandsOfSource()];

  it('has thirteen command words, and commands to check (an empty walk proves nothing)', () => {
    expect(WORDS.sort()).toEqual(['apply', 'check', 'close', 'join', 'new', 'publish', 'revoke', 'status', 'stop', 'verify', 'version', 'want', 'wizard']);
    expect(fromFixtures.length).toBeGreaterThan(30);
    expect(fromScenes.length).toBeGreaterThan(5);
    expect(commandsOfSource().length).toBeGreaterThan(3);
  });
  it('every command begins with ritueel, an optional --dir and one of the thirteen words; no earlier name', () => {
    const bad: string[] = [];
    for (const { where, c } of all) {
      const m = /^ritueel (?:--dir \S+ )?([a-z][a-z-]*)(?: |$)/.exec(c);
      if (!m || !WORDS.includes(m[1])) bad.push(`${where}: ${c}`);
      if (/root-list verify|crl verify|ssh-ca-keys verify|keyring verify|ca-bundle build|card adopt|card check|\bintermediate\b|\bdrill\b|\brecords\b|\bhandoff\b|\bdue\b|\brun\b/.test(c.replace(/^ritueel (--dir \S+ )?/, '').split(' ').slice(0, 3).join(' '))) bad.push(`${where}: earlier name in ${c}`);
    }
    expect(bad).toEqual([]);
  });
  it('every flag is a flag of its own command in cli.md, a flag every ceremony shares, or a listed proposal of that command; apply never carries --confirm', () => {
    const bad: string[] = [];
    for (const { where, c } of all) {
      const m = /^ritueel (?:--dir \S+ )?([a-z][a-z-]*)(?: (\S+))?/.exec(c);
      if (!m) continue; // the earlier test reports it
      const [, word, second] = m;
      const own = ownLines(word);
      // The subcommand of check, verify and status is on a line of the reference too: `check cards`, `verify root-list`.
      if (['check', 'verify', 'status'].includes(word) && second && /^[a-z][a-z-]*$/.test(second) && !own.some((l) => l.includes(second))) bad.push(`${where}: ${word} ${second} is not in cli.md: ${c}`);
      for (const flag of c.match(/--[a-z][a-z-]*/g) ?? []) {
        if (flag === '--dir' || GLOBAL_FLAGS.has(flag) || (PROPOSED_FLAGS[word] ?? []).includes(flag)) continue;
        if (!own.some((line) => new RegExp(`${flag}(?![a-z-])`).test(line))) bad.push(`${where}: ${flag} is not a flag of ${word} in cli.md: ${c}`);
      }
      if (/ apply\b/.test(c) && /--confirm/.test(c)) bad.push(`${where}: apply with --confirm: ${c}`);
    }
    expect(bad).toEqual([]);
  });
  it('the check of flags finds a wrong flag on a wrong command', () => {
    // --pin belongs to `verify root-list` and --card to `revoke`: on any other command they fail.
    expect(ownLines('apply').some((l) => /--pin(?![a-z-])/.test(l))).toBe(false);
    expect(ownLines('verify').some((l) => /--pin(?![a-z-])/.test(l))).toBe(true);
    expect(ownLines('close').some((l) => /--card(?![a-z-])/.test(l))).toBe(false);
    expect(ownLines('revoke').some((l) => /--card(?![a-z-])/.test(l))).toBe(true);
  });
  it('no command names a digest or holds the word --confirm', () => {
    for (const { where, c } of all) {
      expect(c, where).not.toMatch(/--confirm/);
      expect(c, where).not.toMatch(/[0-9a-fA-F]{64}/);
    }
  });
  it('a verifier does not name the bundle, and no command names a bundle by a flag of its own', () => {
    for (const { where, c } of all) {
      if (/^ritueel verify /.test(c)) expect(c, where).not.toContain('--dir');
      expect(c, where).not.toMatch(/ritueel bundle |--bundle\b/);
    }
  });
  it('the shown commands are the ones the records and the reference give for these jobs', () => {
    const cmds = new Set(all.map((x) => x.c));
    expect(cmds.has('ritueel apply --allow-missing acme-release')).toBe(true);
    expect(cmds.has('ritueel publish')).toBe(true);
    expect(cmds.has('ritueel close 20261124T100400Z-apply-7d41e9b3 --reason TEXT')).toBe(true);
    expect(cmds.has('ritueel revoke --card root-a --reason REASON')).toBe(true);
    expect(cmds.has('ritueel revoke acme/A --reason REASON')).toBe(true);
    expect(cmds.has('ritueel status')).toBe(true);
  });
});

// ---- switching the bundle or the scene keeps the screen -----------------------------------------

describe('switching the example bundle or the scene keeps the screen', () => {
  // The tests run in Node, which has no window: this is the address bar of the page. A fallback must replace the
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

  function switchFrom(from: DemoBundle, hash: string, to: DemoBundle) {
    setBundle(from);
    bar = hash;
    writes = [];
    pushes = [];
    setBundle(to);
    expect(pushes, `${from} to ${to} on ${hash}: no history entry is pushed`).toEqual([]);
    return { hash: bar, writes: [...writes] };
  }
  function switchScene(from: number, hash: string, to: number) {
    setScene(from);
    bar = hash;
    writes = [];
    pushes = [];
    expect(setScene(to)).toBe(true);
    expect(pushes, `scene ${from} to ${to} on ${hash}: no history entry is pushed`).toEqual([]);
    return { hash: bar, writes: [...writes] };
  }

  const SLUG: Record<number, ObjectSlug> = {
    [ObjectKind.CARD]: 'card',
    [ObjectKind.ROOT]: 'root',
    [ObjectKind.KEY]: 'key',
    [ObjectKind.USER_ID]: 'userid',
    [ObjectKind.DELEGATION]: 'delegation',
    [ObjectKind.CERTIFICATION]: 'certification',
    [ObjectKind.REQUEST]: 'request',
  };
  /** What the bundle and scene shown now hold, asked of the transport as the screens ask it. Independent of the code under test. */
  async function held() {
    const inv: GetInventoryResponse = await inspect.getInventory({});
    return {
      objects: [
        ...inv.cards.map((c) => `${SLUG[ObjectKind.CARD]}/${c.name}`),
        ...inv.roots.map((r) => `root/${r.name}`),
        ...inv.keys.map((k) => `key/${k.fingerprint}`),
        ...inv.userIds.map((u) => `userid/${u.id}`),
        ...inv.delegations.map((d) => `delegation/${d.name}`),
        ...inv.certifications.map((c) => `certification/${c.id}`),
        ...inv.requests.map((r) => `request/${r.stem}`),
      ],
      ceremonies: (await inspect.listCeremonies({})).ceremonies.map((c) => c.id),
    };
  }
  async function showable(hash: string): Promise<boolean> {
    const r: Route = parseHash(hash);
    const h = await held();
    switch (r.name) {
      case 'inventory':
        return r.object === undefined || h.objects.includes(`${r.object.kind}/${r.object.id}`);
      case 'history':
        return r.id === undefined || h.ceremonies.includes(r.id);
      case 'notfound':
        return false;
      default:
        return true;
    }
  }

  const SCREENS = ['#/todo', '#/todo/findings', '#/inventory', '#/inventory/cards', '#/inventory/roots', '#/inventory/dates', '#/history', '#/trust'];

  it('every screen stays, for every pair of bundles, and the address is not written', () => {
    for (const from of BUNDLES)
      for (const to of BUNDLES)
        for (const screen of SCREENS) {
          const got = switchFrom(from, screen, to);
          expect(got, `${from} to ${to} on ${screen}`).toEqual({ hash: screen, writes: [] });
        }
  });
  it('an empty address, an unknown hash and an old address are left as they are', () => {
    for (const hash of ['', '#', '#/', '#/nope', '#/start', '#/cards', '#/plan', '#/key/A', '#/inventory/cards/x'])
      for (const to of ['globex', 'personal'] as const) expect(switchFrom('acme', hash, to), `${JSON.stringify(hash)} to ${to}`).toEqual({ hash, writes: [] });
  });
  it('an inventory object stays when the new bundle has it, and drops to the list of the same view when not', async () => {
    setBundle('acme');
    const inv = await inspect.getInventory({});
    const card = '#/inventory/cards/card/root-a';
    const fp = encodeURIComponent(inv.keys[0].fingerprint);
    expect(switchFrom('acme', card, 'acme')).toEqual({ hash: card, writes: [] });
    for (const to of ['globex', 'personal'] as const) {
      expect(switchFrom('acme', card, to), to).toEqual({ hash: '#/inventory/cards', writes: ['#/inventory/cards'] });
      expect(switchFrom('acme', `#/inventory/roots/key/${fp}`, to), to).toEqual({ hash: '#/inventory/roots', writes: ['#/inventory/roots'] });
      expect(switchFrom('acme', '#/inventory/dates/certification/cert-8', to), to).toEqual({ hash: '#/inventory/dates', writes: ['#/inventory/dates'] });
    }
  });
  it('a history id stays when the new bundle has it, and drops to History when not', () => {
    const id = '20261120T100000Z-apply-3fa9c1d2';
    expect(switchFrom('acme', `#/history/${id}`, 'acme').hash).toBe(`#/history/${id}`);
    for (const to of ['globex', 'personal'] as const) expect(switchFrom('acme', `#/history/${id}`, to), to).toEqual({ hash: '#/history', writes: ['#/history'] });
  });
  it('nothing ever ends on an address that the new bundle cannot show', async () => {
    for (const from of BUNDLES) {
      setBundle(from);
      const h = await held();
      const details = [
        ...h.objects.map((o) => `#/inventory/${o.startsWith('card/') ? 'cards' : o.startsWith('certification/') ? 'dates' : 'roots'}/${o.split('/')[0]}/${encodeURIComponent(o.slice(o.indexOf('/') + 1))}`),
        ...h.ceremonies.map((c) => `#/history/${c}`),
        '#/inventory/cards/card/none',
        '#/history/20000101T000000Z-apply-00000000',
      ];
      for (const to of BUNDLES.filter((b) => b !== from))
        for (const hash of [...SCREENS, ...details]) {
          const got = switchFrom(from, hash, to);
          expect(await showable(got.hash), `${from} ${hash} to ${to} ended on ${got.hash}`).toBe(true);
          expect(got.writes.length, `${from} ${hash} to ${to}: written only when the route had to fall back`).toBe(got.hash === hash ? 0 : 1);
        }
    }
  });
  it('in the Failed and Waiting page states the detail views of the loaded bundle stay, the others fall back', () => {
    for (const state of ['failed', 'waiting'] as const) {
      setViewState(state);
      expect(switchFrom('acme', '#/inventory/cards/card/root-a', 'globex'), state).toEqual({ hash: '#/inventory/cards', writes: ['#/inventory/cards'] });
      expect(switchFrom('acme', '#/history/20261120T100000Z-apply-3fa9c1d2', 'globex'), state).toEqual({ hash: '#/history', writes: ['#/history'] });
      expect(switchFrom('acme', '#/trust', 'globex'), state).toEqual({ hash: '#/trust', writes: [] });
    }
  });
  it('in the Empty page state nothing is held, so every detail view falls back', () => {
    setViewState('empty');
    expect(switchFrom('acme', '#/inventory/roots/root/acme-tls', 'globex').hash).toBe('#/inventory/roots');
    expect(switchFrom('acme', '#/history/20261120T100000Z-apply-3fa9c1d2', 'personal').hash).toBe('#/history');
    expect(switchFrom('acme', '#/inventory/cards', 'personal').hash).toBe('#/inventory/cards');
  });
  it('before the demo transport has said what a bundle holds, the address is left alone', async () => {
    vi.resetModules();
    const fresh = await import('./api/demoState');
    bar = '#/inventory/cards/card/root-a';
    fresh.setBundle('globex');
    expect({ hash: bar, writes, pushes }).toEqual({ hash: '#/inventory/cards/card/root-a', writes: [], pushes: [] });
    fresh.provideBundleContents(() => ({ objects: [], ceremonies: [] }));
    fresh.setBundle('personal');
    expect({ hash: bar, writes }).toEqual({ hash: '#/inventory/cards', writes: ['#/inventory/cards'] });
  });
  it('a fixture that cannot be read keeps the address and still tells the listeners', async () => {
    vi.resetModules();
    const fresh = await import('./api/demoState');
    fresh.provideBundleContents(() => {
      throw new Error('missing fixture');
    });
    let told = 0;
    fresh.subscribeBundle(() => told++);
    bar = '#/inventory/cards/card/root-a';
    fresh.setBundle('globex');
    expect({ hash: bar, writes, told, bundle: fresh.getBundle() }).toEqual({ hash: '#/inventory/cards/card/root-a', writes: [], told: 1, bundle: 'globex' });
  });

  it('a scene keeps the screen too: an object the new scene lacks falls back to its list', () => {
    expect(switchScene(1, '#/todo', 5)).toEqual({ hash: '#/todo', writes: [] });
    expect(switchScene(5, '#/inventory/dates/certification/cert-9', 1)).toEqual({ hash: '#/inventory/dates', writes: ['#/inventory/dates'] });
    expect(switchScene(5, '#/inventory/dates/certification/cert-9', 4)).toEqual({ hash: '#/inventory/dates', writes: ['#/inventory/dates'] });
    expect(switchScene(1, '#/inventory/dates/certification/cert-8', 5)).toEqual({ hash: '#/inventory/dates/certification/cert-8', writes: [] });
    // the new ceremony exists in scenes 3 to 5 only
    const id = '20261124T100400Z-apply-7d41e9b3';
    expect(switchScene(3, `#/history/${id}`, 5).hash).toBe(`#/history/${id}`);
    expect(switchScene(3, `#/history/${id}`, 2)).toEqual({ hash: '#/history', writes: ['#/history'] });
    expect(switchScene(5, `#/history/${id}`, 1)).toEqual({ hash: '#/history', writes: ['#/history'] });
  });
  it('setScene refuses 0 and 6 and keeps the scene', () => {
    setScene(3);
    expect(setScene(0)).toBe(false);
    expect(setScene(6)).toBe(false);
    expect(setScene(2.5)).toBe(false);
    expect(getScene()).toBe(3);
    expect(setScene(4)).toBe(true);
    expect(getScene()).toBe(4);
  });
});

// ---- the inventory objects ---------------------------------------------------------------------

describe('the objects of the inventory hold together', () => {
  const worlds: [string, DemoBundle, number][] = [['acme', 'acme', 1], ['globex', 'globex', 1], ['personal', 'personal', 1], ...[2, 3, 4, 5].map((n) => [`acme scene ${n}`, 'acme', n] as [string, DemoBundle, number])];
  for (const [id, bundle, scene] of worlds) {
    it(`${id}: ids are unique, references name what exists, and a touch names a ceremony`, () => {
      const w = loadWorld(bundle, scene);
      const inv = w.inventory;
      const unique = (what: string, ids: string[]) => expect(new Set(ids).size, `${id}: ${what} ids are unique`).toBe(ids.length);
      unique('card', inv.cards.map((c) => c.name));
      unique('root', inv.roots.map((r) => r.name));
      unique('key', inv.keys.map((k) => k.fingerprint));
      unique('user ID', inv.userIds.map((u) => u.id));
      unique('delegation', inv.delegations.map((d) => d.name));
      unique('certification', inv.certifications.map((c) => c.id));
      unique('request', inv.requests.map((r) => r.stem));
      unique('change', inv.changes.map((c) => c.id));
      for (const k of inv.keys) {
        const len = k.kind === KeyKind.OPENPGP ? 40 : 64;
        expect(k.fingerprint, `${id}: ${k.label}`).toMatch(new RegExp(`^[0-9a-fA-F]{${len}}$`));
        if (k.root) expect(inv.roots.map((r) => r.name), `${id}: key ${k.label} root`).toContain(k.root);
        if (k.place?.card) expect(inv.cards.map((c) => c.name), `${id}: key ${k.label} card`).toContain(k.place.card);
      }
      for (const d of inv.delegations) expect(inv.roots.map((r) => r.name), `${id}: ${d.name}`).toContain(d.root);
      for (const u of inv.userIds) expect(inv.keys.map((k) => k.fingerprint), `${id}: ${u.id}`).toContain(u.key);
      const exists = (kind: ObjectKind, oid: string) => {
        switch (kind) {
          case ObjectKind.CARD: return inv.cards.some((c) => c.name === oid);
          case ObjectKind.ROOT: return inv.roots.some((r) => r.name === oid);
          case ObjectKind.KEY: return inv.keys.some((k) => k.fingerprint === oid);
          case ObjectKind.USER_ID: return inv.userIds.some((u) => u.id === oid);
          case ObjectKind.DELEGATION: return inv.delegations.some((d) => d.name === oid);
          case ObjectKind.CERTIFICATION: return inv.certifications.some((c) => c.id === oid);
          case ObjectKind.REQUEST: return inv.requests.some((r) => r.stem === oid);
          case ObjectKind.CEREMONY: return w.ceremonies.ceremonies.some((c) => c.id === oid);
          default: return true;
        }
      };
      for (const c of inv.certifications) {
        expect(inv.keys.map((k) => k.fingerprint), `${id}: ${c.id} issuer`).toContain(c.issuer);
        expect(exists(c.subject!.kind, c.subject!.id), `${id}: ${c.id} subject`).toBe(true);
      }
      const ceremonyIds = new Set(w.ceremonies.ceremonies.map((c) => c.id));
      const touches = [...inv.cards, ...inv.roots, ...inv.keys, ...inv.userIds, ...inv.delegations, ...inv.certifications, ...inv.requests].flatMap((o) => o.touchedBy);
      for (const t of touches) expect(ceremonyIds.has(t.id), `${id}: touchedBy ${t.id}`).toBe(true);
      for (const c of inv.changes) {
        expect(exists(c.object!.kind, c.object!.id), `${id}: ${c.id} object`).toBe(true);
        for (const o of c.involves) expect(exists(o.kind, o.id), `${id}: ${c.id} involves ${o.id}`).toBe(true);
        if (c.inCeremony) expect(ceremonyIds.has(c.inCeremony), `${id}: ${c.id} in ceremony`).toBe(true);
      }
    });
  }
  it('touchedBy lists the ceremonies that changed or used an object, newest first (the reverse index of applied)', () => {
    for (const [id, bundle, scene] of worlds.filter((x) => x[0] !== 'acme scene 5')) {
      const w = loadWorld(bundle, scene);
      const index = new Map<string, string[]>();
      for (const c of w.ceremonies.ceremonies.filter((x) => x.state === CeremonyState.RECORDED))
        for (const a of c.applied) {
          const key = `${a.object!.kind}/${a.object!.id}`;
          index.set(key, [...(index.get(key) ?? []), c.id]);
        }
      const objects: [ObjectKind, { id: string; touchedBy: { id: string }[] }][] = [
        ...w.inventory.cards.map((o) => [ObjectKind.CARD, { id: o.name, touchedBy: o.touchedBy }] as [ObjectKind, { id: string; touchedBy: { id: string }[] }]),
        ...w.inventory.keys.map((o) => [ObjectKind.KEY, { id: o.fingerprint, touchedBy: o.touchedBy }] as [ObjectKind, { id: string; touchedBy: { id: string }[] }]),
        ...w.inventory.userIds.map((o) => [ObjectKind.USER_ID, { id: o.id, touchedBy: o.touchedBy }] as [ObjectKind, { id: string; touchedBy: { id: string }[] }]),
        ...w.inventory.certifications.map((o) => [ObjectKind.CERTIFICATION, { id: o.id, touchedBy: o.touchedBy }] as [ObjectKind, { id: string; touchedBy: { id: string }[] }]),
      ];
      for (const [kind, o] of objects) {
        const listed = o.touchedBy.map((t) => t.id);
        const wanted = index.get(`${kind}/${o.id}`) ?? [];
        // Every ceremony that applied a change to the object is listed; the list may hold more (a card that signed).
        for (const cid of wanted) expect(listed, `${id}: ${ObjectKind[kind]} ${o.id}`).toContain(cid);
        const times = o.touchedBy.map((t) => Number((t as { at?: { seconds: bigint } }).at?.seconds ?? 0n));
        expect(times, `${id}: ${o.id} newest first`).toEqual([...times].sort((a, b) => b - a));
      }
    }
  });
});

// ---- the example texts fit the page's own limits ----------------------------------------------
//
// The page cuts a text from the bundle at a limit and writes "(cut: the text is longer than N
// characters)" (lib/safe.ts). That guard is for text no one wrote for this page. The texts of the
// demo are written for it, so none of them may run into it. The limits are the ones the screens
// use (lib/caps.ts, lib/safe.ts); nothing here copies a number.

const SCHEMAS: [string, DescMessage][] = [
  ['get-summary', GetSummaryResponseSchema],
  ['list-findings', ListFindingsResponseSchema],
  ['get-inventory', GetInventoryResponseSchema],
  ['list-ceremonies', ListCeremoniesResponseSchema],
  ['list-trust-files', ListTrustFilesResponseSchema],
];
const CALL_OF: Record<string, 'GetSummary' | 'ListFindings' | 'GetInventory' | 'ListCeremonies' | 'ListTrustFiles'> = {
  'get-summary': 'GetSummary',
  'list-findings': 'ListFindings',
  'get-inventory': 'GetInventory',
  'list-ceremonies': 'ListCeremonies',
  'list-trust-files': 'ListTrustFiles',
};

/** The limit of one text: a command has the limit of the Copy control; the smallest limit of the places that draw the field. */
function limitOf(key: string): number {
  const field = key.split('.')[1] ?? '';
  if (/_command$/.test(field)) return COMMAND_CAP;
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
      } else if (typeof x === 'string' && x.length > 0) yield [`${d.name}.${f.name}`, x];
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
  it('no text of any fixture or scene is longer than the limit of the place that shows it', () => {
    const tooLong: string[] = [];
    let checked = 0;
    for (const bundle of BUNDLES) {
      const scenes = bundle === 'acme' ? [1, 2, 3, 4, 5] : [0];
      for (const scene of scenes)
        for (const [file, schema] of SCHEMAS) {
          const call = CALL_OF[file];
          const json = scene === 0 ? baseJson(bundle, call) : applySceneNumber(scene, call, baseJson(bundle, call));
          const msg = fromJson(schema, json) as unknown as Record<string, unknown>;
          for (const [key, value] of textsOf(schema, msg)) {
            checked += 1;
            const cap = limitOf(key);
            if ([...value].length > cap) tooLong.push(`${bundle} scene ${scene} ${file} ${key}: ${[...value].length} characters, limit ${cap}, begins "${value.slice(0, 40)}"`);
          }
        }
    }
    expect(checked).toBeGreaterThan(1000);
    expect([...new Set(tooLong)]).toEqual([]);
  });
  it('every limit in the table belongs to a field of the contract', () => {
    const real = new Set<string>();
    for (const [, schema] of SCHEMAS) for (const k of fieldsOf(schema)) real.add(k);
    expect(Object.keys(CAPS).filter((k) => !real.has(k.split('#')[0]!))).toEqual([]);
  });
  it('a chain state exists for every history the demo shows', async () => {
    for (const b of BUNDLES) {
      setBundle(b);
      const h = (await inspect.getSummary({})).history;
      expect([ChainState.NOT_CHECKED, ChainState.VERIFIED, ChainState.BROKEN], b).toContain(h?.chainState);
    }
  });
});
