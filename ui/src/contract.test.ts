import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MethodOptions_IdempotencyLevel } from '@bufbuild/protobuf/wkt';
import { ScalarType, type DescMessage } from '@bufbuild/protobuf';
import { file_ritueel_local_v1alpha1_common } from './gen/ritueel/local/v1alpha1/common_pb';
import { file_ritueel_local_v1alpha1_inspect_service, InspectService } from './gen/ritueel/local/v1alpha1/inspect_service_pb';

// The contract in proto/ is what the page may ask of the process. In the first build it is
// five reads and nothing that writes, and no field takes text typed by a person. This test
// reads the generated descriptor, so a new call or a new field fails here before it reaches
// a screen. Security profile row 7 of docs/reference/wizard.md.

const FILES = [file_ritueel_local_v1alpha1_common, file_ritueel_local_v1alpha1_inspect_service];
const MESSAGES: DescMessage[] = FILES.flatMap((f) => f.messages);

describe('the service has five reads and nothing that writes', () => {
  it('the files declare one service, InspectService, with these five methods in this order', () => {
    expect(FILES.flatMap((f) => f.services.map((s) => s.name))).toEqual(['InspectService']);
    expect(InspectService.methods.map((m) => m.name)).toEqual(['GetSummary', 'ListFindings', 'GetInventory', 'ListCeremonies', 'ListTrustFiles']);
  });
  it('every method is unary and marked NO_SIDE_EFFECTS, so a read may be a GET', () => {
    for (const m of InspectService.methods) {
      expect(m.methodKind, m.name).toBe('unary');
      expect(m.idempotency, m.name).toBe(MethodOptions_IdempotencyLevel.NO_SIDE_EFFECTS);
    }
  });
  it('no method is named like an act', () => {
    const act = /^(Save|Set|Create|Delete|Update|Start|Confirm|Sign|Run|Apply|Revoke|Publish|Accept|Decline|Close)/;
    expect(InspectService.methods.filter((m) => act.test(m.name)).map((m) => m.name)).toEqual([]);
  });
  it('no request has a field, except one level to filter findings by', () => {
    for (const m of InspectService.methods) {
      if (m.name === 'ListFindings') {
        expect(m.input.fields.map((f) => `${f.name}:${f.fieldKind === 'enum' ? f.enum.name : f.fieldKind}`)).toEqual(['min_severity:Severity']);
      } else {
        expect(m.input.fields.map((f) => f.name), m.name).toEqual([]);
      }
    }
  });
  it('every response has a read_at, the time of the read', () => {
    for (const m of InspectService.methods) {
      const f = m.output.fields.find((x) => x.name === 'read_at');
      expect(f, m.name).toBeDefined();
      expect(f?.message?.typeName, m.name).toBe('google.protobuf.Timestamp');
    }
  });
  it('the old plan service and its messages are gone', () => {
    const names = MESSAGES.map((m) => m.name);
    for (const gone of ['StartPlanRequest', 'StartPlanResponse', 'SavePlanRequest', 'SavePlanResponse', 'ListIntentionsRequest', 'ListIntentionsResponse', 'Plan', 'PlanStep', 'Intention']) expect(names, gone).not.toContain(gone);
    expect(FILES.flatMap((f) => f.enums.map((e) => e.name))).not.toContain('Intention');
  });
});

describe('no field carries a secret or typed text', () => {
  // A field whose name is, or holds as a whole word, one of these would carry a secret. The one exception
  // is Slot.pin_rule, which is a fixed choice (PinRule), not a PIN; touch_rule does not match.
  const SECRET = new Set(['pin', 'passphrase', 'secret', 'password', 'private', 'token']);
  it('no field is named pin, passphrase, secret, password, private key or token, except Slot.pin_rule', () => {
    const hits: string[] = [];
    for (const m of MESSAGES)
      for (const f of m.fields) {
        const words = f.name.split('_');
        if (!words.some((w) => SECRET.has(w))) continue;
        if (m.name === 'Slot' && f.name === 'pin_rule' && f.fieldKind === 'enum' && f.enum.name === 'PinRule') continue;
        hits.push(`${m.name}.${f.name}`);
      }
    expect(hits).toEqual([]);
  });
  it('no field is bytes, so nothing binary goes to or from the page', () => {
    const hits = MESSAGES.flatMap((m) => m.fields.filter((f) => f.scalar === ScalarType.BYTES).map((f) => `${m.name}.${f.name}`));
    expect(hits).toEqual([]);
  });
  it('the contract files hold no word of the write side', () => {
    const proto = ['common.proto', 'inspect_service.proto'].map((n) => readFileSync(new URL(`../../proto/ritueel/local/v1alpha1/${n}`, import.meta.url), 'utf8')).join('\n');
    expect(proto).not.toMatch(/^\s*rpc\s+(Save|Start|Set|Create|Delete|Update|Confirm|Sign|Run|Apply|Revoke|Publish)/m);
  });
});

describe('the README of the contract lists every enum of it', () => {
  const readme = readFileSync(new URL('../../proto/README.md', import.meta.url), 'utf8');
  it('names every enum of both files and every call', () => {
    const enums = FILES.flatMap((f) => f.enums.map((e) => e.name));
    expect(enums.length).toBeGreaterThan(20);
    for (const e of enums) expect(readme, `enum ${e}`).toMatch(new RegExp(`\\b${e}\\b`));
    for (const m of InspectService.methods) expect(readme, `call ${m.name}`).toContain(m.name);
  });
});
