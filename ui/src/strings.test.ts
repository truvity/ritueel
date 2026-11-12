import { describe, expect, it } from 'vitest';
import { ScalarType, type DescField, type DescMessage, type Message } from '@bufbuild/protobuf';
import { file_ritueel_local_v1alpha1_common } from './gen/ritueel/local/v1alpha1/common_pb';
import {
  file_ritueel_local_v1alpha1_inspect_service,
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
} from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { WORLDS, type World } from './testkit';

// The hostile test marks every string a fixture holds. A string field that no fixture fills (a
// list that is always empty) is never marked, so no screen path of it is tested. This test reads
// every string field of the generated contract and demands that some world fills it.

const isString = (f: DescField) =>
  (f.fieldKind === 'scalar' && f.scalar === ScalarType.STRING) || (f.fieldKind === 'list' && f.listKind === 'scalar' && f.scalar === ScalarType.STRING);

const ALL: DescMessage[] = [file_ritueel_local_v1alpha1_common, file_ritueel_local_v1alpha1_inspect_service].flatMap((f) => f.messages);
const REQUESTS = new Set(['GetSummaryRequest', 'ListFindingsRequest', 'GetInventoryRequest', 'ListCeremoniesRequest', 'ListTrustFilesRequest']);
const RESPONSES = [GetSummaryResponseSchema, ListFindingsResponseSchema, GetInventoryResponseSchema, ListCeremoniesResponseSchema, ListTrustFilesResponseSchema];

function filled(world: World, seen: Set<string>) {
  const walk = (schema: DescMessage, msg: Message | undefined) => {
    if (!msg) return;
    for (const f of schema.fields) {
      const v = (msg as unknown as Record<string, unknown>)[f.localName];
      if (isString(f)) {
        if (typeof v === 'string' ? v !== '' : Array.isArray(v) && v.length > 0) seen.add(`${schema.name}.${f.name}`);
      } else if (f.fieldKind === 'message' && v) walk(f.message, v as Message);
      else if (f.fieldKind === 'list' && f.listKind === 'message') for (const x of v as Message[]) walk(f.message, x);
    }
  };
  for (const schema of RESPONSES) {
    const key = { GetSummaryResponse: 'summary', ListFindingsResponse: 'findings', GetInventoryResponse: 'inventory', ListCeremoniesResponse: 'ceremonies', ListTrustFilesResponse: 'trust' }[schema.name] as keyof World;
    walk(schema, world[key] as unknown as Message);
  }
}

describe('every string field of the contract is filled in some example world', () => {
  it('finds the string fields', () => {
    expect(ALL.flatMap((m) => m.fields.filter(isString)).length).toBeGreaterThan(80);
  });
  it('no string field stays empty in all eight worlds', () => {
    const seen = new Set<string>();
    for (const w of WORLDS()) filled(w, seen);
    const missing = ALL.filter((m) => !REQUESTS.has(m.name)).flatMap((m) => m.fields.filter(isString).map((f) => `${m.name}.${f.name}`)).filter((k) => !seen.has(k));
    expect(missing).toEqual([]);
  });
});
