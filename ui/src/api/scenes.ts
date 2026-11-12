// The five scenes of the example bundle acme. A scene is one moment of one
// change: the base files of the bundle plus the patches of that scene (not the
// scene before it). The patches and the line of each scene are data, in
// fixtures/acme/scenes.json; this file reads them and applies them.
//
// A patch is { call, set, lists }:
//   call   one of the five reads of the contract
//   set    replaces the named fields of the response (protobuf JSON values)
//   lists  for a repeated field of the response, one of
//          { replace: [...] }, { prepend: [...] }, { append: [...] }
//
// The patches are applied to the JSON of the base file, before the demo
// transport parses it with the generated schema, so a field that is not in the
// contract is an error there. A patch that names a call, a field or a list
// that the contract does not have is an error here, with the scene in the
// message. The time of the read is the time of the scene: it replaces readAt
// in all five answers, and no patch sets it.
import type { DescMessage, JsonValue } from '@bufbuild/protobuf';
import {
  GetInventoryResponseSchema,
  GetSummaryResponseSchema,
  ListCeremoniesResponseSchema,
  ListFindingsResponseSchema,
  ListTrustFilesResponseSchema,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import scenesFile from '../fixtures/acme/scenes.json';
import { getScene } from './demoState';

/** The five calls a patch may name, with the schema of the answer of each. */
const SCHEMAS: Record<string, DescMessage> = {
  GetSummary: GetSummaryResponseSchema,
  ListFindings: ListFindingsResponseSchema,
  GetInventory: GetInventoryResponseSchema,
  ListCeremonies: ListCeremoniesResponseSchema,
  ListTrustFiles: ListTrustFilesResponseSchema,
};

type JsonObject = { [key: string]: JsonValue };

export interface ListOperation {
  replace?: JsonValue[];
  prepend?: JsonValue[];
  append?: JsonValue[];
}

export interface Patch {
  call: string;
  set?: JsonObject;
  lists?: Record<string, ListOperation>;
}

export interface Scene {
  scene: number;
  line: string;
  readAt: string;
  patches: Patch[];
}

const OPERATIONS = ['replace', 'prepend', 'append'] as const;

function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** The field of an answer with this name in protobuf JSON (camelCase), or undefined. */
function fieldOf(call: string, name: string) {
  return SCHEMAS[call]?.fields.find((f) => f.jsonName === name);
}

function checkPatch(scene: number, index: number, p: unknown): Patch {
  const where = `scene ${scene}, patch ${index + 1}`;
  if (!isObject(p) || typeof p.call !== 'string') throw new Error(`${where}: a patch needs a call`);
  if (!(p.call in SCHEMAS)) throw new Error(`${where}: ${p.call} is not a call of the contract`);
  const call = p.call;
  if (p.set !== undefined) {
    if (!isObject(p.set)) throw new Error(`${where}: set must be an object`);
    for (const name of Object.keys(p.set)) {
      const field = fieldOf(call, name);
      if (!field) throw new Error(`${where}: ${call} has no field ${name}`);
      if (field.fieldKind === 'list') throw new Error(`${where}: ${name} is a list; use lists`);
      if (name === 'readAt') throw new Error(`${where}: readAt is the time of the scene`);
    }
  }
  if (p.lists !== undefined) {
    if (!isObject(p.lists)) throw new Error(`${where}: lists must be an object`);
    for (const [name, op] of Object.entries(p.lists)) {
      const field = fieldOf(call, name);
      if (!field || field.fieldKind !== 'list') throw new Error(`${where}: ${call} has no list ${name}`);
      const given = isObject(op) ? OPERATIONS.filter((o) => (op as JsonObject)[o] !== undefined) : [];
      if (given.length !== 1 || !Array.isArray((op as JsonObject)[given[0]])) {
        throw new Error(`${where}: ${name} needs exactly one of replace, prepend and append, with a list`);
      }
    }
  }
  return p as unknown as Patch;
}

function checkScenes(file: unknown): Scene[] {
  const list = isObject(file) ? file.scenes : undefined;
  if (!Array.isArray(list) || list.length === 0) throw new Error('scenes.json needs a list of scenes');
  return list.map((s: unknown, i: number) => {
    if (!isObject(s) || s.scene !== i + 1) throw new Error(`scenes.json: scene ${i + 1} is missing or out of order`);
    if (typeof s.line !== 'string' || typeof s.readAt !== 'string' || !Array.isArray(s.patches)) {
      throw new Error(`scenes.json: scene ${i + 1} needs a line, a readAt and a list of patches`);
    }
    s.patches.forEach((p: unknown, j: number) => checkPatch(i + 1, j, p));
    return s as unknown as Scene;
  });
}

/** The scenes in order, scene 1 first. Checked when this file loads. */
export const SCENES: readonly Scene[] = checkScenes(scenesFile);

export const SCENE_COUNT: number = SCENES.length;

/** The line that says what was done outside the page in scene n (1 to SCENE_COUNT). */
export function sceneLine(n: number): string {
  return SCENES[n - 1]?.line ?? '';
}

/** The time of the read in scene n, as the text of the timestamp. */
export function sceneReadAt(n: number): string {
  return SCENES[n - 1]?.readAt ?? '';
}

function applyList(base: JsonValue | undefined, op: ListOperation): JsonValue[] {
  const current = Array.isArray(base) ? base : [];
  if (op.replace) return op.replace;
  if (op.prepend) return [...op.prepend, ...current];
  return [...current, ...(op.append ?? [])];
}

/**
 * The answer of a call in scene n, from the JSON of its base file. The base
 * JSON is a shared object and is never changed: the result is a copy.
 */
export function applySceneNumber(n: number, call: string, json: JsonValue): JsonValue {
  const scene = SCENES[n - 1];
  if (!scene) throw new Error(`scene ${n} does not exist`);
  if (!(call in SCHEMAS)) throw new Error(`${call} is not a call of the contract`);
  if (!isObject(json)) throw new Error(`the base answer of ${call} is not an object`);
  const out = JSON.parse(JSON.stringify(json)) as JsonObject;
  for (const patch of scene.patches) {
    if (patch.call !== call) continue;
    for (const [name, value] of Object.entries(patch.set ?? {})) out[name] = JSON.parse(JSON.stringify(value));
    for (const [name, op] of Object.entries(patch.lists ?? {})) {
      out[name] = JSON.parse(JSON.stringify(applyList(out[name], op)));
    }
  }
  out.readAt = scene.readAt;
  return out;
}

/** The answer of a call in the scene the demo shows now (getScene). */
export function applyScene(call: string, json: JsonValue): JsonValue {
  return applySceneNumber(getScene(), call, json);
}
