#!/usr/bin/env node
// Writes the Worker configuration the deploy uses: site/wrangler.jsonc with the id of the KV
// namespace put in from the environment variable RITUEEL_STATUS_KV_ID, so that the id is never
// in this repository. Wrangler does not read environment variables in its configuration.
//
// usage: RITUEEL_STATUS_KV_ID=<32 hex characters> site/scripts/deploy-config.mjs
//
// The file is site/wrangler.deploy.json (ignored by Git), beside wrangler.jsonc so that the
// relative paths in it (main, assets.directory) mean the same. The id is never printed.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const BINDING = 'STATUS';
const VALID = /^[0-9a-f]{32}$/;

// JSON from JSONC: drops // and /* */ comments outside strings, and trailing commas.
export function parseJsonc(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2) + 1;
      if (i === 0) throw new Error('an unterminated comment');
    } else {
      out += c;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
}

// The configuration with the id of the binding replaced. Throws on an id that is not one.
export function withKvId(config, id) {
  if (!VALID.test(id)) throw new Error('RITUEEL_STATUS_KV_ID is not a KV namespace id (32 lowercase hexadecimal characters)');
  const kv = (config.kv_namespaces ?? []).filter((n) => n.binding === BINDING);
  if (kv.length !== 1) throw new Error(`wrangler.jsonc declares ${kv.length} KV namespaces named ${BINDING}; it must declare exactly one`);
  kv[0].id = id;
  return config;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..');
  const id = (process.env.RITUEEL_STATUS_KV_ID ?? '').trim();
  if (!id) {
    console.error('deploy-config: RITUEEL_STATUS_KV_ID is not set');
    process.exit(1);
  }
  const config = withKvId(parseJsonc(readFileSync(join(dir, 'wrangler.jsonc'), 'utf8')), id);
  writeFileSync(join(dir, 'wrangler.deploy.json'), JSON.stringify(config, null, 1) + '\n', { mode: 0o600 });
  console.log(`deploy-config: wrote site/wrangler.deploy.json (the ${BINDING} KV id came from RITUEEL_STATUS_KV_ID)`);
}
