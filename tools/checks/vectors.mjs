#!/usr/bin/env node
// Test vectors in testdata/*/v*/: every set has a manifest.json, and the manifest and the files
// agree. The vectors are fixtures that other products run, so a file that is missing (ignored by
// git, say) fails every case that names it, and a file nobody names is one nobody tests.
//
// For each tracked testdata/<set>/v<N>/manifest.json:
//   - every file it names (in `pinned`, in each case's `files` and `kms_stub`, in each response's
//     `files`) is tracked by git;
//   - every tracked file under v<N>/ other than the manifest is named by it;
//   - case ids are unique, and each response's `request` is the id of a request case;
//   - a refused case or response has a `reason`, an accepted or installed one has none;
//   - for a request the manifest expects accepted, `request_sha256` in its proof is the digest of
//     its request (the DER of a CSR, or the bytes of a subkey file);
//   - every artifact a `result.json` lists is a file of that response, with that SHA-256.
//
// usage: tools/checks/vectors.mjs [repo-root]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { reporter, repoRoot, trackedFiles } from './lib.mjs';

const root = repoRoot();
const r = reporter('check-vectors');
const E = r.error;
const tracked = new Set(trackedFiles(root));
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const der = (pem) => Buffer.from(pem.toString('utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');

// Every string in `pinned` that looks like a relative file path.
const paths = (v) => (typeof v === 'string' ? (/^[\w.-]+\/[\w./-]+$/.test(v) ? [v] : [])
  : Array.isArray(v) ? v.flatMap(paths) : v && typeof v === 'object' ? Object.values(v).flatMap(paths) : []);

let files = 0;
const manifests = [...tracked].filter((p) => /^testdata\/[^/]+\/v\d+\/manifest\.json$/.test(p));
for (const mpath of manifests) {
  const dir = dirname(mpath);
  let m;
  try { m = JSON.parse(readFileSync(join(root, mpath), 'utf8')); } catch (e) { E(`${mpath}: not JSON (${e.message})`); continue; }
  const read = (p) => readFileSync(join(root, dir, p));
  const named = new Set();
  const need = (p, where) => {
    named.add(p);
    if (!tracked.has(`${dir}/${p}`)) E(`${mpath}: ${where} names ${p}, which git does not track`);
  };
  for (const p of paths(m.pinned ?? {})) need(p, 'pinned');
  const ids = new Set();
  for (const c of m.requests ?? []) {
    if (ids.has(c.id)) E(`${mpath}: request id ${c.id} is used twice`);
    ids.add(c.id);
    for (const p of c.files ?? []) need(p, `request ${c.id}`);
    if (c.kms_stub) need(c.kms_stub, `request ${c.id}`);
    if ((c.expect === 'refuse') !== Boolean(c.reason)) E(`${mpath}: request ${c.id} expects ${c.expect} ${c.reason ? 'with' : 'without'} a reason`);
    const proof = (c.files ?? []).find((p) => p.endsWith('.proof.json'));
    const req = (c.files ?? []).find((p) => !p.endsWith('.json'));
    if (c.expect === 'accept' && proof && req && tracked.has(`${dir}/${proof}`) && tracked.has(`${dir}/${req}`)) {
      const body = read(req);
      const want = sha(req.endsWith('.pem') ? der(body) : body);
      if (JSON.parse(read(proof)).request_sha256 !== want) E(`${mpath}: request ${c.id}: request_sha256 is not the digest of ${req}`);
    }
  }
  const rids = new Set();
  for (const s of m.responses ?? []) {
    if (rids.has(s.id)) E(`${mpath}: response id ${s.id} is used twice`);
    rids.add(s.id);
    if (!ids.has(s.request)) E(`${mpath}: response ${s.id} answers ${s.request}, which is no request case`);
    for (const p of s.files ?? []) need(p, `response ${s.id}`);
    if ((s.expect === 'refuse') !== Boolean(s.reason)) E(`${mpath}: response ${s.id} expects ${s.expect} ${s.reason ? 'with' : 'without'} a reason`);
    const result = (s.files ?? []).find((p) => p.endsWith('.result.json'));
    if (!result || !tracked.has(`${dir}/${result}`)) continue;
    for (const a of JSON.parse(read(result)).artifacts ?? []) {
      const p = (s.files ?? []).find((f) => basename(f) === a.name);
      if (!p) E(`${mpath}: response ${s.id}: artifact ${a.name} is not one of its files`);
      else if (tracked.has(`${dir}/${p}`) && sha(read(p)) !== a.sha256) E(`${mpath}: response ${s.id}: the SHA-256 of ${a.name} is not the one result.json lists`);
    }
  }
  if (!ids.size) E(`${mpath}: no request cases`);
  for (const t of tracked) {
    if (!t.startsWith(`${dir}/`) || t === mpath) continue;
    files++;
    if (!named.has(t.slice(dir.length + 1))) E(`${t}: not named by ${mpath}`);
  }
}
r.finish(manifests.length && files, 'vector files');
