#!/usr/bin/env node
// Test vectors in testdata/*/v*/: every set has a manifest.json, and the manifest and the files
// agree. The vectors are fixtures that other products run, so a file that is missing (ignored by
// git, say) fails every case that names it, and a file nobody names is one nobody tests.
//
// A manifest with the member `root_list` is a root list set (docs/reference/root-list.md), with its
// own rules, listed at checkRootList below. For every other tracked testdata/<set>/v<N>/manifest.json,
// a hand-off set (docs/reference/hand-off-contract.md):
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
import { X509Certificate, createHash, createPublicKey, verify } from 'node:crypto';
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
  if (m.root_list !== undefined) {
    checkRootList(mpath, m, read, need);
  } else {
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
  }
  for (const t of tracked) {
    if (!t.startsWith(`${dir}/`) || t === mpath) continue;
    files++;
    if (!named.has(t.slice(dir.length + 1))) E(`${t}: not named by ${mpath}`);
  }
}
r.finish(manifests.length && files, 'vector files');

// A root list set:
//   - every file it names (each root's `certificate` and `openpgp`, each list's `files`, each
//     bundle's `file`) is tracked, and every tracked file under v<N>/ is named, as above;
//   - each root's `x509_spki_sha256` is the SHA-256 of its certificate's SubjectPublicKeyInfo, and
//     its `openpgp_fingerprint` the v4 fingerprint of the first packet of its OpenPGP file;
//   - each list is a `.json` and a `.jws`: the JWS header has `alg` ES384, `typ` root-list+json and a
//     `kid` that is the SPKI hash of its `x5c` certificate and of the root named as `signer`;
//   - the signature verifies over the `.json` bytes, except for a list that a case refuses with
//     `signature-invalid`, whose signature must not verify;
//   - case ids are unique, `held` and `candidate` name lists (or are null), a refused case has a
//     `reason`, a warned one a `warning`, an accepted one neither;
//   - each bundle starts with `# trust-sequence: N` for its `sequence`, and holds the certificates of
//     its `roots`, in that order.
function checkRootList(mpath, m, read, need) {
  const b64u = (s) => Buffer.from(s, 'base64url');
  const spkiHash = (cert) => sha(cert.publicKey.export({ type: 'spki', format: 'der' }));
  const roots = new Map();
  for (const root of m.roots ?? []) {
    roots.set(root.label, root);
    need(root.certificate, `root ${root.label}`);
    need(root.openpgp, `root ${root.label}`);
    try {
      if (spkiHash(new X509Certificate(read(root.certificate))) !== root.x509_spki_sha256) E(`${mpath}: root ${root.label}: x509_spki_sha256 is not the SPKI hash of ${root.certificate}`);
      if (pgpFingerprint(read(root.openpgp)) !== root.openpgp_fingerprint) E(`${mpath}: root ${root.label}: openpgp_fingerprint is not the fingerprint of ${root.openpgp}`);
    } catch (e) { E(`${mpath}: root ${root.label}: ${e.message}`); }
  }
  for (const label of m.initial_pins ?? []) if (!roots.has(label)) E(`${mpath}: initial pin ${label} is no root`);
  const cases = m.cases ?? [];
  const badSig = new Set(cases.filter((c) => c.reason === 'signature-invalid').map((c) => c.candidate));
  const lists = new Set();
  for (const l of m.lists ?? []) {
    if (lists.has(l.id)) E(`${mpath}: list id ${l.id} is used twice`);
    lists.add(l.id);
    for (const p of l.files ?? []) need(p, `list ${l.id}`);
    const json = (l.files ?? []).find((p) => p.endsWith('.json'));
    const sig = (l.files ?? []).find((p) => p.endsWith('.jws'));
    if (!json || !sig) { E(`${mpath}: list ${l.id} needs a .json and a .jws file`); continue; }
    if (!tracked.has(`${dirname(mpath)}/${json}`) || !tracked.has(`${dirname(mpath)}/${sig}`)) continue;
    try {
      const [h, middle, s] = read(sig).toString('ascii').split('.');
      if (middle !== '' || !s) throw new Error('not a detached compact JWS');
      const header = JSON.parse(b64u(h).toString('utf8'));
      const cert = new X509Certificate(Buffer.from(header.x5c?.[0] ?? '', 'base64'));
      if (header.alg !== 'ES384' || header.typ !== 'root-list+json') E(`${mpath}: list ${l.id}: the header is not alg ES384, typ root-list+json`);
      if (header.kid !== spkiHash(cert)) E(`${mpath}: list ${l.id}: kid is not the SPKI hash of the x5c certificate`);
      if (header.kid !== roots.get(l.signer)?.x509_spki_sha256) E(`${mpath}: list ${l.id}: kid is not the key of its signer ${l.signer}`);
      const input = Buffer.from(`${h}.${read(json).toString('base64url')}`, 'ascii');
      const ok = verify('sha384', input, { key: createPublicKey(cert.publicKey.export({ type: 'spki', format: 'pem' })), dsaEncoding: 'ieee-p1363' }, b64u(s));
      if (ok === badSig.has(l.id)) E(`${mpath}: list ${l.id}: the signature ${ok ? 'verifies, but a case expects signature-invalid' : 'does not verify'}`);
    } catch (e) { E(`${mpath}: list ${l.id}: ${e.message}`); }
  }
  const ids = new Set();
  for (const c of cases) {
    if (ids.has(c.id)) E(`${mpath}: case id ${c.id} is used twice`);
    ids.add(c.id);
    for (const k of ['held', 'candidate']) if (c[k] !== null && !lists.has(c[k])) E(`${mpath}: case ${c.id}: ${k} ${c[k]} is no list`);
    if (!['accept', 'refuse', 'warn'].includes(c.expect)) E(`${mpath}: case ${c.id}: expect is ${c.expect}`);
    if ((c.expect === 'refuse') !== Boolean(c.reason)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.reason ? 'with' : 'without'} a reason`);
    if ((c.expect === 'warn') !== Boolean(c.warning)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.warning ? 'with' : 'without'} a warning`);
  }
  if (!ids.size) E(`${mpath}: no root list cases`);
  for (const b of m.bundles ?? []) {
    need(b.file, `bundle ${b.id}`);
    if (!tracked.has(`${dirname(mpath)}/${b.file}`)) continue;
    const text = read(b.file).toString('utf8');
    if (!text.startsWith(`# trust-sequence: ${b.sequence}\n`)) E(`${mpath}: bundle ${b.id}: the first line is not "# trust-sequence: ${b.sequence}"`);
    const certs = text.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----\n/g) ?? [];
    const got = certs.map((pem) => spkiHash(new X509Certificate(pem)));
    const want = (b.roots ?? []).map((label) => roots.get(label)?.x509_spki_sha256);
    if (got.join() !== want.join()) E(`${mpath}: bundle ${b.id}: the certificates are not those of ${(b.roots ?? []).join(', ')}, in that order`);
  }
}

// The v4 fingerprint of the first packet of an OpenPGP file: SHA-1 over 0x99, a two-byte length and
// the key packet's body (RFC 9580, section 5.5.4.2).
function pgpFingerprint(buf) {
  if ((buf[0] & 0xc0) !== 0xc0) throw new Error('not a new-format OpenPGP packet');
  let len;
  let off;
  if (buf[1] < 192) [len, off] = [buf[1], 2];
  else if (buf[1] < 224) [len, off] = [((buf[1] - 192) << 8) + buf[2] + 192, 3];
  else if (buf[1] === 255) [len, off] = [buf.readUInt32BE(2), 6];
  else throw new Error('a partial-length key packet');
  const body = buf.subarray(off, off + len);
  const head = Buffer.from([0x99, len >> 8, len & 0xff]);
  return createHash('sha1').update(head).update(body).digest('hex');
}
