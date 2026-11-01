#!/usr/bin/env node
// Test vectors in testdata/*/v*/: every set has a manifest.json, and the manifest and the files
// agree. The vectors are fixtures that other products run, so a file that is missing (ignored by
// git, say) fails every case that names it, and a file nobody names is one nobody tests.
//
// A manifest with the member `root_list` is a root list set (docs/reference/root-list.md), one with
// `ssh_ca_keys` an SSH CA key list set (docs/reference/ssh-ca-key-list.md) and one with `crl` a CRL set
// (docs/reference/crl.md), each with its own rules, listed at checkRootList, checkSshCaKeys and checkCrl
// below. For every other tracked testdata/<set>/v<N>/manifest.json, a hand-off set
// (docs/reference/hand-off-contract.md):
//   - every file it names (in `pinned`, in each case's `files` and `kms_stub`, in each response's
//     `files`) is tracked by git;
//   - every tracked file under v<N>/ other than the manifest is named by it;
//   - case ids are unique, and each response's `request` is the id of a request case;
//   - a refused case or response has a `reason`, an accepted or installed one has none;
//   - for a request the manifest expects accepted, `request_sha256` in its proof is the digest of
//     its request (the DER of a CSR, or the bytes of a subkey file);
//   - every artifact a `result.json` lists is a file of that response, with that SHA-256;
//   - a response with `ssh_ca_key_list` names a list of the SSH CA key list set.
//
// usage: tools/checks/vectors.mjs [repo-root]
import { X509Certificate, createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
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

// The list ids of the SSH CA key list set, which an ssh-ca-key answer names.
let sshListIds;
function sshLists() {
  if (!sshListIds) {
    const p = join(root, 'testdata', 'ssh-ca-keys', 'v1', 'manifest.json');
    sshListIds = new Set(existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')).lists ?? []).map((l) => l.id) : []);
  }
  return sshListIds;
}

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
  } else if (m.ssh_ca_keys !== undefined) {
    checkSshCaKeys(mpath, m, read, need);
  } else if (m.crl !== undefined) {
    checkCrl(mpath, m, read, need);
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
      if (s.ssh_ca_key_list !== undefined && !sshLists().has(s.ssh_ca_key_list)) E(`${mpath}: response ${s.id}: ssh_ca_key_list ${s.ssh_ca_key_list} is no list of the SSH CA key list set`);
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

// An SSH CA key list set:
//   - every file it names (each root's `certificate`, each list's `files`, each `files` entry) is tracked,
//     and every tracked file under v<N>/ is named, as above;
//   - each root's `x509_spki_sha256` is the SHA-256 of its certificate's SubjectPublicKeyInfo;
//   - each list is a `.json` and a `.jws`: the JWS header has `alg` ES384, `typ` ssh-ca-keys+json (except
//     in a list a case refuses with `malformed`) and a `kid` that is the SPKI hash of its `x5c` certificate
//     and of the root named as `signer`; the signature verifies over the `.json` bytes, except for a list
//     that a case refuses with `signature-invalid`, whose signature must not verify;
//   - in every list a case does not refuse with `malformed`, `signature-invalid` or `version-unsupported`: the members are the ones of version 1, the
//     keys are sorted by name and unique, no key is listed twice, each `fingerprint` is the SHA-256 of its
//     `ssh_public_key`, each `ssh_public_key` is `ecdsa-sha2-nistp384`, and `root` is present exactly in the
//     entries named break-glass-<root>;
//   - case ids are unique, `held` and `candidate` name lists (or are null), a refused case has a `reason`,
//     a warned one a `warning`, an accepted one neither; and a case with `user_keys` names a file whose
//     lines are the candidate's keys with use user, under its trust sequence, when the case accepts it, and
//     differ from them when the case refuses it with `user-keys-mismatch`.
function checkSshCaKeys(mpath, m, read, need) {
  const b64u = (s) => Buffer.from(s, 'base64url');
  const spkiHash = (cert) => sha(cert.publicKey.export({ type: 'spki', format: 'der' }));
  const roots = new Map();
  for (const rt of m.roots ?? []) {
    roots.set(rt.label, rt);
    need(rt.certificate, `root ${rt.label}`);
    try {
      if (spkiHash(new X509Certificate(read(rt.certificate))) !== rt.x509_spki_sha256) E(`${mpath}: root ${rt.label}: x509_spki_sha256 is not the SPKI hash of ${rt.certificate}`);
    } catch (e) { E(`${mpath}: root ${rt.label}: ${e.message}`); }
  }
  const cases = m.cases ?? [];
  const refusedWith = (code) => new Set(cases.filter((c) => c.reason === code).map((c) => c.candidate));
  const badSig = refusedWith('signature-invalid');
  const malformed = refusedWith('malformed');
  const unchecked = new Set([...malformed, ...badSig, ...refusedWith('version-unsupported')]);   // content a case refuses on purpose
  const lists = new Map();
  for (const l of m.lists ?? []) {
    if (lists.has(l.id)) E(`${mpath}: list id ${l.id} is used twice`);
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
      if (header.alg !== 'ES384' || (header.typ !== 'ssh-ca-keys+json' && !malformed.has(l.id))) E(`${mpath}: list ${l.id}: the header is not alg ES384, typ ssh-ca-keys+json`);
      if (header.kid !== spkiHash(cert)) E(`${mpath}: list ${l.id}: kid is not the SPKI hash of the x5c certificate`);
      if (header.kid !== roots.get(l.signer)?.x509_spki_sha256) E(`${mpath}: list ${l.id}: kid is not the key of its signer ${l.signer}`);
      const input = Buffer.from(`${h}.${read(json).toString('base64url')}`, 'ascii');
      const ok = verify('sha384', input, { key: createPublicKey(cert.publicKey.export({ type: 'spki', format: 'pem' })), dsaEncoding: 'ieee-p1363' }, b64u(s));
      if (ok === badSig.has(l.id)) E(`${mpath}: list ${l.id}: the signature ${ok ? 'verifies, but a case expects signature-invalid' : 'does not verify'}`);
      const doc = JSON.parse(read(json).toString('utf8'));
      lists.set(l.id, doc);
      if (!unchecked.has(l.id)) checkSshList(mpath, l.id, doc);
    } catch (e) { E(`${mpath}: list ${l.id}: ${e.message}`); }
  }
  const ids = new Set();
  for (const c of cases) {
    if (ids.has(c.id)) E(`${mpath}: case id ${c.id} is used twice`);
    ids.add(c.id);
    for (const k of ['held', 'candidate']) if (c[k] !== null && !(m.lists ?? []).some((l) => l.id === c[k])) E(`${mpath}: case ${c.id}: ${k} ${c[k]} is no list`);
    for (const label of c.root_list?.roots ?? []) if (!roots.has(label)) E(`${mpath}: case ${c.id}: root ${label} is no root`);
    if (!['accept', 'refuse', 'warn'].includes(c.expect)) E(`${mpath}: case ${c.id}: expect is ${c.expect}`);
    if ((c.expect === 'refuse') !== Boolean(c.reason)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.reason ? 'with' : 'without'} a reason`);
    if ((c.expect === 'warn') !== Boolean(c.warning)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.warning ? 'with' : 'without'} a warning`);
    if (c.user_keys) {
      const f = (m.files ?? []).find((x) => x.id === c.user_keys || x.file === c.user_keys);
      const doc = lists.get(c.candidate);
      if (!f || !doc || !tracked.has(`${dirname(mpath)}/${f.file}`)) { E(`${mpath}: case ${c.id}: user_keys ${c.user_keys} is no named, tracked file, or the candidate is unreadable`); continue; }
      const want = `# trust-sequence: ${doc.sequence}\n${doc.keys.filter((k) => k.use === 'user').map((k) => `${k.ssh_public_key}\n`).join('')}`;
      const same = read(f.file).toString('utf8') === want;
      if (same === (c.reason === 'user-keys-mismatch')) E(`${mpath}: case ${c.id}: the file ${f.file} ${same ? 'is the' : 'is not the'} user keys of ${c.candidate}, but the case expects ${c.expect}${c.reason ? ` ${c.reason}` : ''}`);
    }
  }
  for (const f of m.files ?? []) need(f.file, `file ${f.id}`);
  if (!ids.size) E(`${mpath}: no SSH CA key list cases`);
}

function checkSshList(mpath, id, doc) {
  const where = `${mpath}: list ${id}`;
  const members = ['version', 'sequence', 'signed_at', 'expires_at', 'keys'];
  for (const k of Object.keys(doc)) if (!members.includes(k)) E(`${where}: unknown member ${k}`);
  for (const k of members) if (!(k in doc)) E(`${where}: missing member ${k}`);
  if (doc.version !== 1) E(`${where}: version is ${doc.version}`);
  const names = (doc.keys ?? []).map((k) => k.name);
  if (names.join('\n') !== [...names].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).join('\n')) E(`${where}: keys are not sorted by name`);
  if (new Set(names).size !== names.length) E(`${where}: a name is used twice`);
  const seen = new Set();
  for (const k of doc.keys ?? []) {
    const [alg, blob, ...rest] = (k.ssh_public_key ?? '').split(' ');
    if (alg !== 'ecdsa-sha2-nistp384' || !blob || rest.length) E(`${where}: ${k.name}: ssh_public_key is not "ecdsa-sha2-nistp384 <base64>"`);
    else if (k.fingerprint !== `SHA256:${createHash('sha256').update(Buffer.from(blob, 'base64')).digest('base64').replace(/=+$/, '')}`) E(`${where}: ${k.name}: fingerprint is not the SHA-256 of the key`);
    if (seen.has(k.ssh_public_key)) E(`${where}: ${k.name}: the key is listed twice`);
    seen.add(k.ssh_public_key);
    if (!['user', 'host'].includes(k.use)) E(`${where}: ${k.name}: use is ${k.use}`);
    if ((k.root !== undefined) !== /^break-glass-[A-Z]$/.test(k.name) || (k.root !== undefined && k.name !== `break-glass-${k.root}`)) E(`${where}: ${k.name}: root is present exactly in the entries named break-glass-<root>`);
  }
}

// A CRL set:
//   - every file it names (each root's `certificate`, each cert's `file`, each CRL's `file`) is tracked,
//     and every tracked file under v<N>/ is named, as above;
//   - each root's `x509_spki_sha256` is the SHA-256 of its certificate's SubjectPublicKeyInfo, and each
//     cert's `serial` is its serial number and its `issuer` the root whose key verifies it;
//   - each CRL parses (DER, RFC 5280 section 5) and its issuer is the subject of its `signer`; its
//     number, `this_update`, `next_update` and revoked serials are the manifest's; the signature verifies
//     with the signer's key, except for a CRL a case refuses with `signature-invalid`, whose must not;
//   - in every CRL a case does not refuse with `malformed`: version 2, `ecdsa-with-SHA384`, no critical
//     extension, and a CRL number;
//   - case ids are unique, `held` and `candidate` name CRLs (or are null), a refused case has a `reason`, a
//     warned one a `warning`, an accepted one neither; a revocation case names a cert and a CRL and
//     expects `revoked` exactly when the CRL lists the cert's serial, and `good` exactly when it does not.
function checkCrl(mpath, m, read, need) {
  const spkiHash = (cert) => sha(cert.publicKey.export({ type: 'spki', format: 'der' }));
  const roots = new Map();
  for (const rt of m.roots ?? []) {
    need(rt.certificate, `root ${rt.label}`);
    try {
      const cert = new X509Certificate(read(rt.certificate));
      roots.set(rt.label, { cert });
      if (spkiHash(cert) !== rt.x509_spki_sha256) E(`${mpath}: root ${rt.label}: x509_spki_sha256 is not the SPKI hash of ${rt.certificate}`);
    } catch (e) { E(`${mpath}: root ${rt.label}: ${e.message}`); }
  }
  const certs = new Map();
  for (const c of m.certs ?? []) {
    need(c.file, `cert ${c.id}`);
    try {
      const cert = new X509Certificate(read(c.file));
      certs.set(c.id, c);
      if (cert.serialNumber.replace(/^0+/, '').toLowerCase() !== c.serial) E(`${mpath}: cert ${c.id}: serial is not the certificate's`);
      if (!cert.verify(roots.get(c.issuer).cert.publicKey)) E(`${mpath}: cert ${c.id}: not issued by root ${c.issuer}`);
    } catch (e) { E(`${mpath}: cert ${c.id}: ${e.message}`); }
  }
  const cases = m.cases ?? [];
  const refusedWith = (code) => new Set(cases.filter((c) => c.reason === code).map((c) => c.candidate));
  const badSig = refusedWith('signature-invalid');
  const malformed = refusedWith('malformed');
  const listed = new Map();
  const ids = new Set();
  for (const c of m.crls ?? []) {
    if (ids.has(c.id)) E(`${mpath}: crl id ${c.id} is used twice`);
    ids.add(c.id);
    need(c.file, `crl ${c.id}`);
    if (!tracked.has(`${dirname(mpath)}/${c.file}`)) continue;
    try {
      const pem = read(c.file).toString('ascii');
      const body = /^-----BEGIN X509 CRL-----\n([A-Za-z0-9+/=\n]+)-----END X509 CRL-----\n$/.exec(pem);
      if (!body) throw new Error('not a PEM X509 CRL');
      const crl = parseCrl(Buffer.from(body[1].replace(/\n/g, ''), 'base64'));
      listed.set(c.id, new Set(crl.revoked));
      const signer = roots.get(c.signer);
      if (!signer) throw new Error(`signer ${c.signer} is no root`);
      if (crl.number !== BigInt(c.number)) E(`${mpath}: crl ${c.id}: the CRL number is ${crl.number}, not ${c.number}`);
      if (crl.thisUpdate !== c.this_update || crl.nextUpdate !== c.next_update) E(`${mpath}: crl ${c.id}: thisUpdate/nextUpdate are ${crl.thisUpdate}/${crl.nextUpdate}`);
      if (!badSig.has(c.id) && crl.revoked.join() !== c.revoked.map((x) => x.serial).join()) E(`${mpath}: crl ${c.id}: the revoked serials are not the manifest's`);
      if (!crl.issuer.equals(derSubject(signer.cert))) E(`${mpath}: crl ${c.id}: the issuer is not the subject of root ${c.signer}`);
      const hash = { '2a8648ce3d040303': 'sha384', '2a8648ce3d040302': 'sha256' }[crl.sigAlg];
      const ok = hash ? verify(hash, crl.tbs, { key: createPublicKey(signer.cert.publicKey.export({ type: 'spki', format: 'pem' })), dsaEncoding: 'der' }, crl.signature) : false;
      if (ok === badSig.has(c.id)) E(`${mpath}: crl ${c.id}: the signature ${ok ? 'verifies, but a case expects signature-invalid' : 'does not verify'}`);
      if (!malformed.has(c.id) && !(crl.version === 1 && crl.sigAlg === '2a8648ce3d040303' && !crl.critical && crl.number !== undefined)) E(`${mpath}: crl ${c.id}: not version 2, ecdsa-with-SHA384, with a number and no critical extension`);
    } catch (e) { E(`${mpath}: crl ${c.id}: ${e.message}`); }
  }
  const caseIds = new Set();
  for (const c of cases) {
    if (caseIds.has(c.id)) E(`${mpath}: case id ${c.id} is used twice`);
    caseIds.add(c.id);
    for (const k of ['held', 'candidate']) if (c[k] !== null && !ids.has(c[k])) E(`${mpath}: case ${c.id}: ${k} ${c[k]} is no crl`);
    for (const label of c.roots ?? []) if (!roots.has(label)) E(`${mpath}: case ${c.id}: root ${label} is no root`);
    if (!['accept', 'refuse', 'warn'].includes(c.expect)) E(`${mpath}: case ${c.id}: expect is ${c.expect}`);
    if ((c.expect === 'refuse') !== Boolean(c.reason)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.reason ? 'with' : 'without'} a reason`);
    if ((c.expect === 'warn') !== Boolean(c.warning)) E(`${mpath}: case ${c.id} expects ${c.expect} ${c.warning ? 'with' : 'without'} a warning`);
  }
  for (const v of m.revocation ?? []) {
    const cert = certs.get(v.cert);
    if (!cert || !listed.has(v.crl)) { E(`${mpath}: revocation ${v.id}: ${v.cert} or ${v.crl} is unknown`); continue; }
    if (listed.get(v.crl).has(cert.serial) !== (v.expect === 'revoked')) E(`${mpath}: revocation ${v.id}: ${v.crl} ${listed.get(v.crl).has(cert.serial) ? 'lists' : 'does not list'} ${v.cert}, but the case expects ${v.expect}`);
  }
  if (!caseIds.size || !(m.revocation ?? []).length) E(`${mpath}: no CRL cases or no revocation cases`);
}

// The subject of a certificate as DER, found by walking its TBSCertificate.
function derSubject(cert) {
  const raw = cert.raw;
  const tbs = children(raw, tlv(raw, 0))[0];
  const kids = children(raw, tbs);
  const at = kids[0].tag === 0xa0 ? 5 : 4;   // [0] version, serial, signature, issuer, validity, subject
  return raw.subarray(kids[at].start, kids[at].end);
}

// A minimal DER reader: just enough for a CRL (RFC 5280, section 5).
function tlv(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let hl = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hl = 2 + n;
  }
  return { tag, start: off, vstart: off + hl, end: off + hl + len };
}
function children(buf, t) {
  const out = [];
  for (let o = t.vstart; o < t.end;) { const c = tlv(buf, o); out.push(c); o = c.end; }
  return out;
}
function parseCrl(der) {
  const top = tlv(der, 0);
  const [tbs, alg, sig] = children(der, top);
  const kids = children(der, tbs);
  let i = 0;
  let version = 0;
  if (kids[i].tag === 0x02) { version = der[kids[i].vstart]; i++; }
  i++;                                           // the signature algorithm inside the TBS
  const issuer = der.subarray(kids[i].start, kids[i].end); i++;
  const time = (t) => {
    const s = der.subarray(t.vstart, t.end).toString('ascii');
    const [y, rest] = t.tag === 0x17 ? [(Number(s.slice(0, 2)) >= 50 ? '19' : '20') + s.slice(0, 2), s.slice(2)] : [s.slice(0, 4), s.slice(4)];
    return `${y}-${rest.slice(0, 2)}-${rest.slice(2, 4)}T${rest.slice(4, 6)}:${rest.slice(6, 8)}:${rest.slice(8, 10)}Z`;
  };
  const thisUpdate = time(kids[i]); i++;
  let nextUpdate;
  if (kids[i]?.tag === 0x17 || kids[i]?.tag === 0x18) { nextUpdate = time(kids[i]); i++; }
  const revoked = [];
  if (kids[i]?.tag === 0x30) {
    for (const e of children(der, kids[i])) {
      const serial = der.subarray(tlv(der, e.vstart).vstart, tlv(der, e.vstart).end);
      revoked.push(serial.toString('hex').replace(/^0+/, ''));
    }
    i++;
  }
  let number;
  let critical = false;
  if (kids[i]?.tag === 0xa0) {
    for (const ext of children(der, children(der, kids[i])[0])) {
      const [oid, ...rest] = children(der, ext);
      const isCritical = rest.length === 2 && der[rest[0].vstart] === 0xff;
      const value = rest[rest.length - 1];
      if (der.subarray(oid.vstart, oid.end).toString('hex') === '551d14') {
        const n = tlv(der, value.vstart);
        number = BigInt(`0x${der.subarray(n.vstart, n.end).toString('hex')}`);
      }
      if (isCritical) critical = true;
    }
  }
  const sigBits = der.subarray(sig.vstart + 1, sig.end);   // the first byte counts unused bits
  const algOid = der.subarray(tlv(der, alg.vstart).vstart, tlv(der, alg.vstart).end).toString('hex');
  return { version, issuer, thisUpdate, nextUpdate, revoked, number, critical, sigAlg: algOid, tbs: der.subarray(tbs.start, tbs.end), signature: sigBits };
}
