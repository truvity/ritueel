#!/usr/bin/env node
// The terms that ritueel shares with sluis (docs/shared-terms.yaml), offline.
//
// docs/shared-terms.yaml is one file with one wording, copied byte for byte into truvity/ritueel and
// truvity/sluis. A word has one owner, who changes it; the other repository copies the file after the
// owner's change has merged. This check keeps the copy in this repository honest, with no network:
//
//   - the file in docs/ equals the pinned copy of the other repository's file, byte for byte
//     (third_party/sluis/shared-terms.yaml);
//   - the pinned copy has the sha256 that third_party/sluis/PIN records, and the PIN has exactly the keys
//     source (truvity/sluis), commit (`pending` until sluis has merged its copy, then a full commit id)
//     and sha256;
//   - the file's own shape: schema 1, unique terms, an owner (ritueel or sluis), a status (decided or
//     proposed), `not` lines as strings, and `see` only as absolute https URLs on ritueel.id or sluis.id,
//     never a repository path, because the file lives in two repositories;
//   - for a word that ritueel owns, every `see` URL on ritueel.id is the address of a page that
//     site/published.txt lists (the address of a file is the site's own, addressOf in site/lib/published.mjs;
//     an anchor is not checked here, `just site-links` checks anchors in the built site).
//
// Whether sluis's main has moved on is not this check's: it never fetches. Bumping the pin is a change of the
// two files third_party/sluis/ and, when the owner's wording changed, docs/shared-terms.yaml together.
//
// The file is read by a small strict reader below (the repository's checks have no YAML package, and
// `just check-rules` installs none). It reads exactly the shape of this file and refuses anything else:
// comments, `schema: N`, `terms:`, entries `  - key: value`, fields `    key: value`, block lists of
// double-quoted strings, flow lists of double-quoted strings, and double-quoted or plain scalars.
//
// usage: tools/checks/shared-terms.mjs [repo-root]
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { reporter, repoRoot } from './lib.mjs';
import { addressOf } from '../../site/lib/published.mjs';

const root = repoRoot();
const { error, finish } = reporter('check-shared-terms');

const SHARED = 'docs/shared-terms.yaml';
const COPY = 'third_party/sluis/shared-terms.yaml';
const PIN = 'third_party/sluis/PIN';
const PUBLISHED = 'site/published.txt';
const OWNERS = ['ritueel', 'sluis'];
const STATUSES = ['decided', 'proposed'];
const FIELDS = ['term', 'definition', 'owner', 'status', 'not', 'see'];

const bytes = (rel) => (existsSync(join(root, rel)) ? readFileSync(join(root, rel)) : null);
const mine = bytes(SHARED);
const copy = bytes(COPY);
const pin = bytes(PIN);
const published = bytes(PUBLISHED);
for (const [rel, b] of [[SHARED, mine], [COPY, copy], [PIN, pin], [PUBLISHED, published]]) if (!b) error(`${rel} is missing`);
if (!mine || !copy || !pin || !published) finish(0, 'shared terms');

// ---- the pin and the vendored copy
const pinned = {};
for (const [i, line] of pin.toString('utf8').split('\n').entries()) {
  if (!line.trim() || line.startsWith('#')) continue;
  const m = /^([a-z0-9]+): (\S+)$/.exec(line);
  if (!m) { error(`${PIN}:${i + 1}: expected "source: ...", "commit: ..." or "sha256: ..."`); continue; }
  if (!['source', 'commit', 'sha256'].includes(m[1])) { error(`${PIN}:${i + 1}: unknown key ${m[1]}; the pin has source, commit and sha256`); continue; }
  if (m[1] in pinned) error(`${PIN}:${i + 1}: ${m[1]} is given twice`);
  pinned[m[1]] = m[2];
}
for (const k of ['source', 'commit', 'sha256']) if (!(k in pinned)) error(`${PIN}: ${k} is missing`);
if (pinned.source !== undefined && pinned.source !== 'truvity/sluis') error(`${PIN}: source must be truvity/sluis`);
if (pinned.commit !== undefined && !/^(pending|[0-9a-f]{40})$/.test(pinned.commit)) error(`${PIN}: commit must be "pending" or a full 40-digit commit id of ${pinned.source ?? 'the source'}`);
if (pinned.sha256 !== undefined && !/^[0-9a-f]{64}$/.test(pinned.sha256)) error(`${PIN}: sha256 must be 64 lower-case hexadecimal digits`);
const digest = createHash('sha256').update(copy).digest('hex');
if (pinned.sha256 && pinned.sha256 !== digest) error(`${COPY}: its sha256 is ${digest}, but ${PIN} pins ${pinned.sha256}`);
if (!mine.equals(copy)) {
  const a = mine.toString('utf8').split('\n');
  const b = copy.toString('utf8').split('\n');
  const at = a.findIndex((l, i) => l !== b[i]);
  const where = at === -1 ? `one ends at line ${Math.min(a.length, b.length)}` : `first difference at line ${at + 1}`;
  error(`${SHARED} differs from the pinned copy ${COPY} (${mine.length} and ${copy.length} bytes; ${where}); both repositories must hold the same bytes`);
}

// ---- the strict reader
// A double-quoted string at the start of `s`: [value, rest], or null. Only \" and \\ are escapes.
function quoted(s) {
  const m = /^"((?:[^"\\]|\\["\\])*)"/.exec(s);
  return m ? [m[1].replace(/\\(["\\])/g, '$1'), s.slice(m[0].length)] : null;
}
// A value after `key:`: a double-quoted string, a flow list of them, or a plain scalar.
function value(s) {
  if (s.startsWith('"')) {
    const q = quoted(s);
    if (!q || q[1] !== '') throw new Error('a double-quoted string must end the line (only \\" and \\\\ are escapes)');
    return q[0];
  }
  if (s.startsWith('[')) {
    const items = [];
    let rest = s.slice(1).trimStart();
    while (rest !== ']') {
      const q = quoted(rest);
      if (!q) throw new Error('a flow list holds double-quoted strings only');
      items.push(q[0]);
      rest = q[1].trimStart();
      if (rest.startsWith(',')) rest = rest.slice(1).trimStart();
      else if (rest !== ']') throw new Error('a flow list is "a", "b" between brackets');
    }
    return items;
  }
  if (/^[\s'{|>&*!%@`,#-]|^\]/.test(s) || /\s#|: |:$|\s$/.test(s)) throw new Error(`"${s}" is not a plain scalar this reader knows; use double quotes`);
  if (/^(true|false|null|yes|no|on|off|~|[-+]?[0-9][0-9._]*)$/i.test(s)) throw new Error(`"${s}" would be read by YAML as something other than a string; use double quotes`);
  return s;
}
function read(text) {
  const doc = {};
  let inTerms = false;
  let entry = null;
  let open = null; // the key of the entry whose block list is being read
  for (const [i, line] of text.split('\n').entries()) {
    const at = `${SHARED}:${i + 1}`;
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    try {
      if (line.includes('\t')) throw new Error('a tab; indent with spaces');
      let m;
      if ((m = /^([a-z]+):(?: (.+))?$/.exec(line))) {
        entry = null; open = null; inTerms = false;
        if (m[1] in doc) throw new Error(`${m[1]} is given twice`);
        if (m[1] === 'terms') {
          if (m[2] !== undefined) throw new Error('terms: is followed by its entries on the next lines');
          inTerms = true;
          doc.terms = [];
        } else if (m[1] === 'schema') {
          if (!/^[0-9]+$/.test(m[2] ?? '')) throw new Error('schema is a number');
          doc.schema = Number(m[2]);
        } else throw new Error(`unknown top-level key ${m[1]}`);
      } else if (!inTerms) throw new Error('expected a top-level key');
      else if ((m = /^  - ([a-z]+):(?: (.+))?$/.exec(line))) {
        entry = {}; doc.terms.push(entry); open = null;
        if (m[2] === undefined) throw new Error('an entry starts with its term');
        entry[m[1]] = value(m[2]);
      } else if ((m = /^    ([a-z]+):(?: (.+))?$/.exec(line))) {
        if (!entry) throw new Error('a field outside an entry');
        if (m[1] in entry) throw new Error(`${m[1]} is given twice`);
        if (m[2] === undefined) { entry[m[1]] = []; open = m[1]; } else { entry[m[1]] = value(m[2]); open = null; }
      } else if ((m = /^      - (.+)$/.exec(line))) {
        if (!open) throw new Error('a list item outside a list');
        const v = value(m[1]);
        if (typeof v !== 'string') throw new Error('a list item is a string');
        entry[open].push(v);
      } else throw new Error('a line of a shape this reader does not know');
    } catch (e) {
      error(`${at}: ${e.message}`);
      return null;
    }
  }
  return doc;
}

// ---- the shape of the file
const doc = read(mine.toString('utf8'));
const terms = doc && Array.isArray(doc.terms) ? doc.terms : [];
if (doc && doc.schema !== 1) error(`${SHARED}: schema must be 1`);

// the addresses of the pages that site/published.txt lists, in the site's own form (/learn/revoke/)
const pages = new Set(
  published.toString('utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map(addressOf),
);

const seen = new Set();
const SEE = /^https:\/\/(ritueel|sluis)\.id\/\S*$/;
for (const [i, t] of terms.entries()) {
  const at = `${SHARED}: terms[${i}]${typeof t.term === 'string' ? ` (${t.term})` : ''}`;
  if (typeof t.term !== 'string' || !t.term) { error(`${at}: term is missing`); continue; }
  if (seen.has(t.term.toLowerCase())) error(`${at}: the term is listed twice`);
  seen.add(t.term.toLowerCase());
  for (const k of Object.keys(t)) if (!FIELDS.includes(k)) error(`${at}: unknown field ${k}`);
  if (typeof t.definition !== 'string' || !t.definition) error(`${at}: definition is missing`);
  if (!OWNERS.includes(t.owner)) error(`${at}: owner must be one of ${OWNERS.join(', ')}`);
  if (!STATUSES.includes(t.status)) error(`${at}: status must be one of ${STATUSES.join(', ')}`);
  if ('not' in t && !(Array.isArray(t.not) && t.not.length && t.not.every((s) => typeof s === 'string' && s))) error(`${at}: not must be a non-empty list of strings`);
  if ('see' in t) {
    if (!(Array.isArray(t.see) && t.see.length && t.see.every((s) => typeof s === 'string'))) { error(`${at}: see must be a non-empty list of strings`); continue; }
    for (const u of t.see) {
      if (!SEE.test(u)) { error(`${at}: see "${u}" must be an absolute URL on ritueel.id or sluis.id, not a repository path`); continue; }
      if (t.owner === 'ritueel' && u.startsWith('https://ritueel.id/')) {
        const path = u.slice('https://ritueel.id'.length).replace(/[#?].*$/, '');
        if (!pages.has(path)) error(`${at}: see "${u}" is not a page that ${PUBLISHED} publishes (the address of a published page, with its trailing slash, is expected)`);
      }
    }
  }
}

finish(terms.length, 'shared terms');
