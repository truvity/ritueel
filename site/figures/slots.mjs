// The one table of what the cards hold. The wide and the narrow drawing of a layout, and every
// other figure that names a slot, are functions of this file, so a change is made once and the two
// drawings cannot drift apart (site/test/figures.test.mjs compares their slot ids and row labels).
//
// What is decided (decision records 0015 and 0016; the owner's words of 2026-11-11):
//  - A root card is a YubiKey whose PIV application has 24 key slots, read as six rows of four.
//  - Row 1 (9a 9c 9d 9e) is the card's own jobs and holds no root. Three slots stay empty. What 9d
//    holds is an EXAMPLE, not a decision: a spare key for opening key files, for the case that the
//    passkey way cannot be used.
//  - Rows 2 to 6 hold one root each, the same kind of key in the same column: X.509 root key,
//    OpenPGP primary, break-glass SSH CA key, empty. One row is kept free so that a replacement root
//    can be born beside the old one: four bundles on a pair of cards.
//  - The partner root of the same bundle sits in the same row on the second card (acme/A on card
//    one, acme/B on card two).
//  - The bundle names acme and personal are made-up examples (the public repository holds no real name).

/** The four columns of rows 2 to 6: the kind of key, and what it is for. */
export const COLUMNS = [
  { type: 'X.509', sub: 'root key' },
  { type: 'OpenPGP', sub: 'primary' },
  { type: 'SSH CA', sub: 'break-glass' },
  { type: 'empty', sub: 'stays empty' },
];

/** The 24 PIV slot ids of a root card, six rows of four, in reading order. */
export const PIV_ROWS = [
  ['9a', '9c', '9d', '9e'],
  ['82', '83', '84', '85'],
  ['86', '87', '88', '89'],
  ['8a', '8b', '8c', '8d'],
  ['8e', '8f', '90', '91'],
  ['92', '93', '94', '95'],
];

const bundleRow = (n, name, accent) => ({
  n,
  label: name,
  sub: 'card one',
  kind: 'bundle',
  accent,
  states: [accent ? 'acme' : 'held', accent ? 'acme' : 'held', accent ? 'acme' : 'held', 'empty'],
});

/**
 * The rows of the root card. `states` is one of 'empty' | 'held' | 'acme' | 'free' for each of the
 * four slots; `types` names the key inside a held slot. The accent marks the example bundle acme.
 */
export const ROOT_CARD_ROWS = [
  { n: 1, label: 'own jobs', sub: 'no root', kind: 'own', states: ['empty', 'empty', 'held', 'empty'], types: [null, null, 'spare', null] },
  { ...bundleRow(2, 'personal/A', false), types: COLUMNS.map((c) => c.type) },
  { ...bundleRow(3, 'acme/A', true), types: COLUMNS.map((c) => c.type) },
  { n: 4, label: 'room', sub: 'for a bundle', kind: 'room', states: ['empty', 'empty', 'empty', 'empty'] },
  { n: 5, label: 'room', sub: 'for a bundle', kind: 'room', states: ['empty', 'empty', 'empty', 'empty'] },
  { n: 6, label: 'kept free', sub: 'replacement', kind: 'free', states: ['free', 'free', 'free', 'free'] },
];

/** Every cell of the root card with its slot id: [{id, row, col, state, type}]. */
export function rootCardCells() {
  const out = [];
  ROOT_CARD_ROWS.forEach((row, r) => {
    row.states.forEach((state, c) => {
      out.push({ id: PIV_ROWS[r][c], row: row.n, col: c, state, type: row.types?.[c] ?? null });
    });
  });
  return out;
}

/** The notes next to the rows. `example` marks a thing that is an illustration, not a decision. */
export const ROOT_CARD_NOTES = {
  own: { title: 'Row 1', text: "the card's own jobs, no root. 9d, a spare key, is an example." },
  bundle: { title: 'acme/A', text: 'card two holds acme/B in this row.' },
  four: { title: 'Rows 2 to 5', text: 'four bundles on a pair of cards.' },
  free: { title: 'Row 6', text: 'kept free: a replacement root is born here.' },
};

/** The day-to-day card: three applications, one set of keys per card. */
export const DAY_CARD_APPS = [
  { name: 'OpenPGP', holds: ['signing', 'decryption', 'authentication'], note: 'one set per card' },
  { name: 'FIDO2', holds: ['passkeys'], note: 'for signing in' },
  { name: 'PIV', holds: [], note: 'stays empty' },
];

/**
 * The server card stays plugged into a server of a requester system and signs for its services;
 * ritueel lists it and only reads it. Its slots follow the requester's own layout, so no slot names
 * are drawn here unless the requester publishes them (the example requester is
 * https://github.com/truvity/sluis).
 */
export const SERVER_CARD = { reads: 'ritueel lists it and only reads it', slots: 'follow the requester' };
