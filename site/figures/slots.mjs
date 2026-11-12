// The one table of what the cards hold. The wide and the narrow drawing of a layout, and every
// other figure that names a slot, are functions of this file, so a change is made once and the two
// drawings cannot drift apart (site/test/figures.test.mjs compares their slot ids and row labels).
//
// What is decided (decision records 0002 and 0003; the owner's words of 2026-11-11):
//  - A root card is a YubiKey whose PIV application has 24 key slots, read as six rows of four.
//  - Row 1 (9a 9c 9d 9e) is the card's own jobs and holds no root. All four are drawn empty: three stay
//    empty, and 9d is tagged "spare key" because records 0002 (rule 24) and 0003 (rule 3) make a spare
//    key there only if the passkey way cannot be used (a fallback, never a held key in the picture).
//  - Rows 2 to 6 each hold the keys of one bundle, the same kind of key in the same column: X.509 root key,
//    OpenPGP primary, break-glass SSH CA key, empty. One row is kept free so that a replacement root
//    can be born beside the old one: four bundles on a pair of cards. Which row stays free is drawn as
//    row 6 only for the picture; the rule that the plan takes the lowest empty row is Proposed
//    (reference/cards), so no caption states it.
//  - A root has key A on one card and key B on the other (record 0003, rule 1), in the same row of the
//    second card as of the first; this card holds the A keys.
//  - The bundle names acme, personal and initech are made-up examples (the public repository holds no real name).

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

const KEY_COLUMNS = COLUMNS.map((c) => c.type);
const held = (n, label, accent = false) => ({
  n,
  label,
  sub: 'keys A',
  kind: 'bundle',
  accent,
  states: [accent ? 'acme' : 'held', accent ? 'acme' : 'held', accent ? 'acme' : 'held', 'empty'],
  types: [...KEY_COLUMNS.slice(0, 3), null],
});

/**
 * The rows of the root card. `states` is one of 'empty' | 'held' | 'acme' | 'free' for each of the
 * four slots; `types` names the key inside a held slot; `tags` is a short word written in an empty
 * slot. The accent marks the example bundle acme (row 2) and nothing else. The bundle names are made
 * up. A row with fewer kinds of key leaves its other cells empty (personal/A has an OpenPGP primary
 * only; initech/A has no SSH CA key). Which row is the free one is not fixed; row 6 is how the picture
 * draws it.
 */
export const ROOT_CARD_ROWS = [
  {
    n: 1,
    label: 'own jobs',
    sub: 'no root',
    kind: 'own',
    states: ['empty', 'empty', 'empty', 'empty'],
    types: [null, null, null, null],
    tags: ['empty', 'empty', 'spare key', 'never used'],
  },
  held(2, 'bundle acme', true),
  { ...held(3, 'bundle personal'), states: ['empty', 'held', 'empty', 'empty'], types: [null, 'OpenPGP', null, null] },
  { ...held(4, 'bundle initech'), states: ['held', 'held', 'empty', 'empty'], types: ['X.509', 'OpenPGP', null, null] },
  { n: 5, label: 'room', sub: 'for a new bundle', kind: 'room', states: ['empty', 'empty', 'empty', 'empty'] },
  { n: 6, label: 'kept free', sub: 'for a replacement', kind: 'free', states: ['free', 'free', 'free', 'free'] },
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

/**
 * The notes next to the rows, one list of lines each. Row 1's 9d is a conditional fallback of record
 * 0002, not an example: it is made only if the passkey way cannot be used.
 */
export const ROOT_CARD_NOTES = {
  own: ['Row 1', 'the card’s own jobs, no root.', '9d: a spare key to open key', 'files, only if the passkey', 'way cannot be used.'],
  bundles: ['Rows 2 to 5', 'the keys of one bundle each,', 'the same key kind in a column:', 'four bundles on a pair of cards.', 'Key B: same row, second card.', 'Fewer kinds leave cells empty.'],
  free: ['Row 6', 'kept free: a replacement root', 'is born here, beside the old one.'],
};

/** The pill under the card: the key file opens with a passkey (record 0002). */
export const ROOT_CARD_PASSKEY = ['FIDO2: a passkey opens key files', '(decided, not yet proven)'];

/** The day-to-day card: three applications, one set of keys per card (record 0008, rule 7; owner decision of 2026-11-11). */
export const DAY_CARD = {
  openpgp: [
    { name: 'signing', how: ['born on', 'the card'] },
    { name: 'decryption', how: ['made on', 'your computer,', 'loaded on card'] },
    { name: 'authentication', how: ['born on', 'the card'] },
  ],
};

/**
 * The server card of the example requester sluis: its own slot plan, "default card slot map, version
 * 1", read 2026-11-11 at https://sluis.id/reference/keys/#board-slot-plan (the same text is
 * docs/reference/keys.md, section "Board slot plan", the source's own heading, of https://github.com/truvity/sluis on main,
 * commit bc1b3729b840c8d4ea0309db4b420d0182c83ad9). Another requester's plan will differ. ritueel
 * lists a server card and only reads it; it checks no layout. `use` is the purpose, as the source names it.
 */
const SPARE = { state: 'empty', use: 'spare' };
export const SERVER_PLAN = {
  '9a': { state: 'held', use: 'token-signing' },
  '9c': { state: 'acme', use: 'x509-intermediate' },
  '9d': { state: 'held', use: 'wrapping' },
  '9e': { state: 'empty', use: 'unused' },
  '82': { state: 'held', use: 'ssh-user' },
  '83': { state: 'held', use: 'ssh-host' },
  '84': { state: 'held', use: 'audit-log' },
  '85': { state: 'held', use: 'release-signing' },
  '86': { state: 'held', use: 'workload-issuer' },
  '87': { state: 'held', use: 'pin-release' },
  '88': { state: 'held', use: 'token-signing-rs256' },
};

/** The 24 cells of the server card in PIV order: [{id, state, use, two}]. */
export function serverCardCells() {
  return PIV_ROWS.flat().map((id) => ({ id, ...(SERVER_PLAN[id] ?? SPARE) }));
}
