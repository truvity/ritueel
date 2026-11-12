// The joins of the inventory: what the three views and the panel need from the
// lists of one GetInventory answer. Pure functions, no React, no window.
//
//  - By card: keys by the card they sit on, then the cloud keys, then the key
//    files.
//  - By root: for each root its keys, user IDs, delegations and, under a
//    delegation, its requests.
//  - By date: the certifications, soonest end first.
//
// The rule of marks: a change marks its `object` and every `involves` entry, in
// every view that lists that object. A group header (a card, a root) shows the
// roll-up: the changes on the group and on what it holds, each counted once.
//
// An object is named by "<slug>/<id>" (the slugs of lib/route.ts), the same
// string the demo gives to BundleContents. That string is data. Before it goes
// into an attribute it passes `domKey`.
import { ObjectKind, Store, type ObjectRef } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  CardKind,
  KeyRole,
  type Card,
  type Certification,
  type Change,
  type Delegation,
  type GetInventoryResponse,
  type Key,
  type Request,
  type Root,
  type UserId,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { href, objectSlug, type InventoryView, type ObjectSlug } from './route';
import { safeString } from './safe';

export type Inventory = GetInventoryResponse;
export type ObjectId = { kind: ObjectSlug; id: string };

/** "<slug>/<id>" for a kind the inventory lists; undefined for any other kind (a ceremony, a trust set, the bundle). */
export function objectKey(ref: Pick<ObjectRef, 'kind' | 'id'>): string | undefined {
  const slug = objectSlug(ref.kind);
  return slug ? `${slug}/${ref.id}` : undefined;
}

export const keyOfObject = (o: ObjectId): string => `${o.kind}/${o.id}`;

/** The same name as a plain string that is safe in an attribute: nothing outside printable ASCII reaches the markup. */
export function domKey(key: string): string {
  return safeString(key, 100);
}

/** Everything the views and the panel look up, built once for one answer. */
export interface InvIndex {
  inv: Inventory;
  cards: Map<string, Card>;
  roots: Map<string, Root>;
  keys: Map<string, Key>;
  userIds: Map<string, UserId>;
  delegations: Map<string, Delegation>;
  certs: Map<string, Certification>;
  requests: Map<string, Request>;
  /** The changes on an object, by `objectKey`. A change appears once for an object. */
  changes: Map<string, Change[]>;
}

export function buildIndex(inv: Inventory): InvIndex {
  const by = <T>(list: T[], id: (x: T) => string) => new Map(list.map((x) => [id(x), x]));
  const changes = new Map<string, Change[]>();
  for (const c of inv.changes) {
    const seen = new Set<string>();
    for (const ref of [c.object, ...c.involves]) {
      const k = ref ? objectKey(ref) : undefined;
      if (!k || seen.has(k)) continue;
      seen.add(k);
      changes.set(k, [...(changes.get(k) ?? []), c]);
    }
  }
  return {
    inv,
    cards: by(inv.cards, (c) => c.name),
    roots: by(inv.roots, (r) => r.name),
    keys: by(inv.keys, (k) => k.fingerprint),
    userIds: by(inv.userIds, (u) => u.id),
    delegations: by(inv.delegations, (d) => d.name),
    certs: by(inv.certifications, (c) => c.id),
    requests: by(inv.requests, (r) => r.stem),
    changes,
  };
}

/** The changes on any of these objects (names from `objectKey`), each once, in the order of the answer. */
export function changesOn(ix: InvIndex, keys: (string | undefined)[]): Change[] {
  const ids = new Set<string>();
  for (const k of keys) for (const c of (k ? ix.changes.get(k) : undefined) ?? []) ids.add(c.id);
  return ix.inv.changes.filter((c) => ids.has(c.id));
}

/** The attribute value `data-changes`: the ids of the changes, separated by spaces. Undefined when there is none. */
export function changeIds(changes: Change[]): string | undefined {
  return changes.length > 0 ? changes.map((c) => safeString(c.id, 40)).join(' ') : undefined;
}

/** Links to the objects of the inventory inside one view. A line of a table links to its own object in the view it is in. */
export function inventoryHrefs(view: InventoryView) {
  const to = (kind: ObjectSlug) => (id: string) => href.inventory(view, { kind, id });
  return {
    list: () => href.inventory(view),
    card: to('card'),
    root: to('root'),
    key: to('key'),
    userId: to('userid'),
    delegation: to('delegation'),
    certification: to('certification'),
    request: to('request'),
  };
}

const keyName = (k: Key) => objectKey({ kind: ObjectKind.KEY, id: k.fingerprint }) as string;
const cardName = (c: Card) => `card/${c.name}`;

// ---- By card ----------------------------------------------------------------------

export type CardLine = { kind: 'key'; key: Key } | { kind: 'none'; card: string };

/** A group of the By card view: a card, the cloud keys, the key files, or a card that the inventory does not list. */
export interface CardGroup {
  id: string;
  kind: 'card' | 'cloud' | 'files' | 'unlisted';
  /** The card (kind `card`) or the name of an unlisted card (kind `unlisted`). */
  card?: Card;
  name?: string;
  keys: Key[];
  lines: CardLine[];
}

const CARD_ORDER = [CardKind.ROOT, CardKind.DAY_TO_DAY, CardKind.REHEARSAL, CardKind.SERVER];

function slotOrder(card: Card): Map<string, number> {
  const ids = [...(card.piv?.rows ?? []).flatMap((r) => r.slots.map((s) => s.id)), ...(card.openpgp?.slots ?? []).map((s) => s.id)];
  return new Map(ids.map((id, i) => [id, i]));
}

/** Groups in this order: root cards, day-to-day cards, rehearsal cards, server cards (each by name), cloud keys, key files. */
export function cardGroups(ix: InvIndex): CardGroup[] {
  const { cards, keys } = ix.inv;
  const onCard = (k: Key, name: string) => (k.place?.store === Store.PIV || k.place?.store === Store.OPENPGP_CARD) && k.place.card === name;
  const rank = (c: Card) => {
    const i = CARD_ORDER.indexOf(c.kind);
    return i < 0 ? CARD_ORDER.length : i;
  };
  const sorted = [...cards].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
  const groups: CardGroup[] = sorted.map((card) => {
    const order = slotOrder(card);
    const mine = keys
      .filter((k) => onCard(k, card.name))
      .sort((a, b) => (order.get(a.place?.slot ?? '') ?? 999) - (order.get(b.place?.slot ?? '') ?? 999));
    return {
      id: cardName(card),
      kind: 'card',
      card,
      keys: mine,
      lines: mine.length > 0 ? mine.map((key) => ({ kind: 'key' as const, key })) : [{ kind: 'none' as const, card: card.name }],
    };
  });
  const known = new Set(cards.map((c) => c.name));
  const strays = new Map<string, Key[]>();
  for (const k of keys) {
    const p = k.place;
    if ((p?.store === Store.PIV || p?.store === Store.OPENPGP_CARD) && !known.has(p.card)) strays.set(p.card, [...(strays.get(p.card) ?? []), k]);
  }
  for (const [name, mine] of strays) groups.push({ id: `unlisted/${name}`, kind: 'unlisted', name, keys: mine, lines: mine.map((key) => ({ kind: 'key' as const, key })) });
  const cloud = keys.filter((k) => k.place?.store === Store.AWS_KMS);
  if (cloud.length > 0) groups.push({ id: 'cloud', kind: 'cloud', keys: cloud, lines: cloud.map((key) => ({ kind: 'key' as const, key })) });
  const files = keys.filter((k) => k.place?.store === Store.SOFTWARE);
  if (files.length > 0) groups.push({ id: 'files', kind: 'files', keys: files, lines: files.map((key) => ({ kind: 'key' as const, key })) });
  return groups;
}

/** The changes a group shows as its roll-up: on the card, on its keys, or involving them. */
export function cardRollup(ix: InvIndex, g: CardGroup): Change[] {
  return changesOn(ix, [g.card ? cardName(g.card) : undefined, ...g.keys.map(keyName)]);
}

// ---- By root ----------------------------------------------------------------------

export interface DelegationLine {
  delegation: Delegation;
  /** The key of the delegation; undefined while no key is certified. */
  key?: Key;
  certification?: Certification;
  requests: Request[];
}

export interface RootGroup {
  root: Root;
  /** The keys A, B, C of the root, in the order of the root's own list. */
  keys: Key[];
  userIds: UserId[];
  delegations: DelegationLine[];
}

export function rootGroups(ix: InvIndex): RootGroup[] {
  const { roots, keys, userIds, delegations, requests } = ix.inv;
  return roots.map((root) => {
    const order = new Map(root.keyIds.map((id, i) => [id, i]));
    const mine = keys
      .filter((k) => k.root === root.name && k.role !== KeyRole.DELEGATED_KEY)
      .sort((a, b) => (order.get(a.fingerprint) ?? 99) - (order.get(b.fingerprint) ?? 99) || a.label.localeCompare(b.label));
    const own = new Set(mine.map((k) => k.fingerprint));
    return {
      root,
      keys: mine,
      userIds: userIds.filter((u) => own.has(u.key)),
      delegations: delegations
        .filter((d) => d.root === root.name)
        .map((delegation) => ({
          delegation,
          key: delegation.key ? ix.keys.get(delegation.key) : undefined,
          certification: delegation.certification ? ix.certs.get(delegation.certification) : undefined,
          requests: requests.filter((r) => r.delegation === delegation.name),
        })),
    };
  });
}

/** The changes a root shows as its roll-up: on the root, its keys, user IDs, delegations (and their keys) and requests. */
export function rootRollup(ix: InvIndex, g: RootGroup): Change[] {
  return changesOn(ix, [
    `root/${g.root.name}`,
    ...g.keys.map(keyName),
    ...g.userIds.map((u) => `userid/${u.id}`),
    ...g.delegations.flatMap((d) => [`delegation/${d.delegation.name}`, d.key ? keyName(d.key) : undefined, ...d.requests.map((r) => `request/${r.stem}`)]),
  ]);
}

// ---- By date ----------------------------------------------------------------------

/** The certifications, soonest end first; the same end by id. */
export function dateRows(ix: InvIndex): Certification[] {
  const at = (c: Certification) => c.validUntil?.seconds ?? BigInt(Number.MAX_SAFE_INTEGER);
  return [...ix.inv.certifications].sort((a, b) => (at(a) < at(b) ? -1 : at(a) > at(b) ? 1 : a.id.localeCompare(b.id)));
}

// ---- the object of an address -----------------------------------------------------

/** The thing an address names, if the bundle has it. */
export type Found =
  | { kind: 'card'; value: Card }
  | { kind: 'root'; value: Root }
  | { kind: 'key'; value: Key }
  | { kind: 'userid'; value: UserId }
  | { kind: 'delegation'; value: Delegation }
  | { kind: 'certification'; value: Certification }
  | { kind: 'request'; value: Request };

export function lookup(ix: InvIndex, o: ObjectId): Found | undefined {
  switch (o.kind) {
    case 'card':
      return pick(ix.cards.get(o.id), 'card');
    case 'root':
      return pick(ix.roots.get(o.id), 'root');
    case 'key':
      return pick(ix.keys.get(o.id), 'key');
    case 'userid':
      return pick(ix.userIds.get(o.id), 'userid');
    case 'delegation':
      return pick(ix.delegations.get(o.id), 'delegation');
    case 'certification':
      return pick(ix.certs.get(o.id), 'certification');
    case 'request':
      return pick(ix.requests.get(o.id), 'request');
  }
}

function pick<K extends Found['kind']>(value: Extract<Found, { kind: K }>['value'] | undefined, kind: K): Found | undefined {
  return value === undefined ? undefined : ({ kind, value } as Found);
}

/** True when the view has a line for the object (a group header counts). */
export function listedIn(ix: InvIndex, view: InventoryView, o: ObjectId): boolean {
  if (!lookup(ix, o)) return false;
  switch (view) {
    case 'cards':
      return o.kind === 'card' || o.kind === 'key';
    case 'roots':
      if (o.kind === 'key') return ix.keys.get(o.id)?.role !== KeyRole.DELEGATED_KEY;
      return o.kind === 'root' || o.kind === 'userid' || o.kind === 'delegation' || o.kind === 'request';
    case 'dates':
      return o.kind === 'certification';
  }
}

/** The object the panel shows when the address names none and the screen is wide: the first line of the view that is an object. */
export function firstObject(ix: InvIndex, view: InventoryView): ObjectId | undefined {
  switch (view) {
    case 'cards': {
      for (const g of cardGroups(ix)) {
        if (g.card) return { kind: 'card', id: g.card.name };
        const key = g.keys[0];
        if (key) return { kind: 'key', id: key.fingerprint };
      }
      return undefined;
    }
    case 'roots': {
      const g = ix.inv.roots[0];
      return g ? { kind: 'root', id: g.name } : undefined;
    }
    case 'dates': {
      const c = dateRows(ix)[0];
      return c ? { kind: 'certification', id: c.id } : undefined;
    }
  }
}

/** The lines of a view, to tell an empty view from a full one. */
export function viewIsEmpty(ix: InvIndex, view: InventoryView): boolean {
  switch (view) {
    case 'cards':
      return ix.inv.cards.length === 0 && ix.inv.keys.length === 0;
    case 'roots':
      return ix.inv.roots.length === 0;
    case 'dates':
      return ix.inv.certifications.length === 0;
  }
}

export function inventoryIsEmpty(inv: Inventory): boolean {
  return (
    inv.cards.length + inv.roots.length + inv.keys.length + inv.userIds.length + inv.delegations.length + inv.certifications.length + inv.requests.length + inv.changes.length === 0
  );
}

/** A name that is safe as one word of a command: letters, digits, "." "_" and "-" only. Anything else is never put into a command. */
export function isCommandWord(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$/.test(s);
}
