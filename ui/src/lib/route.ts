import { useSyncExternalStore } from 'react';
import { ObjectKind, type ObjectRef } from '../gen/ritueel/local/v1alpha1/common_pb';
import { ChangeKind, type Change } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';

// Hash routes, because a static host has no fallback for deep links.
//   #/todo  #/todo/findings
//   #/inventory[/cards|roots|dates[/<kind>/<id>]]
//   #/history[/<ceremony>]  #/trust
// An empty hash is To do. Any other hash that does not name a screen is
// "not found", and says so: it is never shown as another screen. That holds
// for the addresses of the older page too (#/start, #/findings, #/roots,
// #/key/A, #/cards, #/plan).

export type InventoryView = 'cards' | 'roots' | 'dates';

/** The kinds of object the inventory panel shows, as they are written in an address. */
export type ObjectSlug = 'card' | 'root' | 'key' | 'userid' | 'delegation' | 'certification' | 'request';

export type Route =
  | { name: 'todo'; tab: 'changes' | 'findings' }
  | { name: 'inventory'; view: InventoryView; object?: { kind: ObjectSlug; id: string } }
  | { name: 'history'; id?: string }
  | { name: 'trust' }
  | { name: 'notfound'; hash: string };

const VIEWS: readonly InventoryView[] = ['cards', 'roots', 'dates'];
const SLUGS: readonly ObjectSlug[] = ['card', 'root', 'key', 'userid', 'delegation', 'certification', 'request'];

const isView = (s: string | undefined): s is InventoryView => VIEWS.includes(s as InventoryView);
const isSlug = (s: string | undefined): s is ObjectSlug => SLUGS.includes(s as ObjectSlug);

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, '');
  if (raw === '') return { name: 'todo', tab: 'changes' };
  let parts: string[];
  try {
    parts = raw.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    return { name: 'notfound', hash };
  }
  const notfound: Route = { name: 'notfound', hash };
  const [head, a, b, c, ...more] = parts;
  if (more.length > 0) return notfound;
  switch (head) {
    case 'todo':
      if (b !== undefined) return notfound;
      if (a === undefined) return { name: 'todo', tab: 'changes' };
      return a === 'findings' ? { name: 'todo', tab: 'findings' } : notfound;
    case 'inventory': {
      if (a === undefined) return { name: 'inventory', view: 'cards' };
      if (!isView(a)) return notfound;
      if (b === undefined) return c === undefined ? { name: 'inventory', view: a } : notfound;
      if (!isSlug(b) || c === undefined) return notfound;
      return { name: 'inventory', view: a, object: { kind: b, id: c } };
    }
    case 'history':
      return b === undefined && c === undefined ? { name: 'history', id: a } : notfound;
    case 'trust':
      return a === undefined ? { name: 'trust' } : notfound;
    default:
      return notfound;
  }
}

export const href = {
  todo: () => '#/todo',
  findings: () => '#/todo/findings',
  inventory: (view: InventoryView = 'cards', object?: { kind: ObjectSlug; id: string }) =>
    object ? `#/inventory/${view}/${object.kind}/${encodeURIComponent(object.id)}` : `#/inventory/${view}`,
  history: (id?: string) => (id ? `#/history/${encodeURIComponent(id)}` : '#/history'),
  trust: () => '#/trust',
};

/** The address of a route, the one `parseHash` reads back as the same route. */
export function hrefOf(r: Route): string {
  switch (r.name) {
    case 'todo':
      return r.tab === 'findings' ? href.findings() : href.todo();
    case 'inventory':
      return href.inventory(r.view, r.object);
    case 'history':
      return href.history(r.id);
    case 'trust':
      return href.trust();
    default:
      return r.hash;
  }
}

/**
 * The word of an object kind in an address, for the kinds the inventory panel
 * shows. Undefined for the others (the bundle, a ceremony, a trust set, a trust
 * file): they have their own screens or none.
 */
export function objectSlug(kind: ObjectKind): ObjectSlug | undefined {
  switch (kind) {
    case ObjectKind.CARD:
      return 'card';
    case ObjectKind.ROOT:
      return 'root';
    case ObjectKind.KEY:
      return 'key';
    case ObjectKind.USER_ID:
      return 'userid';
    case ObjectKind.DELEGATION:
      return 'delegation';
    case ObjectKind.CERTIFICATION:
      return 'certification';
    case ObjectKind.REQUEST:
      return 'request';
    default:
      return undefined;
  }
}

/**
 * The address that shows an object: a card in By card, a certification in By
 * date, any other object of the panel in By root. A ceremony opens History, a
 * trust set or a trust file opens Trust set, the bundle opens To do.
 */
export function hrefForObject(ref: Pick<ObjectRef, 'kind' | 'id'>): string {
  switch (ref.kind) {
    case ObjectKind.CEREMONY:
      return href.history(ref.id);
    case ObjectKind.TRUST_SET:
    case ObjectKind.TRUST_FILE:
      return href.trust();
    case ObjectKind.CARD:
      return href.inventory('cards', { kind: 'card', id: ref.id });
    case ObjectKind.CERTIFICATION:
      return href.inventory('dates', { kind: 'certification', id: ref.id });
    default: {
      const kind = objectSlug(ref.kind);
      return kind ? href.inventory('roots', { kind, id: ref.id }) : href.todo();
    }
  }
}

/**
 * The address a line of "not applied yet" opens. A renewal that has a
 * certification in `involves` opens that certification in By date, where the
 * end is. Any other change opens its own object.
 */
export function hrefForChange(change: Pick<Change, 'kind' | 'object' | 'involves'>): string {
  if (change.kind === ChangeKind.RENEW) {
    const cert = change.involves.find((o) => o.kind === ObjectKind.CERTIFICATION);
    if (cert) return hrefForObject(cert);
  }
  return change.object ? hrefForObject(change.object) : href.todo();
}

/**
 * What a bundle holds that an address can name. `objects` are "<slug>/<id>"
 * with the slugs of ObjectSlug and the id as the contract gives it (not
 * escaped); `ceremonies` are the names of the ceremony folders.
 */
export interface BundleContents {
  objects: string[];
  ceremonies: string[];
}

/**
 * The route to show when the demo changes its example bundle or its scene, from
 * the route shown now. A screen that every bundle has stays. A detail view
 * stays only if the new bundle (or scene) has what it names, and otherwise
 * falls back to its own list, in the same view: an Inventory object drops, a
 * ceremony drops to History. The same route object comes back when nothing has
 * to change, so a caller can tell by identity. Pure: no window, no fixtures.
 */
export function routeForBundle(r: Route, has: BundleContents): Route {
  switch (r.name) {
    case 'inventory':
      return r.object === undefined || has.objects.includes(`${r.object.kind}/${r.object.id}`) ? r : { name: 'inventory', view: r.view };
    case 'history':
      return r.id === undefined || has.ceremonies.includes(r.id) ? r : { name: 'history' };
    default:
      return r;
  }
}

/** The title of a screen, for the browser tab and the screen reader. */
export function routeTitle(r: Route): string {
  switch (r.name) {
    case 'todo':
      return r.tab === 'findings' ? 'Findings' : 'To do';
    case 'inventory':
      return r.view === 'cards' ? 'Inventory, by card' : r.view === 'roots' ? 'Inventory, by root' : 'Inventory, by date';
    case 'history':
      return 'History';
    case 'trust':
      return 'Trust set';
    default:
      return 'No such screen';
  }
}

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb);
  return () => window.removeEventListener('hashchange', cb);
}

export function useHash(): string {
  return useSyncExternalStore(subscribe, () => window.location.hash);
}

export function useRoute(): Route {
  return parseHash(useHash());
}

/** A link a visitor follows to the site (not a fetch). */
export function siteUrl(path = ''): string {
  const base = __SITE_URL__.endsWith('/') ? __SITE_URL__ : __SITE_URL__ + '/';
  return base + path.replace(/^\//, '');
}
