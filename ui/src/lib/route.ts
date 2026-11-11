import { useSyncExternalStore } from 'react';

// Hash routes, because a static host has no fallback for deep links.
//   #/start  #/findings  #/roots  #/key/<root label: A, B ...>  #/cards[/<serial>]
//   #/history[/<record id>]  #/trust  #/plan[/<goal>]
// An empty hash is Start. Any other hash that does not name a screen is
// "not found", and says so: it is never shown as another screen.

export type Route =
  | { name: 'start' }
  | { name: 'findings' }
  | { name: 'roots' }
  | { name: 'key'; root: string }
  | { name: 'cards'; serial?: string }
  | { name: 'history'; id?: string }
  | { name: 'trust' }
  | { name: 'plan'; goal?: string }
  | { name: 'notfound'; hash: string };

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, '');
  if (raw === '') return { name: 'start' };
  let parts: string[];
  try {
    parts = raw.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    return { name: 'notfound', hash };
  }
  const [head, arg, ...more] = parts;
  if (more.length > 0) return { name: 'notfound', hash };
  switch (head) {
    case 'start':
      return arg === undefined ? { name: 'start' } : { name: 'notfound', hash };
    case 'findings':
      return arg === undefined ? { name: 'findings' } : { name: 'notfound', hash };
    case 'roots':
      return arg === undefined ? { name: 'roots' } : { name: 'notfound', hash };
    case 'trust':
      return arg === undefined ? { name: 'trust' } : { name: 'notfound', hash };
    case 'key':
      return { name: 'key', root: arg ?? 'A' };
    case 'cards':
      return { name: 'cards', serial: arg };
    case 'history':
      return { name: 'history', id: arg };
    case 'plan':
      return { name: 'plan', goal: arg };
    default:
      return { name: 'notfound', hash };
  }
}

export const href = {
  start: () => '#/start',
  findings: () => '#/findings',
  roots: () => '#/roots',
  key: (root = 'A') => `#/key/${encodeURIComponent(root)}`,
  cards: (serial?: string) => (serial ? `#/cards/${encodeURIComponent(serial)}` : '#/cards'),
  history: (id?: string) => (id ? `#/history/${encodeURIComponent(id)}` : '#/history'),
  trust: () => '#/trust',
  plan: (goal?: string) => (goal ? `#/plan/${encodeURIComponent(goal)}` : '#/plan'),
};

/** The address of a route, the one `parseHash` reads back as the same route. */
export function hrefOf(r: Route): string {
  switch (r.name) {
    case 'start':
      return href.start();
    case 'findings':
      return href.findings();
    case 'roots':
      return href.roots();
    case 'key':
      return href.key(r.root);
    case 'cards':
      return href.cards(r.serial);
    case 'history':
      return href.history(r.id);
    case 'trust':
      return href.trust();
    case 'plan':
      return href.plan(r.goal);
    default:
      return r.hash;
  }
}

/**
 * What a bundle holds that an address can name: the labels of its roots, the
 * serials of its cards, the ids of its ledger records, and the goals (their
 * slugs in the address) it offers, that is, the ones that apply to it.
 */
export interface BundleContents {
  roots: readonly string[];
  cards: readonly string[];
  records: readonly string[];
  goals: readonly string[];
}

/**
 * The route to show when the demo changes its example bundle, from the route
 * shown now. A screen that every bundle has stays. A detail view stays only if
 * the new bundle has what it names, and otherwise falls back one step, to its
 * own list: a card to Cards, a record to History, a root's key to Roots, a
 * goal's wizard to the goals. The same route object comes back when nothing has
 * to change, so a caller can tell by identity. Pure: no window, no fixtures.
 */
export function routeForBundle(r: Route, has: BundleContents): Route {
  switch (r.name) {
    case 'key':
      return has.roots.includes(r.root) ? r : { name: 'roots' };
    case 'cards':
      return r.serial === undefined || has.cards.includes(r.serial) ? r : { name: 'cards' };
    case 'history':
      return r.id === undefined || has.records.includes(r.id) ? r : { name: 'history' };
    case 'plan':
      return r.goal === undefined || has.goals.includes(r.goal) ? r : { name: 'plan' };
    default:
      return r;
  }
}

/** The title of a screen, for the browser tab and the screen reader. */
export function routeTitle(r: Route): string {
  switch (r.name) {
    case 'start':
      return 'Start';
    case 'findings':
      return 'Findings';
    case 'roots':
      return 'Roots';
    case 'key':
      return 'Key';
    case 'cards':
      return r.serial ? 'Card' : 'Cards';
    case 'history':
      return r.id ? 'Ceremony' : 'History';
    case 'trust':
      return 'Trust files';
    case 'plan':
      return 'Make a plan';
    default:
      return 'Not found';
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
