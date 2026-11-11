import { useSyncExternalStore } from 'react';

// Hash routes, because a static host has no fallback for deep links.
//   #/start  #/findings  #/roots  #/key/<root label>  #/cards[/<serial>]
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
      return { name: 'key', root: arg ?? 'personal' };
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
  key: (root = 'personal') => `#/key/${encodeURIComponent(root)}`,
  cards: (serial?: string) => (serial ? `#/cards/${encodeURIComponent(serial)}` : '#/cards'),
  history: (id?: string) => (id ? `#/history/${encodeURIComponent(id)}` : '#/history'),
  trust: () => '#/trust',
  plan: (goal?: string) => (goal ? `#/plan/${encodeURIComponent(goal)}` : '#/plan'),
};

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
