import { useSyncExternalStore } from 'react';
import { hrefOf, parseHash, routeForBundle, type BundleContents } from '../lib/route';

// Demo mode only: which of the four states every read should show.
//   loaded   the bundle answers
//   empty    a new bundle that holds nothing yet
//   failed   the read fails (the page must not draw this as empty)
//   waiting  the program has not answered yet
// In the real program this stays "loaded" for ever and nothing changes it.
//
// The bar at the top names the two switches "Page state" (this one) and
// "Example bundle" (the next). Waiting never ends by itself, on purpose: it is
// the screen the switch exists to show, and the page says so.
//
// A second switch chooses which example bundle the demo answers for. The
// contract has no call that names or selects a bundle (which bundle the process
// serves is not decided by the records, record 0010), so there is no such switch
// there and no call for it.
//
// A third control steps through the five scenes of the bundle acme (see
// api/scenes.ts). A scene is one moment of one change; the other two bundles
// have none. The scene chosen stays when the bundle is changed and changed back.

export type ViewState = 'loaded' | 'empty' | 'failed' | 'waiting';

export const VIEW_STATES: { value: ViewState; label: string; hint: string }[] = [
  { value: 'loaded', label: 'Loaded', hint: 'The bundle answers.' },
  { value: 'empty', label: 'Empty', hint: 'A new bundle that holds nothing yet.' },
  { value: 'failed', label: 'Failed read', hint: 'ritueel could not read the bundle.' },
  { value: 'waiting', label: 'Waiting', hint: 'ritueel has not answered yet. It stays so until you choose another page state.' },
];

export type DemoBundle = 'acme' | 'globex' | 'personal';

export const DEMO_BUNDLES: { value: DemoBundle; label: string; hint: string }[] = [
  { value: 'acme', label: 'acme', hint: 'A company with two root cards and one cloud key.' },
  { value: 'globex', label: 'globex', hint: 'A company with one cloud root only.' },
  { value: 'personal', label: 'personal', hint: 'One person: an OpenPGP key in a key file, and day-to-day cards.' },
];

let currentBundle: DemoBundle = 'acme';
const bundleListeners = new Set<() => void>();

export function getBundle(): DemoBundle {
  return currentBundle;
}

let contentsOfBundle: (() => BundleContents) | undefined;

/**
 * The demo transport (api/demo.ts) says what the open bundle holds, so that this
 * file never imports the fixtures: it is read by the pages of the real build too.
 * Until the transport is loaded (it loads on the first call) nothing says what a
 * bundle holds, and the address is left alone: a detail view the new bundle lacks
 * then shows its own "not in the inventory" page, which is better than dropping
 * a place that every bundle has.
 *
 * The Failed and Waiting page states use the contents of the loaded bundle, on
 * purpose: the detail screens then show the failure or the wait, and not a list.
 */
export function provideBundleContents(read: () => BundleContents): void {
  contentsOfBundle = read;
}

/** Keep the screen after the demo's data changed (bundle or scene): only a detail view the data cannot show falls back to its list. */
function keepScreen(): void {
  if (typeof window !== 'undefined' && window.location && contentsOfBundle) {
    try {
      const now = parseHash(window.location.hash);
      const to = routeForBundle(now, contentsOfBundle());
      if (to !== now) window.location.replace(hrefOf(to));
    } catch {
      // The contents could not be read: keep the address.
    }
  }
}

/**
 * Choose the example bundle. The page keeps the screen it is on. Only a detail
 * view the new bundle cannot show falls back to its list (routeForBundle), and
 * the address changes only then. The fallback replaces the history entry, so
 * Back never returns to an address the new bundle cannot show.
 */
export function setBundle(next: DemoBundle): void {
  if (next === currentBundle) return;
  currentBundle = next;
  keepScreen();
  bundleListeners.forEach((l) => l());
}

export function subscribeBundle(cb: () => void): () => void {
  bundleListeners.add(cb);
  return () => {
    bundleListeners.delete(cb);
  };
}

export function useBundle(): DemoBundle {
  return useSyncExternalStore(subscribeBundle, getBundle, getBundle);
}

let current: ViewState = 'loaded';
const listeners = new Set<() => void>();

export function getViewState(): ViewState {
  return current;
}

export function setViewState(next: ViewState): void {
  if (next === current) return;
  current = next;
  listeners.forEach((l) => l());
}

export function subscribeViewState(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

export function useViewState(): ViewState {
  return useSyncExternalStore(subscribeViewState, getViewState, getViewState);
}

/** Resolves the next time the state changes (a "waiting" answer ends here). */
export function whenViewStateChanges(): Promise<void> {
  return new Promise((resolve) => {
    const off = subscribeViewState(() => {
      off();
      resolve();
    });
  });
}

// ---- the scenes of acme ------------------------------------------------------

/** The first and the last scene. The text of each scene is in api/scenes.ts and fixtures/acme/scenes.json. */
export const FIRST_SCENE = 1;
export const LAST_SCENE = 5;

let currentScene = FIRST_SCENE;
const sceneListeners = new Set<() => void>();

export function getScene(): number {
  return currentScene;
}

/**
 * Choose a scene, 1 to 5. A value outside that range is refused: the scene does
 * not change and false comes back. The page keeps the screen, as for a bundle:
 * an object that the new scene lacks falls back to its list.
 */
export function setScene(next: number): boolean {
  if (!Number.isInteger(next) || next < FIRST_SCENE || next > LAST_SCENE) return false;
  if (next === currentScene) return true;
  currentScene = next;
  keepScreen();
  sceneListeners.forEach((l) => l());
  return true;
}

export function subscribeScene(cb: () => void): () => void {
  sceneListeners.add(cb);
  return () => {
    sceneListeners.delete(cb);
  };
}

export function useScene(): number {
  return useSyncExternalStore(subscribeScene, getScene, getScene);
}
