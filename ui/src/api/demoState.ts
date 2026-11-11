import { useSyncExternalStore } from 'react';

// Demo mode only: which of the four states every read should show.
//   loaded   the bundle answers
//   empty    a new bundle that holds nothing yet
//   failed   the read fails (the page must not draw this as empty)
//   waiting  the program has not answered yet
// In the real program this stays "loaded" for ever and nothing changes it.
//
// A second switch chooses which example bundle the demo answers for. The real
// process serves one bundle, the one it was started on, so there is no such
// switch there and no call for it in the contract.

export type ViewState = 'loaded' | 'empty' | 'failed' | 'waiting';

export const VIEW_STATES: { value: ViewState; label: string; hint: string }[] = [
  { value: 'loaded', label: 'Loaded', hint: 'The bundle answers.' },
  { value: 'empty', label: 'Empty', hint: 'A new bundle that holds nothing yet.' },
  { value: 'failed', label: 'Failed read', hint: 'ritueel could not read the bundle.' },
  { value: 'waiting', label: 'Waiting', hint: 'ritueel has not answered yet.' },
];

export type DemoBundle = 'personal' | 'acme' | 'globex';

export const DEMO_BUNDLES: { value: DemoBundle; label: string; hint: string }[] = [
  { value: 'personal', label: 'personal', hint: 'A holder\'s own OpenPGP key, kept in an encrypted file.' },
  { value: 'acme', label: 'acme', hint: 'A company with two roots, acme/A and acme/B, on two root cards.' },
  { value: 'globex', label: 'globex', hint: 'A company with one cloud root, used from the workstation.' },
];

let currentBundle: DemoBundle = 'personal';
const bundleListeners = new Set<() => void>();

export function getBundle(): DemoBundle {
  return currentBundle;
}

/** Choose the example bundle. The hash goes back to Start, so no route names a card or a root the new bundle lacks. */
export function setBundle(next: DemoBundle): void {
  if (next === currentBundle) return;
  currentBundle = next;
  if (typeof window !== 'undefined' && window.location) window.location.hash = '#/start';
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
