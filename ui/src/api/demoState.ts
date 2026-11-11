import { useSyncExternalStore } from 'react';

// Demo mode only: which of the four states every read should show.
//   loaded   the bundle answers
//   empty    a new bundle that holds nothing yet
//   failed   the read fails (the page must not draw this as empty)
//   waiting  the program has not answered yet
// In the real program this stays "loaded" for ever and nothing changes it.

export type ViewState = 'loaded' | 'empty' | 'failed' | 'waiting';

export const VIEW_STATES: { value: ViewState; label: string; hint: string }[] = [
  { value: 'loaded', label: 'Loaded', hint: 'The bundle answers.' },
  { value: 'empty', label: 'Empty', hint: 'A new bundle that holds nothing yet.' },
  { value: 'failed', label: 'Failed read', hint: 'ritueel could not read the bundle.' },
  { value: 'waiting', label: 'Waiting', hint: 'ritueel has not answered yet.' },
];

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
