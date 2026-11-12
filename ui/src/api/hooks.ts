import { useCallback, useEffect, useRef, useState } from 'react';
import { ConnectError } from '@connectrpc/connect';
import { Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import { inspect } from './client';
import { useBundle, useScene, useViewState } from './demoState';

/**
 * What a read can be. "error" is its own state: a read that failed is never
 * drawn as an empty answer, because the page does not know what is there.
 */
export type Loaded<T> =
  | { state: 'loading' }
  | { state: 'error'; message: string; retry: () => void }
  | { state: 'ready'; data: T; reload: () => void };

export function messageOf(e: unknown): string {
  if (e instanceof ConnectError) return e.rawMessage || e.message;
  return e instanceof Error ? e.message : 'unknown error';
}

/** A focus that comes this soon after a read starts no new read (milliseconds). */
const FOCUS_QUIET_MS = 1000;

/**
 * One read. The page reads when a screen opens and when the window gets the
 * focus; there is no timer. A focus within one second of the last read starts
 * no read (the clock is `performance.now()`, not a timer). While it reads again
 * the data stay on screen: the state is "loading" only for the first read and
 * for a change of key, bundle, scene or page state. A read again that fails
 * turns the screen into "error", because the page then does not know what is
 * there.
 */
export function useCall<T>(key: string, run: () => Promise<T>): Loaded<T> {
  const view = useViewState();
  const bundle = useBundle();
  const scene = useScene();
  const [tick, setTick] = useState(0);
  const [value, setValue] = useState<Loaded<T>>({ state: 'loading' });
  const latest = useRef(run);
  latest.current = run;
  const lastRead = useRef(Number.NEGATIVE_INFINITY);
  const seq = useRef(0);
  const retry = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    const mine = ++seq.current;
    lastRead.current = performance.now();
    setValue({ state: 'loading' });
    latest.current().then(
      (data) => live && mine === seq.current && setValue({ state: 'ready', data, reload: retry }),
      (e: unknown) => live && mine === seq.current && setValue({ state: 'error', message: messageOf(e), retry }),
    );
    return () => {
      live = false;
    };
  }, [key, view, bundle, scene, tick, retry]);

  useEffect(() => {
    let live = true;
    const onFocus = () => {
      const now = performance.now();
      if (now - lastRead.current < FOCUS_QUIET_MS) return;
      lastRead.current = now;
      const mine = ++seq.current;
      latest.current().then(
        (data) => live && mine === seq.current && setValue({ state: 'ready', data, reload: retry }),
        (e: unknown) => live && mine === seq.current && setValue({ state: 'error', message: messageOf(e), retry }),
      );
    };
    window.addEventListener('focus', onFocus);
    return () => {
      live = false;
      window.removeEventListener('focus', onFocus);
    };
  }, [key, view, bundle, scene, retry]);

  return value;
}

/** Several reads as one: loading until all are in, an error if any failed. */
export function combine<A, B>(a: Loaded<A>, b: Loaded<B>): Loaded<[A, B]>;
export function combine<A, B, C>(a: Loaded<A>, b: Loaded<B>, c: Loaded<C>): Loaded<[A, B, C]>;
export function combine(...all: Loaded<unknown>[]): Loaded<unknown[]> {
  const failed = all.find((x) => x.state === 'error');
  if (failed && failed.state === 'error') return failed;
  if (all.some((x) => x.state === 'loading')) return { state: 'loading' };
  const ready = all as Extract<Loaded<unknown>, { state: 'ready' }>[];
  return { state: 'ready', data: ready.map((r) => r.data), reload: () => ready.forEach((r) => r.reload()) };
}

export const useSummary = () => useCall('summary', () => inspect.getSummary({}));
export const useFindings = (min: Severity = Severity.UNSPECIFIED) => useCall(`findings:${min}`, () => inspect.listFindings({ minSeverity: min }));
export const useInventory = () => useCall('inventory', () => inspect.getInventory({}));
export const useCeremonies = () => useCall('ceremonies', () => inspect.listCeremonies({}));
export const useTrustFiles = () => useCall('trust', () => inspect.listTrustFiles({}));

/** The name of the bundle the process serves (acme), from the summary. Undefined until it is read. */
export function useBundleName(): string | undefined {
  const res = useSummary();
  return res.state === 'ready' ? res.data.bundle?.name || undefined : undefined;
}
