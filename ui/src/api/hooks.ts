import { useCallback, useEffect, useRef, useState } from 'react';
import { ConnectError } from '@connectrpc/connect';
import { Severity, type Intention } from '../gen/ritueel/local/v1alpha1/common_pb';
import type { IntentionOption } from '../gen/ritueel/local/v1alpha1/plan_service_pb';
import { inspect, plans } from './client';
import { useBundle, useViewState } from './demoState';

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

export function useCall<T>(key: string, run: () => Promise<T>): Loaded<T> {
  const view = useViewState();
  const bundle = useBundle();
  const [tick, setTick] = useState(0);
  const [value, setValue] = useState<Loaded<T>>({ state: 'loading' });
  const latest = useRef(run);
  latest.current = run;
  const retry = useCallback(() => setTick((n) => n + 1), []);
  useEffect(() => {
    let live = true;
    setValue({ state: 'loading' });
    latest.current().then(
      (data) => live && setValue({ state: 'ready', data, reload: retry }),
      (e: unknown) => live && setValue({ state: 'error', message: messageOf(e), retry }),
    );
    return () => {
      live = false;
    };
  }, [key, view, bundle, tick, retry]);
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
/** The name of the bundle the process serves (acme), from the summary. Undefined until it is read. */
export function useBundleName(): string | undefined {
  const res = useSummary();
  return res.state === 'ready' ? res.data.bundle?.name || undefined : undefined;
}
export const useRoots = () => useCall('roots', () => inspect.listRoots({}));
export const useCards = () => useCall('cards', () => inspect.listCards({}));
export const useCeremonies = () => useCall('ceremonies', () => inspect.listCeremonies({}));
export const useTrustFiles = () => useCall('trust', () => inspect.listTrustFiles({}));
export const useIntentions = () => useCall('intentions', () => plans.listIntentions({}));

/** The wizard goals by intention, so a finding can say "not now" and why. Undefined until they are in. */
export function useGoalMap(): Map<Intention, IntentionOption> | undefined {
  const res = useIntentions();
  return res.state === 'ready' ? new Map(res.data.options.map((o) => [o.intention, o])) : undefined;
}
