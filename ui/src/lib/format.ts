import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { timestampDate } from '@bufbuild/protobuf/wkt';

export function toDate(ts: Timestamp | undefined): Date | undefined {
  return ts ? timestampDate(ts) : undefined;
}

/** 2026-11-11, in UTC, so the same day shows everywhere. */
export function ymd(ts: Timestamp | undefined): string {
  const d = toDate(ts);
  return d ? d.toISOString().slice(0, 10) : '-';
}

const DAY = 86_400_000;

/** Whole days from "now" (the as-of of the summary, never the browser clock). */
export function daysBetween(from: Timestamp | undefined, to: Timestamp | undefined): number | undefined {
  const a = toDate(from);
  const b = toDate(to);
  if (!a || !b) return undefined;
  const a0 = Date.UTC(a.getUTCFullYear(), a.getUTCMonth(), a.getUTCDate());
  const b0 = Date.UTC(b.getUTCFullYear(), b.getUTCMonth(), b.getUTCDate());
  return Math.round((b0 - a0) / DAY);
}

export function inDays(n: number | undefined): string {
  if (n === undefined) return '-';
  if (n === 0) return 'today';
  if (n < 0) return `${-n} days overdue`;
  return n === 1 ? 'in 1 day' : `in ${n} days`;
}

export function agoDays(n: number | undefined): string {
  if (n === undefined) return '-';
  if (n === 0) return 'today';
  return n === 1 ? '1 day ago' : `${n} days ago`;
}

export function plural(n: number, one: string, many = one + 's'): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Fractional year of a timestamp, for the validity chart. */
export function yearFraction(ts: Timestamp | undefined): number | undefined {
  const d = toDate(ts);
  if (!d) return undefined;
  const y = d.getUTCFullYear();
  const start = Date.UTC(y, 0, 1);
  const end = Date.UTC(y + 1, 0, 1);
  return y + (d.getTime() - start) / (end - start);
}
