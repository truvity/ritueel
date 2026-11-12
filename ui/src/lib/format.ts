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

/** The time of a read, as every screen writes it: 2026-11-24 09:00 UTC. Always UTC, so it reads the same everywhere. */
export function readTime(ts: Timestamp | undefined): string {
  const d = toDate(ts);
  return d ? `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC` : '-';
}
