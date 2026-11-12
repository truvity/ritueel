import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { readTime, toDate, ymd } from '../lib/format';

/**
 * "Read 2026-11-24 09:00 UTC": the time of the read, from the `readAt` of the
 * answer and never from the browser clock. A screen shows it when it has read
 * (loaded or empty), not while it waits or when the read failed.
 */
export function ReadTime({ ts, label = true }: { ts: Timestamp | undefined; label?: boolean }) {
  const d = toDate(ts);
  if (!d) return null;
  return (
    <>
      {label ? 'Read ' : null}
      <time dateTime={d.toISOString()} className="whitespace-nowrap">
        {readTime(ts)}
      </time>
    </>
  );
}

/**
 * A day, 2026-11-24, in UTC. It never breaks across two lines: a break
 * after a hyphen would leave "2026-11-" at the end of one line.
 */
export function Day({ ts }: { ts: Timestamp | undefined }) {
  const d = toDate(ts);
  if (!d) return <>-</>;
  return (
    <time dateTime={d.toISOString().slice(0, 10)} className="whitespace-nowrap">
      {ymd(ts)}
    </time>
  );
}
