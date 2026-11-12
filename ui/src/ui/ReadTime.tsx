import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { readTime, toDate } from '../lib/format';

/**
 * "Read 2026-11-24 09:00 UTC": the time of the read, from the `readAt` of the
 * answer and never from the browser clock. A screen shows it when it has read
 * (loaded or empty), not while it waits or when the read failed.
 */
export function ReadTime({ ts }: { ts: Timestamp | undefined }) {
  const d = toDate(ts);
  if (!d) return null;
  return (
    <>
      Read <time dateTime={d.toISOString()}>{readTime(ts)}</time>
    </>
  );
}
