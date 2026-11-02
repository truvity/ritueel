// The decisions of the status page's live script (src/scripts/status-live.ts) that need no
// browser, so that site/scripts/check-worker.mjs can run them in Node.

// Why an answer of /api/status/live/ is not taken, or null when it is. Only a 200 that says it is
// HTML counts: the 503 of a Worker that has no document yet, and anything a proxy put in its
// place, leave the snapshot where it is.
export function liveProblem(status: number, contentType: string | null): string | null {
  const type = contentType?.split(';')[0].trim().toLowerCase();
  if (status !== 200) return `HTTP ${status}`;
  if (type !== 'text/html') return `content type ${type ?? 'none'}`;
  return null;
}

// Whether each milestone's <details> stays open or closed as the reader left it: the live
// block's own default (the current milestone open) applies only to a group the reader never saw.
export function carryOpen(before: Map<string, boolean>, incoming: { group: string; open: boolean }[]): Map<string, boolean> {
  return new Map(incoming.map(({ group, open }) => [group, before.get(group) ?? open]));
}
