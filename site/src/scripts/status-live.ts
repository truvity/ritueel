// The live parts of the status page (/status/): swaps the build-time snapshot of each for the
// same markup rendered by the Worker from the data it keeps current (/api/status/live/). It does
// what an Astro server island does, from a bundled script, because Astro's own island loader is
// an inline script whose contents change on every build, which a hash-listed
// Content-Security-Policy (public/_headers) cannot allow. This file is a same-origin script, so
// the policy's `script-src 'self'` covers it.
//
// The fragment comes from this origin and holds no script. It is parsed into a <template>, so
// nothing in it runs. On any failure the snapshot stays, and the note above it says so.
import { carryOpen, liveProblem } from './status-live-core.ts';

const root = document.querySelector<HTMLElement>('[data-live-src]');
const note = root?.querySelector<HTMLElement>('[data-live-note]');

async function load(page: HTMLElement, src: string, notice: HTMLElement) {
  try {
    const res = await fetch(src, { headers: { accept: 'text/html' }, signal: AbortSignal.timeout(10_000) });
    const problem = liveProblem(res.status, res.headers.get('content-type'));
    if (problem) throw new Error(problem);
    const t = document.createElement('template');
    t.innerHTML = await res.text();
    if (!t.content.querySelector('.ps-body[data-mode="live"]')) throw new Error('not a live block');
    // Every part of the page needs its live counterpart before any is swapped: a half-live page
    // would mix two moments.
    const swaps = [...page.querySelectorAll<HTMLElement>('[data-live-part]')].map((part) => {
      const next = t.content.querySelector<HTMLElement>(`[data-live-part="${part.dataset.livePart}"]`);
      if (!next) throw new Error(`no ${part.dataset.livePart} part`);
      return { part, next };
    });
    if (swaps.length === 0) throw new Error('no live part on the page');
    for (const { part, next } of swaps) {
      const before = new Map([...part.querySelectorAll<HTMLDetailsElement>('details[data-group]')].map((d) => [d.dataset.group!, d.open]));
      const incoming = [...next.querySelectorAll<HTMLDetailsElement>('details[data-group]')];
      const open = carryOpen(before, incoming.map((d) => ({ group: d.dataset.group!, open: d.open })));
      for (const d of incoming) d.open = open.get(d.dataset.group!)!;
      part.replaceChildren(...next.childNodes);
    }
    page.dataset.live = 'live';
    notice.hidden = true;
  } catch {
    page.dataset.live = 'snapshot';
    notice.hidden = false;
  }
}

if (root && note && root.dataset.liveSrc) load(root, root.dataset.liveSrc, note);
