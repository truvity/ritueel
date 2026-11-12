import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { focusRowAfterRender } from './DataTable';

// The shell of the panel at the right of a list (Inventory, History).
//
// Focus rules this file owns:
//  - The panel is a region labelled by its heading (`h2#panel-title`).
//  - From 1440 px, choosing a line does not move the focus: the panel changes
//    beside the list. Nothing is announced (no live region).
//  - Below 1440 px the panel replaces the list. When it opens, the focus goes to
//    its heading, and the first element is the link `Back to the list`. That
//    link, and the browser's Back button, return to the list and put the focus
//    on the link of the row that was chosen (`focusRowAfterRender`).
//  - Escape with the focus inside the panel moves the focus to the chosen row's
//    link from 1440 px, and does what `Back to the list` does below that.

const WIDE = '(min-width:1440px)';

const isWide = () => typeof window.matchMedia === 'function' && window.matchMedia(WIDE).matches;

/**
 * `rowId` is the `data-row-id` of the chosen row. `backHref` is the address of
 * the list without the object.
 */
export function PanelFrame({ kind, title, backHref, rowId, children }: { kind: string; title: ReactNode; backHref: string; rowId?: string; children: ReactNode }) {
  const heading = useRef<HTMLHeadingElement>(null);

  // Below 1440 px the panel opens in place of the list: start at its heading.
  useEffect(() => {
    if (!isWide()) heading.current?.focus({ preventScroll: true });
  }, []);

  // The browser's Back button leaves the panel the same way the link does.
  useEffect(() => {
    const back = () => {
      if (!isWide()) focusRowAfterRender(rowId);
    };
    window.addEventListener('popstate', back);
    return () => window.removeEventListener('popstate', back);
  }, [rowId]);

  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    if (isWide()) {
      Array.from(document.querySelectorAll<HTMLElement>('[data-row-id]'))
        .find((el) => el.dataset.rowId === rowId)
        ?.querySelector<HTMLElement>('a')
        ?.focus();
    } else {
      focusRowAfterRender(rowId);
      window.location.hash = backHref;
    }
  };

  return (
    <aside role="region" aria-labelledby="panel-title" onKeyDown={onKeyDown} className="min-w-0 border border-rule bg-panel p-4">
      <a
        href={backHref}
        onClick={() => focusRowAfterRender(rowId)}
        className="mb-3 inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4 min-[1440px]:hidden"
      >
        Back to the list
      </a>
      <p className="font-mono text-xs tracking-wider text-dim uppercase">{kind}</p>
      <h2 id="panel-title" ref={heading} tabIndex={-1} className="mb-3 text-xl leading-tight font-semibold [overflow-wrap:anywhere] outline-none">
        {title}
      </h2>
      <div className="space-y-4 min-[1800px]:columns-2 min-[1800px]:gap-x-6 min-[1800px]:space-y-0">{children}</div>
    </aside>
  );
}

/** One section of a panel: an `h3` and its content. Sections do not break across the two columns of a wide screen. */
export function PanelSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 break-inside-avoid min-[1800px]:mb-4">
      <h3 className="mb-1.5 border-b border-line pb-1 text-base font-bold">{title}</h3>
      <div className="space-y-2 text-[0.9375rem]">{children}</div>
    </section>
  );
}
