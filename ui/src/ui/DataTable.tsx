import { Fragment, useEffect, useRef, type ReactNode } from 'react';
import useMediaQuery from '@mui/material/useMediaQuery';
import { safeString } from '../lib/safe';

// One table for the lists of the page (changes, inventory, history, trust files).
//
// Focus rules this file owns (the keyboard rules of Inventory and History):
//  - The first cell of a row holds one link, and Enter follows it. The link
//    text is the name of the object, never an act word. The chosen row is
//    marked by `aria-current="true"` on that link (`RowLink`), so it is a word
//    for a screen reader and not colour alone.
//  - Every row carries `data-row-id`. A panel that goes back to the list asks
//    for the focus on a row with `focusRowAfterRender(id)`; the table finds the
//    row by that attribute and focuses its first link.
//  - A `detail` line is text and `Cmd` controls only. It is not a row for the
//    keyboard: Tab visits its controls, the arrow keys do nothing special.

export interface Column<R> {
  key: string;
  header: string;
  /** Width in rem at 1440 px. A column without one takes the rest of the width. */
  width?: number;
  /** On a phone the cell stands under its header in the whole width, not beside it (a command). */
  block?: boolean;
  /** The cell. The first column holds the link of the row (use `RowLink`). */
  render: (row: R, ctx: { current: boolean }) => ReactNode;
}

export interface Group<R> {
  key: string;
  /** The content of the group header (a `th` with scope rowgroup). */
  header: ReactNode;
  /** How many columns the header spans. The rest of the header row is `aside`. Default: all. */
  span?: number;
  aside?: ReactNode;
  rows: R[];
}

let pendingFocus: string | undefined;

/** Ask for the focus on the link of a row, the next time a table draws. Used when a panel goes back to its list. */
export function focusRowAfterRender(id: string | undefined): void {
  pendingFocus = id;
}

/** The link of a row. `current` puts `aria-current="true"` on it. */
export function RowLink({ href, current, children }: { href: string; current?: boolean; children: ReactNode }) {
  return (
    <a href={href} aria-current={current ? 'true' : undefined} className="font-semibold text-accent underline underline-offset-4">
      {children}
    </a>
  );
}

export interface DataTableProps<R> {
  columns: Column<R>[];
  /** Plain rows, or ... */
  rows?: R[];
  /** ... rows in groups. */
  groups?: Group<R>[];
  /** Visually hidden. Says what the table is and how many lines it has. */
  caption: string;
  /** The key of the chosen row. */
  selectedKey?: string;
  rowKey: (row: R) => string;
  /** Data attributes for the row element: `data-object`, `data-key-fp`, `data-changes` and the like. */
  rowAttrs?: (row: R) => Record<`data-${string}`, string | undefined>;
  /** An optional second line under a row: text and `Cmd` controls only. */
  detail?: (row: R) => ReactNode;
}

function widthsOf<R>(columns: Column<R>[]): (string | undefined)[] {
  const sized = columns.every((c) => c.width !== undefined);
  const sum = columns.reduce((n, c) => n + (c.width ?? 0), 0);
  // All columns sized: they share the width in proportion, so the table never scrolls sideways.
  return columns.map((c) => (c.width === undefined ? undefined : sized ? `${((c.width / sum) * 100).toFixed(2)}%` : `${c.width}rem`));
}

function isEmptyCell(v: ReactNode): boolean {
  return v === null || v === undefined || v === false || v === '';
}

export function DataTable<R>({ columns, rows, groups, caption, selectedKey, rowKey, rowAttrs, detail }: DataTableProps<R>) {
  const wide = useMediaQuery('(min-width:640px)');
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (pendingFocus === undefined) return;
    const id = pendingFocus;
    pendingFocus = undefined;
    const row = Array.from(root.current?.querySelectorAll<HTMLElement>('[data-row-id]') ?? []).find((el) => el.dataset.rowId === id);
    row?.querySelector<HTMLElement>('a')?.focus();
  });

  // The key is data (an id, a path): it reaches the attribute only as plain ASCII, with anything else written as its U+XXXX code.
  const attrsOf = (row: R) => ({ 'data-row-id': safeString(rowKey(row), 100), ...(rowAttrs?.(row) ?? {}) });
  const chosen = (row: R) => selectedKey !== undefined && rowKey(row) === selectedKey;
  const lines = (groups ? groups.flatMap((g) => g.rows) : (rows ?? [])).length;
  const full = `${caption} ${lines} ${lines === 1 ? 'line' : 'lines'}.`;
  const widths = widthsOf(columns);

  if (!wide) {
    const item = (row: R) => {
      const current = chosen(row);
      const [first, ...rest] = columns;
      return (
        <li key={rowKey(row)} {...attrsOf(row)} className={`border-b border-line px-1 py-2 ${current ? 'bg-sunk' : ''}`}>
          <div className="min-h-11 text-base">{first.render(row, { current })}</div>
          {rest.map((c) => {
            const cell = c.render(row, { current });
            if (c.block && !isEmptyCell(cell))
              return (
                <div key={c.key} className="py-0.5 text-sm">
                  <span className="text-dim">{c.header}</span>
                  <div className="mt-0.5 min-w-0">{cell}</div>
                </div>
              );
            return isEmptyCell(cell) ? null : (
              <div key={c.key} className="flex gap-2 py-0.5 text-sm">
                <span className="w-24 shrink-0 text-dim">{c.header}</span>
                <div className="min-w-0 flex-1">{cell}</div>
              </div>
            );
          })}
          {detail?.(row) ? <div className="mt-1 text-sm">{detail(row)}</div> : null}
        </li>
      );
    };
    return (
      <div ref={root}>
        <p className="sr-only">{full}</p>
        <ul aria-label={caption} className="m-0 list-none p-0">
          {groups
            ? groups.map((g) => (
                <li key={g.key} className="list-none">
                  <div className="flex flex-wrap items-baseline justify-between gap-2 border-b-2 border-rule bg-sunk px-1 py-1.5 font-bold">
                    <div className="min-w-0">{g.header}</div>
                    {g.aside ? <div className="text-sm font-normal">{g.aside}</div> : null}
                  </div>
                  <ul className="m-0 list-none p-0">{g.rows.map(item)}</ul>
                </li>
              ))
            : (rows ?? []).map(item)}
        </ul>
      </div>
    );
  }

  const row = (r: R) => {
    const current = chosen(r);
    const [first, ...rest] = columns;
    const second = detail?.(r);
    return (
      <Fragment key={rowKey(r)}>
        <tr {...attrsOf(r)} className={`h-11 lg:h-8 ${second ? '' : 'border-b border-line'} align-top ${current ? 'bg-sunk' : ''}`}>
          <th scope="row" className="min-h-10 px-2 py-2 text-left align-top text-[0.875rem] font-normal lg:min-h-8 lg:py-1.5">
            {first.render(r, { current })}
          </th>
          {rest.map((c) => (
            <td key={c.key} className="px-2 py-2 align-top text-[0.875rem] lg:py-1.5">
              {c.render(r, { current })}
            </td>
          ))}
        </tr>
        {second ? (
          <tr className={`border-b border-line ${current ? 'bg-sunk' : ''}`}>
            <td colSpan={columns.length} className="px-2 pt-0 pb-2 text-[0.875rem]">
              {second}
            </td>
          </tr>
        ) : null}
      </Fragment>
    );
  };

  return (
    <div ref={root} className="min-w-0">
      <table className="w-full table-fixed border-collapse text-left">
        <caption className="sr-only">{full}</caption>
        <colgroup>
          {columns.map((c, i) => (
            <col key={c.key} style={widths[i] ? { width: widths[i] } : undefined} />
          ))}
        </colgroup>
        <thead>
          <tr className="border-b-2 border-rule">
            {columns.map((c) => (
              <th key={c.key} scope="col" className="px-2 py-1.5 text-left text-[0.8125rem] font-bold text-dim">
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        {groups ? (
          groups.map((g) => (
            <tbody key={g.key}>
              <tr className="border-b border-rule bg-sunk">
                <th scope="rowgroup" colSpan={g.span ?? columns.length} className="px-2 py-1.5 text-left align-top text-[0.875rem] font-bold">
                  {g.header}
                </th>
                {g.span !== undefined && g.span < columns.length ? (
                  <td colSpan={columns.length - g.span} className="px-2 py-1.5 align-top text-[0.875rem]">
                    {g.aside}
                  </td>
                ) : null}
              </tr>
              {g.rows.map(row)}
            </tbody>
          ))
        ) : (
          <tbody>
            {(rows ?? []).map(row)}
          </tbody>
        )}
      </table>
    </div>
  );
}
