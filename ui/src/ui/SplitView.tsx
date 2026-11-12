import type { CSSProperties, ReactNode } from 'react';

/**
 * The grid of the list screens (layout numbers of the page, measured at 1440 by
 * 900 and 1920 by 970).
 *
 *  - below 1440 px: one column. `right` shows alone when `panelOpen`, and
 *    `list` shows alone when it is not. The panel replaces the list.
 *  - from 1440 px: the list and `right` side by side. The right column is
 *    `panelRem` wide (30 rem unless the view asks for less), the gap 1.5 rem, and
 *    the tops align. A list with many columns asks for less, because its panel is short.
 *  - from 1800 px: the right column is 40 rem and the list is at most 62 rem,
 *    so nothing is unused at the sides of a wide screen.
 *
 * The element that is hidden is `display: none`, so it is out of the tab order
 * and out of the reading order. `rightLabel` names the right column when it is
 * a landmark of its own; a panel names itself (`PanelFrame`) and passes none.
 */
export const SPLIT_COLUMNS = 'min-[1440px]:grid-cols-[minmax(0,1fr)_var(--panel)] min-[1800px]:grid-cols-[minmax(0,62rem)_40rem]';

export function SplitView({ list, right, rightLabel, panelOpen = false, panelRem = 30 }: { list: ReactNode; right: ReactNode; rightLabel?: string; panelOpen?: boolean; panelRem?: number }) {
  const rightClass = `min-w-0 ${panelOpen ? '' : 'hidden min-[1440px]:block'}`;
  return (
    <div className={`grid gap-6 ${SPLIT_COLUMNS}`} style={{ '--panel': `${panelRem}rem` } as CSSProperties}>
      <div className={`min-w-0 ${panelOpen ? 'hidden min-[1440px]:block' : ''}`}>{list}</div>
      {rightLabel ? (
        <aside aria-label={rightLabel} className={rightClass}>
          {right}
        </aside>
      ) : (
        <div className={rightClass}>{right}</div>
      )}
    </div>
  );
}
