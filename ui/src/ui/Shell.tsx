import { useEffect, useRef, type ReactNode } from 'react';
import { useColorScheme } from '@mui/material/styles';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import type { GetSummaryResponse } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { isDemo } from '../api/client';
import { useSummary } from '../api/hooks';
import { CAPS } from '../lib/caps';
import { plural } from '../lib/format';
import { href, routeTitle, siteUrl, type Route } from '../lib/route';
import { DemoBar } from './DemoBar';
import { ReadTime } from './ReadTime';
import { T } from './T';
import { ToastProvider } from './Toast';

// The frame: four entries, in this order. To do is the home entry.
//   To do      #/todo, #/todo/findings   the count of changes not applied yet
//   Inventory  #/inventory/...
//   History    #/history[/<ceremony>]
//   Trust set  #/trust                   the number of the newest set
// From 1024 px the entries stand in a sidebar; below that, in a bar at the
// bottom with four equal tabs. There is no menu.

type NavKey = 'todo' | 'inventory' | 'history' | 'trust';

const NAV: { key: NavKey; label: string; href: string }[] = [
  { key: 'todo', label: 'To do', href: href.todo() },
  { key: 'inventory', label: 'Inventory', href: href.inventory() },
  { key: 'history', label: 'History', href: href.history() },
  { key: 'trust', label: 'Trust set', href: href.trust() },
];

function navKeyOf(r: Route): NavKey | undefined {
  return r.name === 'notfound' ? undefined : r.name;
}

/**
 * A change of screen moves the focus to the heading and scrolls to the top. A
 * change inside one screen does not: the other tab of To do, the other object
 * of an Inventory view, the other ceremony of History. The focus rules of those
 * screens apply (the table and the panel own them).
 */
function screenKey(r: Route): string {
  switch (r.name) {
    case 'todo':
      return 'todo';
    case 'inventory':
      return `inventory:${r.view}`;
    case 'history':
      return 'history';
    default:
      return JSON.stringify(r);
  }
}

function Mark({ size = 22 }: { size?: number }) {
  // Four slots: used, empty, reserved, spare. The shapes of the slot grid.
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden focusable={false}>
      <rect x="1.5" y="1.5" width="9" height="9" fill="currentColor" />
      <rect x="13.5" y="1.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <rect x="1.5" y="13.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="3 2" />
      <rect x="13.5" y="13.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="0.1 3" strokeLinecap="round" />
    </svg>
  );
}

const SCHEME_BUTTON = { minWidth: 0, paddingInline: { xs: '0.5rem', sm: '0.75rem' } };

function SchemeSwitch() {
  const { mode, setMode } = useColorScheme();
  return (
    // The buttons carry less padding on a phone (SCHEME_BUTTON), so the header of a 360 px window is not wider than the window.
    <ToggleButtonGroup
      exclusive
      size="small"
      value={mode ?? null}
      onChange={(_e, value: 'system' | 'light' | 'dark' | null) => value && setMode(value)}
      aria-label="Colour scheme"
      sx={{ '& .MuiToggleButton-root': SCHEME_BUTTON }}
    >
      <ToggleButton value="system">Auto</ToggleButton>
      <ToggleButton value="light">Light</ToggleButton>
      <ToggleButton value="dark">Dark</ToggleButton>
    </ToggleButtonGroup>
  );
}

/** The counts of the entries, from the summary. Undefined while it is not read. */
function countsOf(s: GetSummaryResponse | undefined) {
  if (!s) return undefined;
  const changes = (s.changes?.ready ?? 0) + (s.changes?.waits ?? 0);
  const urgent = s.findingCounts.filter((c) => c.severity >= Severity.ALERT).reduce((n, c) => n + c.count, 0);
  return { changes, urgent, trust: s.trustSequence };
}

/** The text a screen reader says for the count of To do. */
function todoName(changes: number, urgent: number): string {
  const c = `${plural(changes, 'change')} not applied yet`;
  return urgent > 0 ? `${c}, ${urgent} ${urgent === 1 ? 'finding needs' : 'findings need'} you` : c;
}

export function Shell({ route, children }: { route: Route; children: ReactNode }) {
  const summary = useSummary();
  const data = summary.state === 'ready' ? summary.data : undefined;
  const counts = countsOf(data);
  const active = navKeyOf(route);

  // On a change of screen: a title for the tab, back to the top, and focus on
  // the heading, so a keyboard or screen-reader user starts at the new page.
  const first = useRef(true);
  const lastScreen = useRef(screenKey(route));
  const title = `${routeTitle(route)} - ritueel local page${isDemo ? ' (demo)' : ''}`;
  const screen = screenKey(route);
  useEffect(() => {
    document.title = title;
    const moved = lastScreen.current !== screen;
    lastScreen.current = screen;
    if (first.current) {
      first.current = false;
      return;
    }
    if (!moved) return;
    window.scrollTo(0, 0);
    document.getElementById('page-title')?.focus({ preventScroll: true });
  }, [title, screen]);

  /** The count beside an entry. It is a number for the eye and a sentence for a screen reader. */
  const badge = (key: NavKey, onBar: boolean) => {
    if (!counts) return null;
    if (key === 'todo' && (counts.changes > 0 || counts.urgent > 0)) {
      const critical = counts.urgent > 0;
      return (
        <span className={`font-mono text-xs leading-none font-bold ${critical ? 'bg-critical px-1.5 py-0.5 text-bg' : onBar ? 'text-inherit' : 'text-dim'}`}>
          <span aria-hidden>{counts.changes}</span>
          <span className="sr-only">{todoName(counts.changes, counts.urgent)}</span>
        </span>
      );
    }
    if (key === 'trust' && counts.trust > 0) {
      return (
        <span className={`font-mono text-xs leading-none font-bold ${onBar ? 'text-inherit' : 'text-dim'}`}>
          <span aria-hidden>{counts.trust}</span>
          <span className="sr-only">trust set {counts.trust}</span>
        </span>
      );
    }
    return null;
  };

  return (
    <ToastProvider>
      <div className="min-h-dvh bg-bg text-ink">
        <button
          type="button"
          data-print="hide"
          className="sr-only z-50 bg-accent px-3 py-2 font-bold text-accent-ink focus:not-sr-only focus:absolute focus:top-2 focus:left-2"
          onClick={() => document.getElementById('page-title')?.focus()}
        >
          Skip to the page
        </button>
        <div className="lg:grid lg:min-h-dvh lg:grid-cols-[14rem_minmax(0,1fr)]">
          <aside data-print="hide" className="hidden border-r-[3px] border-double border-rule lg:block">
            <div className="sticky top-0 flex h-dvh flex-col overflow-y-auto px-4 py-5">
              <a href={href.todo()} className="mb-6 flex items-center gap-2.5 text-ink no-underline" aria-label="ritueel local page, to do">
                <Mark size={28} />
                <span className="leading-none">
                  <span className="block font-mono text-lg font-bold tracking-tight">ritueel</span>
                  <span className="block pt-1 font-mono text-xs tracking-wider text-dim uppercase">local page{isDemo ? ', demo' : ''}</span>
                </span>
              </a>
              <nav aria-label="Screens" className="flex flex-col">
                {NAV.map((n) => (
                  <a
                    key={n.key}
                    href={n.href}
                    aria-current={active === n.key ? 'page' : undefined}
                    className={`flex min-h-11 items-center gap-3 border-l-4 pr-2 pl-3 text-base no-underline ${
                      active === n.key ? 'border-accent bg-sunk font-bold text-ink' : 'border-transparent text-ink hover:bg-sunk'
                    }`}
                  >
                    <span className="flex-1">{n.label}</span>
                    {badge(n.key, false)}
                  </a>
                ))}
              </nav>
              <div className="mt-auto space-y-3 border-t border-line pt-4 text-sm text-dim">
                {data ? (
                  <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
                    <dt>Bundle</dt>
                    <dd className="font-mono text-ink">
                      <T cap={CAPS['Bundle.name']}>{data.bundle?.name}</T>
                      <span className="block text-dim">
                        <T cap={CAPS['Bundle.path#shell']}>{data.bundle?.path}</T>
                      </span>
                    </dd>
                    <dt>Read</dt>
                    <dd className="font-mono text-ink">
                      <ReadTime ts={data.readAt} />
                    </dd>
                    <dt>Build</dt>
                    <dd className="font-mono text-ink">
                      <T cap={CAPS['GetSummaryResponse.program_version']}>{data.programVersion}</T>
                    </dd>
                  </dl>
                ) : null}
                <SchemeSwitch />
              </div>
            </div>
          </aside>

          <div className="flex min-w-0 flex-col">
            {isDemo ? <DemoBar /> : null}
            <header data-print="hide" className="sticky top-0 z-40 flex min-w-0 items-center justify-between gap-1 border-b-[3px] border-double border-rule bg-bg px-3 py-1 sm:px-4 lg:hidden">
              <a href={href.todo()} className="flex min-h-11 items-center gap-2 text-ink no-underline max-[359px]:min-w-11 max-[359px]:justify-center" aria-label="ritueel local page, to do">
                <Mark size={22} />
                <span className="font-mono text-base font-bold max-[359px]:sr-only">ritueel</span>
              </a>
              {isDemo ? (
                <a
                  href={siteUrl()}
                  aria-label="This is a demo. Back to ritueel.id"
                  className="inline-flex min-h-11 items-center border border-rule bg-sunk px-1.5 font-mono text-xs font-bold tracking-wider text-ink no-underline"
                >
                  DEMO
                </a>
              ) : null}
              <SchemeSwitch />
            </header>
            <main className="mx-auto flex w-full max-w-[112rem] flex-1 flex-col px-4 pt-4 pb-28 lg:px-8 lg:pt-5 lg:pb-5">
              <div className="flex-1">{children}</div>
              <footer className="mt-6 border-t border-line pt-2 text-sm text-dim">
                <p className="max-w-[70ch]">
                  This page only shows. It never asks for a PIN, a passphrase or a key, and it cannot confirm a ceremony. You confirm in the terminal.
                </p>
                <p className="flex flex-wrap gap-x-6">
                  <a className="inline-flex min-h-11 items-center underline underline-offset-4 lg:min-h-8" href={`${import.meta.env.BASE_URL}THIRD-PARTY-LICENSES.md`}>
                    Licences of the parts this page is built from
                  </a>
                  {isDemo ? (
                    <a className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4 lg:min-h-8" href={siteUrl()}>
                      Back to ritueel.id
                    </a>
                  ) : null}
                </p>
              </footer>
            </main>
          </div>
        </div>

        <nav aria-label="Screens" data-print="hide" className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-4 border-t-[3px] border-double border-rule bg-panel lg:hidden">
          {NAV.map((n) => (
            <a
              key={n.key}
              href={n.href}
              aria-current={active === n.key ? 'page' : undefined}
              className={`flex min-h-14 min-w-0 flex-col items-center justify-center gap-0.5 px-1 text-xs no-underline [@media(max-height:760px)]:min-h-12 ${active === n.key ? 'bg-ink font-bold text-bg' : 'text-ink'}`}
            >
              <span className="max-w-full min-w-0 truncate text-sm leading-none">{n.label}</span>
              {badge(n.key, true)}
            </a>
          ))}
        </nav>
      </div>
    </ToastProvider>
  );
}
