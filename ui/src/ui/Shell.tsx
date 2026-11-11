import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useColorScheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { isDemo } from '../api/client';
import { VIEW_STATES, setViewState, useViewState } from '../api/demoState';
import { useSummary } from '../api/hooks';
import { ymd } from '../lib/format';
import { href, routeTitle, siteUrl, type Route } from '../lib/route';
import { T } from './T';
import { ToastProvider } from './Toast';

type NavKey = 'start' | 'findings' | 'roots' | 'cards' | 'history' | 'trust' | 'plan';

const NAV: { key: NavKey; label: string; href: string }[] = [
  { key: 'start', label: 'Start', href: href.start() },
  { key: 'findings', label: 'Findings', href: href.findings() },
  { key: 'roots', label: 'Roots', href: href.roots() },
  { key: 'cards', label: 'Cards', href: href.cards() },
  { key: 'history', label: 'History', href: href.history() },
  { key: 'trust', label: 'Trust files', href: href.trust() },
  { key: 'plan', label: 'Make a plan', href: href.plan() },
];

const MAIN_TABS: NavKey[] = ['start', 'findings', 'roots', 'cards'];
const MORE: NavKey[] = ['history', 'trust', 'plan'];

function navKeyOf(r: Route): NavKey | undefined {
  switch (r.name) {
    case 'key':
      return 'roots';
    case 'notfound':
      return undefined;
    default:
      return r.name;
  }
}

function Mark({ size = 22 }: { size?: number }) {
  // Four slots: used, empty, reserved, spare. The shapes of the cards screen.
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden focusable={false}>
      <rect x="1.5" y="1.5" width="9" height="9" fill="currentColor" />
      <rect x="13.5" y="1.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <rect x="1.5" y="13.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="3 2" />
      <rect x="13.5" y="13.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="0.1 3" strokeLinecap="round" />
    </svg>
  );
}

function SchemeSwitch() {
  const { mode, setMode } = useColorScheme();
  return (
    <ToggleButtonGroup
      exclusive
      size="small"
      value={mode ?? null}
      onChange={(_e, value: 'system' | 'light' | 'dark' | null) => value && setMode(value)}
      aria-label="Colour scheme"
    >
      <ToggleButton value="system">Auto</ToggleButton>
      <ToggleButton value="light">Light</ToggleButton>
      <ToggleButton value="dark">Dark</ToggleButton>
    </ToggleButtonGroup>
  );
}

/** Demo mode only. Lets a visitor see the four states of every screen. */
function StateSwitch() {
  const view = useViewState();
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span id="state-switch-label" className="text-sm font-semibold">
        Try the states
      </span>
      <ToggleButtonGroup
        exclusive
        size="small"
        value={view}
        onChange={(_e, value) => value && setViewState(value)}
        aria-labelledby="state-switch-label"
        sx={{ '& .MuiToggleButton-root': { minHeight: { xs: 44, lg: 34 }, fontSize: '0.8125rem', paddingInline: '0.7rem' } }}
      >
        {VIEW_STATES.map((s) => (
          <ToggleButton key={s.value} value={s.value} title={s.hint}>
            {s.label}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
    </div>
  );
}

/**
 * The calm mark that this is a demo: on every screen, in words, with the way
 * back to the site. It only exists in the demo build.
 */
function DemoBar() {
  return (
    <div role="region" aria-label="This is a demo" data-print="hide" className="z-40 border-b border-rule bg-sunk lg:sticky lg:top-0">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-2 lg:min-h-12">
        <p className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-0 text-sm">
          <span className="border border-rule bg-panel px-1.5 font-mono text-xs font-bold tracking-wider">DEMO</span>
          <span>The data is made up, and ritueel is still in design. Nothing here acts.</span>
          <a className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4 lg:min-h-0" href={siteUrl()}>
            Back to ritueel.id
          </a>
        </p>
        <StateSwitch />
      </div>
    </div>
  );
}

export function Shell({ route, children }: { route: Route; children: ReactNode }) {
  const summary = useSummary();
  const total = summary.state === 'ready' ? summary.data.findingCounts.reduce((n, c) => n + c.count, 0) : undefined;
  const urgent = summary.state === 'ready' ? summary.data.findingCounts.filter((c) => c.severity >= 3).reduce((n, c) => n + c.count, 0) : 0;
  const active = navKeyOf(route);
  const [more, setMore] = useState<HTMLElement | null>(null);

  // On a change of screen: a title for the tab, back to the top, and focus on
  // the heading, so a keyboard or screen-reader user starts at the new page.
  const first = useRef(true);
  const hashKey = JSON.stringify(route);
  useEffect(() => {
    document.title = `${routeTitle(route)} - ritueel local page${isDemo ? ' (demo)' : ''}`;
    if (first.current) {
      first.current = false;
      return;
    }
    window.scrollTo(0, 0);
    document.getElementById('page-title')?.focus({ preventScroll: true });
  }, [hashKey]);

  const count = (key: NavKey) =>
    key === 'findings' && total !== undefined ? (
      <span
        className={`font-mono text-xs font-bold ${urgent > 0 ? 'bg-critical px-1.5 text-bg' : 'text-dim'}`}
        aria-label={`${total} findings${urgent > 0 ? `, ${urgent} need you` : ''}`}
      >
        {total}
      </span>
    ) : null;

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
        {isDemo ? <DemoBar /> : null}
        <div className="lg:grid lg:grid-cols-[14rem_minmax(0,1fr)]">
          <aside data-print="hide" className="hidden border-r-[3px] border-double border-rule lg:block">
            <div className="sticky top-12 flex h-[calc(100dvh-3rem)] flex-col overflow-y-auto px-4 py-5">
              <a href={href.start()} className="mb-6 flex items-center gap-2.5 text-ink no-underline" aria-label="ritueel local page, start">
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
                    {count(n.key)}
                  </a>
                ))}
              </nav>
              <div className="mt-auto space-y-3 border-t border-line pt-4 text-sm text-dim">
                {summary.state === 'ready' ? (
                  <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
                    <dt>Bundle</dt>
                    <dd className="font-mono text-ink">
                      <T cap={40}>{summary.data.bundle?.path}</T>
                    </dd>
                    <dt>As of</dt>
                    <dd className="font-mono text-ink">{ymd(summary.data.asOf)}</dd>
                    <dt>Build</dt>
                    <dd className="font-mono text-ink">
                      <T cap={30}>{summary.data.programVersion}</T>
                    </dd>
                  </dl>
                ) : null}
                <SchemeSwitch />
              </div>
            </div>
          </aside>

          <div className="min-w-0">
            <header data-print="hide" className="sticky top-0 z-40 flex items-center justify-between gap-2 border-b-[3px] border-double border-rule bg-bg px-4 py-2 lg:hidden">
              <a href={href.start()} className="flex min-h-11 items-center gap-2 text-ink no-underline" aria-label="ritueel local page, start">
                <Mark size={22} />
                <span className="font-mono text-base font-bold">ritueel</span>
              </a>
              {isDemo ? (
                <a
                  href={siteUrl()}
                  aria-label="This is a demo. Back to ritueel.id"
                  className="inline-flex min-h-11 items-center border border-rule bg-sunk px-2 font-mono text-xs font-bold tracking-wider text-ink no-underline"
                >
                  DEMO
                </a>
              ) : null}
              <SchemeSwitch />
            </header>
            <main className="mx-auto w-full max-w-[80rem] px-4 pt-6 pb-28 lg:px-8 lg:pt-8 lg:pb-14">
              {children}
              <footer className="mt-14 border-t border-line pt-4 text-sm text-dim">
                <p className="max-w-[70ch]">
                  This page only shows. It never asks for a PIN, a passphrase or any secret, and it never confirms a ceremony. You confirm in the terminal, on the
                  ceremony machine.
                </p>
                <p className="mt-2 max-w-[70ch]">
                  <a className="inline-flex min-h-11 items-center underline underline-offset-4" href={`${import.meta.env.BASE_URL}THIRD-PARTY-LICENSES.md`}>
                    Licences of the parts this page is built from
                  </a>
                </p>
                {isDemo ? (
                  <p className="mt-2 max-w-[70ch]">
                    This is a demo of the local page. The data is made up and ritueel is in design.{' '}
                    <a className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4" href={siteUrl()}>
                      Back to ritueel.id
                    </a>
                  </p>
                ) : null}
              </footer>
            </main>
          </div>
        </div>

        <nav aria-label="Screens" data-print="hide" className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 border-t-[3px] border-double border-rule bg-panel lg:hidden">
          {MAIN_TABS.map((k) => {
            const n = NAV.find((x) => x.key === k)!;
            return (
              <a
                key={k}
                href={n.href}
                aria-current={active === k ? 'page' : undefined}
                className={`flex min-h-14 flex-col items-center justify-center gap-0.5 px-1 text-xs no-underline ${active === k ? 'bg-ink font-bold text-bg' : 'text-ink'}`}
              >
                <span className="text-sm leading-none">{n.label}</span>
                {k === 'findings' && total !== undefined ? (
                  <span className={`font-mono text-xs leading-none font-bold ${active === k ? 'text-bg' : urgent > 0 ? 'text-critical' : 'text-dim'}`} aria-label={`${total} findings`}>
                    {total}
                  </span>
                ) : null}
              </a>
            );
          })}
          <button
            type="button"
            aria-haspopup="menu"
            aria-expanded={more ? 'true' : undefined}
            onClick={(e) => setMore(e.currentTarget)}
            className={`flex min-h-14 cursor-pointer flex-col items-center justify-center gap-0.5 px-1 text-sm ${active && MORE.includes(active) ? 'bg-ink font-bold text-bg' : 'bg-transparent text-ink'}`}
          >
            More
          </button>
        </nav>
        <Menu anchorEl={more} open={more !== null} onClose={() => setMore(null)} anchorOrigin={{ vertical: 'top', horizontal: 'right' }} transformOrigin={{ vertical: 'bottom', horizontal: 'right' }}>
          {MORE.map((k) => {
            const n = NAV.find((x) => x.key === k)!;
            return (
              <MenuItem key={k} component="a" href={n.href} selected={active === k} onClick={() => setMore(null)}>
                {n.label}
              </MenuItem>
            );
          })}
        </Menu>
      </div>
    </ToastProvider>
  );
}
