import { useEffect, useState, type ReactNode } from 'react';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { ChainState, Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  ChangeSource,
  ChangeState,
  NeedKind,
  type Change,
  type GetInventoryResponse,
  type GetSummaryResponse,
  type Need,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { isDemo } from '../api/client';
import { combine, useFindings, useInventory, useSummary, type Loaded } from '../api/hooks';
import { CAPS } from '../lib/caps';
import { daysBetween, inDays, plural, ymd } from '../lib/format';
import { href, hrefForChange } from '../lib/route';
import { CHAIN_STATE_WORD, CHANGE_STATE_WORD, NEED_KIND_WORD, OBJECT_KIND_WORD } from '../lib/words';
import { Cmd } from '../ui/Cmd';
import { DataTable, RowLink } from '../ui/DataTable';
import { FindingCard } from '../ui/FindingCard';
import { DemoLede } from '../ui/FirstVisit';
import { Page } from '../ui/Page';
import { ReadTime } from '../ui/ReadTime';
import { Empty, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';

// To do: what is not applied yet, which command applies it, and what is wrong.
// Two tabs, each its own address: "Not applied yet" (#/todo) reads the summary
// and the inventory; "Findings" (#/todo/findings) reads the summary and the
// findings. Each tab has the four read states (waiting, failed, empty, loaded).
// The page only shows: every command is text with a Copy control.
//
// Keyboard: the tabs are links in a tab list; the arrow keys move between them
// (roving tabindex) and Enter follows the link. A change of tab keeps the focus
// on the tab (the frame moves it only on a change of screen).

type TabName = 'changes' | 'findings';

const unique = (xs: string[]) => Array.from(new Set(xs));

/** The tab tells the heading when it has read, so the head shows the time only in the loaded and the empty state. */
function useStamp(onRead: (ts: Timestamp | undefined) => void, readAt: Timestamp | undefined): void {
  const key = readAt ? String(readAt.seconds) : '';
  useEffect(() => {
    onRead(readAt);
    return () => onRead(undefined);
    // The time is compared by its seconds, so a new object with the same time starts no effect.
  }, [key]);
}

export function Todo({ tab }: { tab: TabName }) {
  const summary = useSummary();
  const [stamp, setStamp] = useState<Timestamp | undefined>();
  const s = summary.state === 'ready' ? summary.data : undefined;
  const changes = s ? (s.changes?.ready ?? 0) + (s.changes?.waits ?? 0) : undefined;
  const findings = s ? s.findingCounts.reduce((n, c) => n + c.count, 0) : undefined;

  const label = (text: string, n: number | undefined) => (
    <span className="inline-flex items-center gap-2">
      {text}
      {n === undefined ? null : <span className="border border-rule px-1.5 font-mono text-xs leading-5 font-bold">{n}</span>}
    </span>
  );

  return (
    <Page
      title="To do"
      line={
        s && stamp ? (
          <>
            <T cap={CAPS['Bundle.name']}>{s.bundle?.name}</T> {'·'} <ReadTime ts={stamp} />
          </>
        ) : undefined
      }
    >
      {isDemo ? <DemoLede /> : null}
      <div>
        <Tabs value={tab} aria-label="To do" sx={{ minHeight: 44, borderBottom: 1, borderColor: 'divider' }}>
          <Tab component="a" href={href.todo()} value="changes" id="todo-tab-changes" aria-controls="todo-panel" label={label('Not applied yet', changes)} />
          <Tab component="a" href={href.findings()} value="findings" id="todo-tab-findings" aria-controls="todo-panel" label={label('Findings', findings)} />
        </Tabs>
        <div role="tabpanel" id="todo-panel" aria-labelledby={`todo-tab-${tab}`} className="pt-4">
          {tab === 'changes' ? <ChangesTab summary={summary} onRead={setStamp} /> : <FindingsTab summary={summary} onRead={setStamp} />}
        </div>
      </div>
    </Page>
  );
}

// ---- the layout of a tab -------------------------------------------------------

/**
 * The list, and at the right the Apply block and the Bundle block. From 1440 px
 * the list and the right column stand side by side with aligned tops (from 1800
 * px the right column is wider and holds the two blocks side by side). Below
 * 1440 px the order is the Apply block, the list, the Bundle block.
 */
function TodoGrid({ list, apply, bundle }: { list: ReactNode; apply?: ReactNode; bundle: ReactNode }) {
  return (
    <div className="grid gap-6 min-[1440px]:grid-cols-[minmax(0,1fr)_26rem] min-[1800px]:grid-cols-[minmax(0,62rem)_40rem]">
      <div className="order-2 min-w-0 min-[1440px]:order-none min-[1440px]:col-start-1 min-[1440px]:row-start-1">{list}</div>
      <div className="contents min-[1440px]:col-start-2 min-[1440px]:row-start-1 min-[1440px]:grid min-[1440px]:content-start min-[1440px]:gap-6 min-[1800px]:grid-cols-2 min-[1800px]:items-start">
        {apply ? <div className="order-1 min-w-0">{apply}</div> : null}
        <div className="order-3 min-w-0">{bundle}</div>
      </div>
    </div>
  );
}

// ---- tab "Not applied yet" -----------------------------------------------------

function ChangesTab({ summary, onRead }: { summary: Loaded<GetSummaryResponse>; onRead: (ts: Timestamp | undefined) => void }) {
  const inventory = useInventory();
  const res = combine(summary, inventory);
  useStamp(onRead, res.state === 'ready' ? res.data[1].readAt : undefined);
  return (
    <Load res={res} what="the changes">
      {([s, inv]) =>
        inv.changes.length === 0 ? (
          <TodoGrid list={<NothingWaits s={s} />} bundle={<BundleBlock s={s} />} />
        ) : (
          <TodoGrid list={<ChangeTable inv={inv} />} apply={<ApplyBlock s={s} changes={inv.changes} />} bundle={<BundleBlock s={s} />} />
        )
      }
    </Load>
  );
}

function StateMark({ ready }: { ready: boolean }) {
  // A filled disc is ready, a ring waits: the state is a shape and a word, never colour alone.
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden focusable={false} className="shrink-0">
      {ready ? <circle cx="6" cy="6" r="5" fill="currentColor" /> : <circle cx="6" cy="6" r="4.2" fill="none" stroke="currentColor" strokeWidth="1.6" />}
    </svg>
  );
}

function NeedLine({ n }: { n: Need }) {
  return (
    <>
      {NEED_KIND_WORD[n.kind]} <T cap={CAPS['Need.name']}>{n.name}</T>
      {n.met ? '' : ' (missing)'}
    </>
  );
}

function SourceLine({ c, inv }: { c: Change; inv: GetInventoryResponse }) {
  switch (c.source) {
    case ChangeSource.DATE:
      return <>Ends {ymd(c.dueAt)}, {inDays(daysBetween(inv.readAt, c.dueAt))}</>;
    case ChangeSource.WANTED_FILE:
      return c.wantedPath ? (
        <>
          From <T cap={CAPS['Change.wanted_path']}>{c.wantedPath}</T>
        </>
      ) : (
        <>From a wanted file</>
      );
    case ChangeSource.REQUEST:
      return <>From a request</>;
    case ChangeSource.HISTORY:
      return <>From the history</>;
    default:
      return null;
  }
}

function ChangeTable({ inv }: { inv: GetInventoryResponse }) {
  return (
    <>
      <DataTable
        caption="Changes not applied yet."
        rows={inv.changes}
        rowKey={(c) => c.id}
        columns={[
          {
            key: 'object',
            header: 'Object',
            width: 12,
            render: (c, { current }) => (
              <>
                <span className="text-dim">{OBJECT_KIND_WORD[c.object?.kind ?? 0]}</span>{' '}
                <RowLink href={hrefForChange(c)} current={current}>
                  <T cap={CAPS['ObjectRef.label']}>{c.object?.label}</T>
                </RowLink>
              </>
            ),
          },
          {
            key: 'change',
            header: 'Change',
            width: 14,
            render: (c) => (
              <>
                <T cap={CAPS['Change.text#cell']}>{c.text}</T>
                <span className="block text-dim">
                  <SourceLine c={c} inv={inv} />
                </span>
              </>
            ),
          },
          {
            key: 'needs',
            header: 'Needs',
            width: 9,
            render: (c) =>
              c.needs.length === 0 ? (
                'nothing'
              ) : (
                <ul className="m-0 list-none p-0">
                  {c.needs.map((n, i) => (
                    <li key={i}>
                      <NeedLine n={n} />
                    </li>
                  ))}
                </ul>
              ),
          },
          {
            key: 'state',
            header: 'State',
            width: 7,
            render: (c) => (
              <>
                <span className="inline-flex items-center gap-1.5 font-semibold">
                  <StateMark ready={c.state === ChangeState.READY} />
                  {CHANGE_STATE_WORD[c.state]}
                </span>
                {c.state === ChangeState.WAITS && c.reason ? (
                  <span className="mt-0.5 block text-dim">
                    <T cap={CAPS['Change.reason']}>{c.reason}</T>
                  </span>
                ) : null}
                {c.inCeremony ? (
                  <span className="mt-0.5 block text-dim [overflow-wrap:anywhere]">
                    In the plan of{' '}
                    <a className="underline underline-offset-4" href={href.history(c.inCeremony)}>
                      <T cap={CAPS['Ceremony.id']}>{c.inCeremony}</T>
                    </a>
                  </span>
                ) : null}
              </>
            ),
          },
        ]}
      />
      <p className="mt-2 max-w-[70ch] text-sm text-dim">A line opens its object in the inventory.</p>
    </>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <code className="font-mono text-[0.875rem]">{children}</code>;
}

/** The block that says what to type in the terminal. Drawn when at least one change is not applied yet. */
function ApplyBlock({ s, changes }: { s: GetSummaryResponse; changes: Change[] }) {
  const ready = s.changes?.ready ?? 0;
  const waits = s.changes?.waits ?? 0;
  const readyChanges = changes.filter((c) => c.state === ChangeState.READY);
  const cards = unique(readyChanges.flatMap((c) => c.needs).filter((n) => n.kind === NeedKind.CARD).map((n) => n.name));
  const missing = unique(changes.flatMap((c) => c.needs).filter((n) => n.kind === NeedKind.REQUEST && !n.met).map((n) => n.name));
  const keyFile = readyChanges.some((c) => c.needs.some((n) => n.kind === NeedKind.KEY_FILE));
  return (
    <Sec title="Apply in the terminal">
      <div className="space-y-3 text-[0.9375rem]">
        <p className="font-semibold">
          {ready} ready, {waits} waiting
        </p>
        {cards.length > 0 ? (
          <p>
            Cards at hand:{' '}
            {cards.map((name, i) => (
              <span key={i}>
                {i > 0 ? ', ' : ''}
                <T cap={CAPS['Need.name']}>{name}</T>
              </span>
            ))}
          </p>
        ) : null}
        {s.applyCommand ? (
          <>
            <Cmd label="Make the plan in the terminal">{s.applyCommand}</Cmd>
            <p>The terminal prints the plan and its digest. You type the first eight characters there. This page cannot confirm.</p>
          </>
        ) : null}
        {missing.length > 0 ? (
          <p>
            A change waits for a request. <Code>apply</Code> stops while a request is missing, unless you name it with <Code>--allow-missing</Code>.
          </p>
        ) : null}
        {keyFile ? (
          <p>
            A key file is used only in the offline system. <Code>apply --plan-only</Code> writes the plan; you run it there.
          </p>
        ) : null}
        {!s.applyCommand && ready === 0 && missing.length > 0 ? (
          <p>
            No change is ready. Ask the {missing.length === 1 ? 'requester for a request' : 'requesters for requests'} for{' '}
            {missing.map((name, i) => (
              <span key={i}>
                {i > 0 ? ', ' : ''}
                <T cap={CAPS['Need.name']}>{name}</T>
              </span>
            ))}
            .
          </p>
        ) : null}
      </div>
    </Sec>
  );
}

/** The empty state of the tab: nothing is not applied yet. It says when the next end is, or what to do first. */
function NothingWaits({ s }: { s: GetSummaryResponse }) {
  const next = s.nextDate;
  if (next) {
    return (
      <Empty title="Nothing waits.">
        <p>
          The next end is <T cap={CAPS['ObjectRef.label']}>{next.object?.label}</T>, on {ymd(next.endsAt)}, {inDays(daysBetween(s.readAt, next.endsAt))}. It is due from{' '}
          {ymd(next.dueFrom)}.
        </p>
      </Empty>
    );
  }
  if ((s.history?.recordCount ?? 0) === 0) {
    return (
      <Empty title="Nothing waits." command={{ text: 'ritueel want', label: 'List the wanted files in the terminal' }}>
        <p>This bundle holds no wanted file yet. Write the wanted files, then apply them.</p>
      </Empty>
    );
  }
  return (
    <Empty title="Nothing waits.">
      <p>No end date is near.</p>
    </Empty>
  );
}

// ---- the Bundle block ----------------------------------------------------------

function HistoryFact({ s }: { s: GetSummaryResponse }) {
  const h = s.history;
  if (!h || h.recordCount === 0) return <>No records yet.</>;
  if (h.ends > 1) return <span className="font-semibold text-critical">The history has {h.ends} ends. This is a fork.</span>;
  return (
    <>
      {plural(h.recordCount, 'record')}. End of the history <span className="font-mono"><T cap={8}>{h.endRecordSha256.slice(0, 8)}</T></span>.
      <span className={`block ${h.chainState === ChainState.BROKEN ? 'font-semibold text-critical' : 'text-dim'}`}>
        {h.chainState === ChainState.BROKEN ? 'The chain of the history is broken.' : `Chain: ${CHAIN_STATE_WORD[h.chainState] ?? 'not checked'}`}
      </span>
    </>
  );
}

/** The facts of the bundle: the history, the newest trust set, the last ceremony, the ceremonies without a record. */
function BundleBlock({ s }: { s: GetSummaryResponse }) {
  const link = 'font-semibold text-accent underline underline-offset-4';
  const last = s.history?.lastRecordId;
  const without = s.ceremoniesWithoutRecord;
  return (
    <Sec title="Bundle">
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-[0.9375rem]">
        <dt className="text-dim">History</dt>
        <dd>
          <HistoryFact s={s} />
        </dd>
        {s.trustSequence > 0 ? (
          <>
            <dt className="text-dim">Trust set</dt>
            <dd>
              <a className={link} href={href.trust()}>
                Set {s.trustSequence}
              </a>
            </dd>
          </>
        ) : null}
        {last ? (
          <>
            <dt className="text-dim">Last ceremony</dt>
            <dd>
              <a className={link} href={href.history(last)}>
                {ymd(s.history?.lastRecordAt)}
              </a>
            </dd>
          </>
        ) : null}
        {without > 0 ? (
          <>
            <dt className="text-dim">Without a record</dt>
            <dd>
              <a className={link} href={href.history()}>
                {without}
              </a>
            </dd>
          </>
        ) : null}
      </dl>
    </Sec>
  );
}

// ---- tab "Findings" ------------------------------------------------------------

const FILTERS: { value: string; label: string; min: Severity }[] = [
  { value: 'all', label: 'All', min: Severity.UNSPECIFIED },
  { value: 'alert', label: 'Alert and critical', min: Severity.ALERT },
  { value: 'critical', label: 'Critical', min: Severity.CRITICAL },
];

function FindingsTab({ summary, onRead }: { summary: Loaded<GetSummaryResponse>; onRead: (ts: Timestamp | undefined) => void }) {
  const [filter, setFilter] = useState('all');
  const min = FILTERS.find((f) => f.value === filter)?.min ?? Severity.UNSPECIFIED;
  const findings = useFindings(min);
  const res = combine(summary, findings);
  useStamp(onRead, res.state === 'ready' ? res.data[1].readAt : undefined);
  return (
    <div className="space-y-4">
      {/* The filter stays on screen while the list reads again, so the focus is not lost. */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span id="findings-filter-label" className="text-sm font-semibold">
          Show
        </span>
        <ToggleButtonGroup
          exclusive
          size="small"
          value={filter}
          onChange={(_e, value: string | null) => value && setFilter(value)}
          aria-labelledby="findings-filter-label"
          sx={{ '& .MuiToggleButton-root': { minHeight: { xs: 44, lg: 36 }, fontSize: '0.875rem' } }}
        >
          {FILTERS.map((f) => (
            <ToggleButton key={f.value} value={f.value}>
              {f.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      </div>
      <Load res={res} what="the findings">
        {([s, f]) => {
          const worstFirst = [...f.findings].sort((a, b) => b.severity - a.severity);
          const bundle = (
            <div className="space-y-4">
              <BundleBlock s={s} />
              <div className="space-y-2 text-[0.9375rem]">
                <p>Read the same list in the terminal:</p>
                <Cmd label="Read the findings in the terminal">ritueel status</Cmd>
              </div>
            </div>
          );
          if (worstFirst.length === 0) {
            return (
              <TodoGrid
                list={
                  min === Severity.UNSPECIFIED ? (
                    <Empty title="No findings.">
                      <p>ritueel status reports nothing for this bundle.</p>
                    </Empty>
                  ) : (
                    <Empty title="No finding at this level." />
                  )
                }
                bundle={bundle}
              />
            );
          }
          return (
            <TodoGrid
              list={
                <>
                  <p className="mb-3 font-semibold">{plural(worstFirst.length, 'finding')}, worst first</p>
                  <ol className="m-0 list-none space-y-3 p-0">
                    {worstFirst.map((x) => (
                      <li key={x.id}>
                        <FindingCard f={x} />
                      </li>
                    ))}
                  </ol>
                </>
              }
              bundle={bundle}
            />
          );
        }}
      </Load>
    </div>
  );
}
