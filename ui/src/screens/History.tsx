import { useEffect, useState } from 'react';
import useMediaQuery from '@mui/material/useMediaQuery';
import { ChainState } from '../gen/ritueel/local/v1alpha1/common_pb';
import { CeremonyOutcome, CeremonyState, type Ceremony } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { combine, useCeremonies, useSummary } from '../api/hooks';
import { CAPS } from '../lib/caps';
import { plural, ymd } from '../lib/format';
import { domKey } from '../lib/inventory';
import { href } from '../lib/route';
import { safeString } from '../lib/safe';
import { CEREMONY_COMMAND_WORD, CEREMONY_STATE_WORD } from '../lib/words';
import { CeremonyPanel } from '../ui/CeremonyPanel';
import { DataTable, type Column } from '../ui/DataTable';
import { Glyph, type SevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { PanelFrame, PanelSection } from '../ui/PanelFrame';
import { GoToPanel } from '../ui/Panel';
import { ReadTime } from '../ui/ReadTime';
import { Empty, Load } from '../ui/Sec';
import { SplitView } from '../ui/SplitView';
import { T } from '../ui/T';

// History: what happened, newest first, and each ceremony that has no record.
// One list and one panel. The list is a table, one line for each ceremony
// (its ceremony folder). A ceremony in one of four states (planned, started, recorded,
// closed) is a line. A plan that was planned and never run (planned and stale)
// is not a line: the plans are folded into one line with a count, closed, and
// opened they are lines with the state "planned, stale".
//
// The panel shows the ceremony the address names; when it names none and the
// screen is 1440 px or wider, the newest ceremony that is not folded. Below
// 1440 px nothing is implied: the list shows first, and a chosen line shows the
// panel in place of the list (the rules are in ui/PanelFrame.tsx).

const WIDE = '(min-width:1440px)';

const isFolded = (c: Ceremony): boolean => c.state === CeremonyState.PLANNED && c.stale;

/** The date of a ceremony: the time it was planned, which is the time in the name of its ceremony folder. */
const dateOf = (c: Ceremony) => ymd(c.plannedAt ?? c.startedAt ?? c.finishedAt);

function stateWord(c: Ceremony): string {
  const word = CEREMONY_STATE_WORD[c.state] ?? '';
  if (c.state === CeremonyState.RECORDED && c.outcome === CeremonyOutcome.DECLINED) return `${word}, declined`;
  if (isFolded(c)) return `${word}, stale`;
  return word;
}

/** One shape for each state, always with its word. */
function stateLevel(c: Ceremony): SevKey {
  switch (c.state) {
    case CeremonyState.STARTED:
      return 'critical';
    case CeremonyState.RECORDED:
      return 'ok';
    case CeremonyState.CLOSED:
      return 'notice';
    default:
      return 'info';
  }
}

/**
 * The link of a line. Its name is the date, the command and the title; the
 * ceremony folder name is its description. The chosen line has `aria-current`.
 */
function CeremonyRowLink({ c, current }: { c: Ceremony; current: boolean }) {
  const name = `${dateOf(c)} ${CEREMONY_COMMAND_WORD[c.command] ?? ''} ${safeString(c.title, CAPS['Ceremony.title#cell'])}`;
  return (
    <a
      href={href.history(c.id)}
      aria-current={current ? 'true' : undefined}
      aria-label={name}
      aria-description={safeString(c.id, CAPS['Ceremony.id'])}
      className="font-semibold text-accent underline underline-offset-4"
    >
      {dateOf(c)}
    </a>
  );
}

const COLUMNS: Column<Ceremony>[] = [
  { key: 'date', header: 'Date', width: 7, render: (c, { current }) => <CeremonyRowLink c={c} current={current} /> },
  { key: 'command', header: 'Command', width: 5, render: (c) => CEREMONY_COMMAND_WORD[c.command] },
  { key: 'what', header: 'What', width: 22, render: (c) => <T cap={CAPS['Ceremony.title#cell']}>{c.title}</T> },
  {
    key: 'state',
    header: 'State',
    width: 7,
    render: (c) => (
      <span className="inline-flex items-start gap-1.5">
        <span className="mt-[3px]">
          <Glyph level={stateLevel(c)} size={14} />
        </span>
        <span>{stateWord(c)}</span>
      </span>
    ),
  },
];

const rowAttrs = (c: Ceremony) => ({ 'data-state': stateWord(c), 'data-command': CEREMONY_COMMAND_WORD[c.command] });

function CeremonyTable({ rows, caption, selectedKey }: { rows: Ceremony[]; caption: string; selectedKey?: string }) {
  return <DataTable caption={caption} rows={rows} rowKey={(c) => domKey(c.id)} selectedKey={selectedKey} rowAttrs={rowAttrs} columns={COLUMNS} />;
}

/** The fold line: closed unless the chosen ceremony is inside it. */
function Folded({ rows, selectedKey }: { rows: Ceremony[]; selectedKey?: string }) {
  const holdsChosen = selectedKey !== undefined && rows.some((c) => domKey(c.id) === selectedKey);
  const [open, setOpen] = useState(holdsChosen);
  // A link to a folded plan opens the fold, so the chosen line is on screen.
  useEffect(() => {
    if (holdsChosen) setOpen(true);
  }, [holdsChosen]);
  return (
    <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="mt-3">
      <summary className="inline-flex min-h-11 cursor-pointer items-center font-semibold text-accent underline underline-offset-4 lg:min-h-9">
        {plural(rows.length, 'plan')} {rows.length === 1 ? 'was' : 'were'} never run
      </summary>
      <div className="mt-1">
        <CeremonyTable rows={rows} caption="Plans that were never run." selectedKey={selectedKey} />
      </div>
    </details>
  );
}

/** The address names a ceremony folder that this bundle does not hold. The panel says so and goes back to the list. */
function NoSuchCeremony({ id }: { id: string }) {
  return (
    <PanelFrame kind="ceremony" title="No such ceremony" backHref={href.history()}>
      <PanelSection title="Not found">
        <p className="max-w-[70ch]">
          This bundle holds no ceremony folder called <T cap={CAPS['Ceremony.id']}>{id}</T>.
        </p>
      </PanelSection>
    </PanelFrame>
  );
}

export function History({ id }: { id?: string }) {
  const ceremonies = useCeremonies();
  const summary = useSummary();
  const res = combine(ceremonies, summary);
  const wide = useMediaQuery(WIDE);
  const ready = res.state === 'ready' ? res.data : undefined;
  const h = ready?.[0].history;
  return (
    <Page
      title="History"
      line={
        ready ? (
          <>
            <T cap={CAPS['Bundle.name']}>{ready[1].bundle?.name}</T> {'·'} {plural(h?.recordCount ?? 0, 'record')}
            {h && h.recordCount > 0 && h.endRecordSha256 ? (
              <>
                {' '}
                {'·'} End of the history{' '}
                <span className="font-mono">
                  <T cap={8}>{h.endRecordSha256.slice(0, 8)}</T>
                </span>
              </>
            ) : null}{' '}
            {'·'} <ReadTime ts={ready[0].readAt} />
          </>
        ) : undefined
      }
    >
      <Load
        res={res}
        what="the history"
        isEmpty={([d]) => d.ceremonies.length === 0}
        empty={
          <Empty title="No ceremony yet." command={{ text: 'ritueel apply', label: 'Make the plan in the terminal' }}>
            <p>The first apply writes the first ceremony and its record.</p>
          </Empty>
        }
      >
        {([d, s]) => {
          const status = d.history;
          const rows = d.ceremonies.filter((c) => !isFolded(c));
          const folded = d.ceremonies.filter(isFolded);
          // The panel shows the chosen ceremony, or on a wide screen the newest one that is not folded.
          const chosen = id !== undefined ? d.ceremonies.find((c) => c.id === id) : undefined;
          const shown = chosen ?? (id === undefined && wide ? rows[0] : undefined);
          const selectedKey = shown ? domKey(shown.id) : undefined;
          const fork = (status?.ends ?? 0) > 1;
          const broken = status?.chainState === ChainState.BROKEN;
          const list = (
            <>
              {status?.message ? (
                <p className="mb-2 max-w-[70ch] text-[0.9375rem] text-dim">
                  <T cap={CAPS['HistoryStatus.message#history']}>{status.message}</T>
                </p>
              ) : null}
              {fork || broken ? (
                <p role="alert" className="mb-2 flex max-w-[70ch] items-center gap-2 font-semibold text-critical">
                  <Glyph level="critical" size={16} />
                  {fork ? `The history has ${status?.ends} ends. This is a fork.` : 'The chain of the history is broken.'}
                </p>
              ) : null}
              <GoToPanel />
              <CeremonyTable rows={rows} caption="Ceremonies, newest first." selectedKey={selectedKey} />
              {folded.length > 0 ? <Folded rows={folded} selectedKey={selectedKey} /> : null}
            </>
          );
          const panel = shown ? (
            <CeremonyPanel key={shown.id} c={shown} all={d.ceremonies} trustSequence={s.trustSequence} />
          ) : id !== undefined ? (
            <NoSuchCeremony id={id} />
          ) : null;
          return <SplitView list={list} right={panel} panelOpen={id !== undefined} />;
        }}
      </Load>
    </Page>
  );
}
