import { Fragment, type ReactNode } from 'react';
import { CeremonyCommand } from '../gen/ritueel/local/v1alpha1/common_pb';
import { CeremonyState, type Ceremony, type CeremonyChange } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { CAPS } from '../lib/caps';
import { plural } from '../lib/format';
import { domKey } from '../lib/inventory';
import { href, hrefForObject } from '../lib/route';
import { USUAL_STEPS } from '../lib/steps';
import { CHANGE_KIND_WORD, RUN_PLACE_VALUE } from '../lib/words';
import { Cmd } from './Cmd';
import { Fp } from './Fp';
import { LearnLink } from './Page';
import { PanelFrame, PanelSection } from './PanelFrame';
import { T } from './T';

// The panel of one ceremony in History. The screen gives it a key, so a new
// ceremony opens a new panel (and, below 1440 px, the focus goes to its heading).
// It shows what the plan holds, where it runs,
// what the record says and what to do next. It only shows. Every command is
// text with a Copy control, and the page cannot confirm a plan: the first
// eight characters of the digest are typed in the terminal.
//
// The sections follow the state of the ceremony folder:
//   planned   the plan, its digest to compare
//   started   the digest, and what to do with an attempt that has no record
//   recorded  the digest, the record, and the step after the record
//   closed    the digest, and the closing record that names it

const LINK = 'font-semibold text-accent underline underline-offset-4';

const Link = ({ to, children }: { to: string; children: ReactNode }) => (
  <a className={LINK} href={to}>
    {children}
  </a>
);

/** The place of a ceremony in its life: planned, started, then recorded (or closed). The current word is marked for a screen reader too. */
function Stepper({ c }: { c: Ceremony }) {
  const words = ['planned', 'started', c.state === CeremonyState.CLOSED ? 'closed' : 'recorded'];
  const at = c.state === CeremonyState.PLANNED ? 0 : c.state === CeremonyState.STARTED ? 1 : 2;
  return (
    <ol aria-label="The place of this ceremony" className="m-0 flex list-none flex-wrap items-center gap-x-1.5 gap-y-1 p-0">
      {words.map((w, i) => (
        <Fragment key={w}>
          {i > 0 ? (
            <li aria-hidden className="text-dim">
              {'›'}
            </li>
          ) : null}
          <li
            aria-current={i === at ? 'step' : undefined}
            className={`px-2 py-0.5 text-[0.875rem] ${i === at ? 'border-2 border-rule font-bold' : 'border border-line text-dim'}`}
          >
            {w}
            <span className="sr-only">{i < at ? ' (done)' : i > at ? ' (not yet)' : ' (now)'}</span>
          </li>
        </Fragment>
      ))}
    </ol>
  );
}

/** A change of the plan: the kind word, the text, and the object as a link to the inventory. */
function ChangeLine({ ch }: { ch: CeremonyChange }) {
  return (
    <li className="[overflow-wrap:anywhere]">
      <span className="text-dim">{CHANGE_KIND_WORD[ch.kind] ?? ''}</span> <T cap={CAPS['CeremonyChange.text']}>{ch.text}</T>
      {ch.object ? (
        <>
          {' '}
          {'·'}{' '}
          <Link to={hrefForObject(ch.object)}>
            <T cap={CAPS['ObjectRef.label']}>{ch.object.label}</T>
          </Link>
        </>
      ) : null}
      {ch.reason ? (
        <span className="block text-dim">
          <T cap={CAPS['CeremonyChange.reason']}>{ch.reason}</T>
        </span>
      ) : null}
    </li>
  );
}

const List = ({ children }: { children: ReactNode }) => <ul className="m-0 list-none space-y-1 p-0">{children}</ul>;

const first8 = (digest: string) => digest.slice(0, 8);

/** The folder of a ceremony, as a link to its panel. */
function CeremonyLink({ id }: { id: string }) {
  return (
    <Link to={href.history(id)}>
      <span className="[overflow-wrap:anywhere]">
        <T cap={CAPS['Ceremony.id']}>{id}</T>
      </span>
    </Link>
  );
}

export function CeremonyPanel({ c, all, trustSequence }: { c: Ceremony; all: Ceremony[]; trustSequence: number }) {
  const planned = c.state === CeremonyState.PLANNED;
  const closingRecord = c.command === CeremonyCommand.CLOSE;
  // The reason of a closed ceremony is written in the closing record that names it.
  const closer = c.closedBy ? all.find((x) => x.id === c.closedBy) : undefined;
  const reason = closingRecord ? c.closeReason : closer?.closeReason;
  const steps = USUAL_STEPS[c.command] ?? [];
  const counts = c.signatureCount > 0 || c.touchCount > 0;
  return (
    <PanelFrame kind="ceremony" title={<T cap={CAPS['Ceremony.id']}>{c.id}</T>} backHref={href.history()} rowId={domKey(c.id)}>
      {closingRecord ? null : <Stepper c={c} />}

      {c.ranOn || c.cards.length > 0 || counts ? (
        <PanelSection title="Where it runs">
          {RUN_PLACE_VALUE[c.ranOn] ? <p>{RUN_PLACE_VALUE[c.ranOn]}</p> : null}
          {c.cards.length > 0 ? (
            <p>
              {c.cards.length === 1 ? 'Card' : 'Cards'}:{' '}
              {c.cards.map((name, i) => (
                <span key={i}>
                  {i > 0 ? ', ' : ''}
                  <T cap={CAPS['Ceremony.cards']}>{name}</T>
                </span>
              ))}
            </p>
          ) : null}
          {counts ? (
            <p>
              {plural(c.signatureCount, 'signature')}, {plural(c.touchCount, 'touch', 'touches')}
            </p>
          ) : null}
        </PanelSection>
      ) : null}

      {c.planSha256 ? (
        <PanelSection title="Plan digest">
          <Fp kind="Digest" value={c.planSha256} />
          {planned ? (
            <p className="max-w-[70ch]">Compare it with the terminal. Type the first eight characters in the terminal, not here. This page cannot confirm.</p>
          ) : null}
          {planned && c.stale ? (
            <p className="max-w-[70ch]">This plan is stale. The end of the history or the trust set moved on, and apply refuses it.</p>
          ) : null}
        </PanelSection>
      ) : null}

      {c.applied.length > 0 ? (
        <PanelSection title={`In the plan (${c.applied.length})`}>
          <List>
            {c.applied.map((ch, i) => (
              <ChangeLine key={i} ch={ch} />
            ))}
          </List>
        </PanelSection>
      ) : null}

      {c.leftOut.length > 0 ? (
        <PanelSection title={`Left out (${c.leftOut.length})`}>
          <List>
            {c.leftOut.map((ch, i) => (
              <ChangeLine key={i} ch={ch} />
            ))}
          </List>
        </PanelSection>
      ) : null}

      {c.state === CeremonyState.RECORDED && c.publishCommand ? (
        <PanelSection title="After the record">
          <Cmd label="Send the public key in the terminal">{c.publishCommand}</Cmd>
          <p className="max-w-[70ch]">A published user ID cannot be withdrawn. You type the confirmation in the terminal. This page has no button.</p>
          <p>
            <LearnLink path="/design/#after-a-ceremony">After a ceremony</LearnLink>
          </p>
        </PanelSection>
      ) : null}

      {c.state === CeremonyState.STARTED ? (
        <PanelSection title="Attempt">
          <p className="max-w-[70ch]">
            This ceremony has an attempt and no ceremony record. ritueel status reports it as critical until it is recorded or closed. If the run is still going,
            wait for it. If it stopped, a signature may exist.
          </p>
          {c.closeCommand ? <Cmd label="Close it in the terminal">{c.closeCommand}</Cmd> : null}
        </PanelSection>
      ) : null}

      {c.state === CeremonyState.CLOSED || closingRecord ? (
        <PanelSection title={closingRecord ? 'Closing record' : 'Closed'}>
          {closingRecord && c.closes ? (
            <p>
              Closes <CeremonyLink id={c.closes} />
            </p>
          ) : null}
          {!closingRecord && c.closedBy ? (
            <p>
              Closed by <CeremonyLink id={c.closedBy} />
            </p>
          ) : null}
          {reason ? (
            <p className="max-w-[70ch]">
              <T cap={CAPS['Ceremony.close_reason']}>{reason}</T>
            </p>
          ) : null}
        </PanelSection>
      ) : null}

      {c.state === CeremonyState.RECORDED && c.recordSha256 ? (
        <PanelSection title="Record">
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1">
            <dt className="text-dim">Record</dt>
            <dd className="font-mono">
              <T cap={8}>{first8(c.recordSha256)}</T>
            </dd>
            <dt className="text-dim">Record before it</dt>
            <dd className={c.prevRecordSha256 ? 'font-mono' : 'text-dim'}>
              {c.prevRecordSha256 ? <T cap={8}>{first8(c.prevRecordSha256)}</T> : 'none, this is the first record'}
            </dd>
            {c.trustSetName ? (
              <>
                <dt className="text-dim">Trust set</dt>
                {/* The Trust set screen shows the newest set, so only the newest set is a link. */}
                <dd className="[overflow-wrap:anywhere]">
                  {c.trustSequence === trustSequence ? (
                    <Link to={href.trust()}>
                      <T cap={CAPS['Ceremony.trust_set_name']}>{c.trustSetName}</T>
                    </Link>
                  ) : (
                    <>
                      <T cap={CAPS['Ceremony.trust_set_name']}>{c.trustSetName}</T> <span className="text-dim">(not the newest)</span>
                    </>
                  )}
                </dd>
              </>
            ) : null}
          </dl>
        </PanelSection>
      ) : null}

      {steps.length > 0 ? (
        <PanelSection title="The usual steps">
          <ol className="m-0 list-none space-y-1 p-0">
            {steps.map((st) => (
              <li key={st.title}>
                <span className="font-semibold">{st.title}.</span> {st.detail}
              </li>
            ))}
          </ol>
          {c.guidePath ? (
            <p>
              <LearnLink path={c.guidePath}>About a ceremony</LearnLink>
            </p>
          ) : null}
        </PanelSection>
      ) : null}
    </PanelFrame>
  );
}

