import Button from '@mui/material/Button';
import { ChainState, Intention, Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import type { DueItem, GetSummaryResponse, SetupStep } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { plans } from '../api/client';
import { useCall, useFindings, useGoalMap, useSummary } from '../api/hooks';
import { daysBetween, inDays, plural, ymd } from '../lib/format';
import { planHref } from '../lib/finding';
import { safeString } from '../lib/safe';
import { href } from '../lib/route';
import { Cmd } from '../ui/Cmd';
import { FindingCard } from '../ui/FindingCard';
import { Fp } from '../ui/Fp';
import { Glyph, SEV_EDGE, SEV_ORDER, SEV_TEXT, SEV_WORD, Sev, sevKey, type SevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';

function countOf(s: GetSummaryResponse, sev: Severity): number {
  return s.findingCounts.find((c) => c.severity === sev)?.count ?? 0;
}

function isEmptyFolder(s: GetSummaryResponse): boolean {
  return (s.counts?.roots ?? 0) === 0 && (s.ledger?.recordCount ?? 0) === 0 && s.due.length === 0;
}

// ---- the verdict: the state of the keys in one sentence --------------------

function Verdict({ s }: { s: GetSummaryResponse }) {
  const crit = countOf(s, Severity.CRITICAL);
  const alert = countOf(s, Severity.ALERT);
  const rest = countOf(s, Severity.NOTICE) + countOf(s, Severity.INFO);
  const next = [...s.due].sort((a, b) => (daysBetween(s.asOf, a.dueAt) ?? 0) - (daysBetween(s.asOf, b.dueAt) ?? 0))[0];
  const nextDays = next ? daysBetween(s.asOf, next.dueAt) : undefined;
  const worst: SevKey = crit > 0 ? 'critical' : alert > 0 ? 'alert' : rest > 0 ? 'notice' : 'ok';
  const headline =
    crit + alert > 0
      ? `${crit > 0 ? plural(crit, 'critical finding') : ''}${crit > 0 && alert > 0 ? ' and ' : ''}${alert > 0 ? plural(alert, 'finding') + ' at alert level' : ''} need${crit + alert === 1 ? 's' : ''} you.`
      : rest > 0
        ? 'Nothing urgent. A few things to look at.'
        : 'All clear.';
  return (
    <div className={`border-2 border-rule border-l-[10px] bg-panel ${SEV_EDGE[worst]}`}>
      <div className="flex flex-wrap items-center justify-between gap-x-8 gap-y-4 p-4 sm:p-5">
        <div className="min-w-0">
          <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">State of your keys, {ymd(s.asOf)}</p>
          <p className="mt-2 flex items-start gap-2.5 font-serif text-2xl leading-tight font-bold sm:text-3xl">
            <span className="mt-1.5">
              <Glyph level={worst} size={24} />
            </span>
            <span>{headline}</span>
          </p>
          <p className="mt-2 max-w-[60ch] text-base text-dim">
            {next ? (
              <>
                Next date: <strong className="text-ink">{ymd(next.dueAt)}</strong>, {inDays(nextDays)}. <T cap={90}>{next.title}</T>.
              </>
            ) : (
              'Nothing is due.'
            )}{' '}
            {rest > 0 ? `${plural(rest, 'lower finding')} can wait.` : null}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="contained" href={href.plan()}>
            Make a plan
          </Button>
          <Button variant="outlined" href={href.findings()}>
            All findings
          </Button>
        </div>
      </div>
      <dl className="grid grid-cols-2 border-t-2 border-rule sm:grid-cols-4">
        {SEV_ORDER.map((sev, i) => {
          const k = sevKey(sev);
          const n = countOf(s, sev);
          return (
            <a
              key={sev}
              href={href.findings()}
              aria-label={`${n} ${SEV_WORD[k].toLowerCase()} findings`}
              className={`flex min-h-16 items-center gap-3 px-4 py-3 text-ink no-underline hover:bg-sunk ${i % 2 === 1 ? 'border-l' : ''} ${i >= 2 ? 'border-t sm:border-t-0' : ''} ${i > 0 ? 'sm:border-l' : ''} border-line`}
            >
              <Glyph level={k} size={20} />
              <span className="leading-none">
                <dd className={`font-mono text-3xl font-bold ${n > 0 ? SEV_TEXT[k] : 'text-dim'}`}>{n}</dd>
                <dt className="mt-1 font-mono text-xs font-semibold tracking-wider text-dim uppercase">{SEV_WORD[k]}</dt>
              </span>
            </a>
          );
        })}
      </dl>
    </div>
  );
}

// ---- what is due: a timeline and the rows ----------------------------------

function Horizon({ s }: { s: GetSummaryResponse }) {
  const days = s.due.map((d) => daysBetween(s.asOf, d.dueAt) ?? 0);
  const span = Math.max(30, ...days) * 1.06;
  return (
    <div
      className="mb-3 border border-line bg-panel px-4 pt-7 pb-3"
      role="img"
      aria-label={`Timeline from ${ymd(s.asOf)}: ${s.due.map((d, i) => `${safeString(d.title, 80)} ${inDays(days[i])}`).join('; ')}`}
    >
      <div className="relative mx-3 h-8">
        <div className="absolute inset-x-0 top-[15px] h-[2px] bg-ink" />
        <div className="absolute top-[8px] left-0 h-[16px] w-[2px] bg-ink" />
        <span className="absolute -top-5 left-0 font-mono text-xs font-bold">Today</span>
        {s.due.map((d, i) => {
          const pos = (days[i] / span) * 100;
          const k = sevKey(d.severity);
          return (
            <span key={d.id} className="absolute top-[7px] -translate-x-1/2" style={{ left: `${pos}%` }}>
              <Glyph level={k} size={18} />
              <span className={`absolute -top-6 left-1/2 -translate-x-1/2 font-mono text-xs font-bold whitespace-nowrap ${SEV_TEXT[k]}`}>{days[i]} d</span>
            </span>
          );
        })}
      </div>
      <p className="mt-1 text-sm text-dim">Each mark is a due date, counted from {ymd(s.asOf)}.</p>
    </div>
  );
}

function DueRow({ d, asOf }: { d: DueItem; asOf: GetSummaryResponse['asOf'] }) {
  const n = daysBetween(asOf, d.dueAt);
  const last = daysBetween(d.lastDoneAt, asOf);
  const k = sevKey(d.severity);
  return (
    <li className={`grid grid-cols-[4.5rem_minmax(0,1fr)] gap-3 border border-line border-l-[6px] bg-panel p-4 ${SEV_EDGE[k]} sm:grid-cols-[5.5rem_minmax(0,1fr)]`}>
      <div className="leading-none">
        <p className={`font-mono text-3xl font-bold ${SEV_TEXT[k]}`}>{n}</p>
        <p className="mt-1 font-mono text-xs font-semibold text-dim uppercase">days left</p>
      </div>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Sev level={k} />
          <span className="text-sm text-dim">due {ymd(d.dueAt)}</span>
        </div>
        <h3 className="mt-1 text-lg leading-snug font-bold">
          <T cap={120}>{d.title}</T>
        </h3>
        <p className="mt-0.5 max-w-[68ch]">
          <T cap={260}>{d.detail}</T>
        </p>
        {last !== undefined ? (
          <p className="mt-1 text-sm text-dim">
            Last done {ymd(d.lastDoneAt)} ({last} days ago)
          </p>
        ) : null}
      </div>
    </li>
  );
}

/** The command that plans all renewals. The demo builds the plan in memory with the default answers and keeps only its command. */
function RenewAll({ count }: { count: number }) {
  const cmd = useCall('renew-command', async () => {
    const first = await plans.startPlan({ intention: Intention.RENEW_DUE });
    const answers = first.questions.map((q) => ({ questionId: q.id, optionIds: q.defaultOptionIds }));
    const second = await plans.startPlan({ intention: Intention.RENEW_DUE, answers });
    return second.plan?.equivalentCommand ?? '';
  });
  return (
    <div className="mt-3 border border-line bg-panel p-4">
      <p className="mb-2">
        <strong>One plan can renew all {count}.</strong> <span className="text-dim">You build it here and run it on the ceremony machine.</span>
      </p>
      {cmd.state === 'ready' && cmd.data ? <Cmd label="Make the plan that renews what is due">{cmd.data}</Cmd> : null}
      {cmd.state === 'loading' ? <p className="text-sm text-dim">Reading the command ...</p> : null}
      <div className="mt-3">
        <Button variant="outlined" href={planHref(Intention.RENEW_DUE)}>
          Make a plan
        </Button>
      </div>
    </div>
  );
}

// ---- the ledger seal, getting started, what the folder holds ---------------

function Seal({ s }: { s: GetSummaryResponse }) {
  const l = s.ledger;
  const ok = l?.chainState === ChainState.VERIFIED;
  const none = (l?.recordCount ?? 0) === 0;
  return (
    <a href={href.history()} className="block border-2 border-rule bg-panel p-4 text-ink no-underline hover:bg-sunk" aria-label="The ledger, open History">
      <div className="flex items-center gap-3">
        <Glyph level={none ? 'info' : ok ? 'ok' : 'critical'} size={26} />
        <div className="leading-tight">
          <p className="font-mono text-3xl font-bold">{l?.recordCount ?? 0}</p>
          <p className="font-mono text-xs font-semibold tracking-wider uppercase">
            {none ? 'records, none yet' : ok ? 'records, chain verified' : 'records, check the chain'}
          </p>
        </div>
      </div>
      <p className="mt-2 text-sm">
        <T cap={200}>{l?.message}</T>
      </p>
      {!none ? (
        <p className="mt-2 text-sm text-dim">
          The chain: each record names the one before it by its digest. Verified means ritueel checked every link. A rewrite of the whole history is caught only if you compare the newest digest with the one you kept apart.
        </p>
      ) : null}
      {l?.headRecordSha256 ? (
        <p className="mt-2 text-xs text-dim">
          Newest record, digest of its contents:
          <br />
          <Fp kind="Digest" value={l.headRecordSha256} className="text-xs" />
        </p>
      ) : null}
    </a>
  );
}

function Steps({ steps }: { steps: SetupStep[] }) {
  const done = steps.filter((s) => s.done).length;
  const links: Record<string, string> = { cards: href.cards(), 'first-plan': href.plan(), 'public-key': href.key() };
  return (
    <Sec title="Getting started" aside={`${done} of ${steps.length} done`}>
      <ol className="border border-line bg-panel">
        {steps.map((st, i) => (
          <li key={st.id} className={`flex gap-3 p-4 ${i > 0 ? 'border-t border-line' : ''}`}>
            <span className="mt-0.5">
              {st.done ? (
                <Glyph level="ok" size={20} />
              ) : (
                <span className="inline-flex h-5 w-5 items-center justify-center border-2 border-dashed border-ink font-mono text-xs font-bold">{i + 1}</span>
              )}
            </span>
            <div className="min-w-0">
              <p className="leading-snug font-bold">
                {links[st.id] && !st.done ? (
                  <a className="text-accent underline underline-offset-4" href={links[st.id]}>
                    <T cap={100}>{st.title}</T>
                  </a>
                ) : (
                  <T cap={100}>{st.title}</T>
                )}
                <span className="ml-2 font-mono text-xs font-semibold tracking-wider text-dim">{st.done ? 'DONE' : 'TO DO'}</span>
              </p>
              <p className="mt-0.5 text-[0.9375rem] text-dim">
                <T cap={220}>{st.detail}</T>
              </p>
            </div>
          </li>
        ))}
      </ol>
    </Sec>
  );
}

function Holds({ s }: { s: GetSummaryResponse }) {
  const rows: [string, number, string][] = [
    ['roots', s.counts?.roots ?? 0, href.roots()],
    ['delegated keys', s.counts?.delegatedKeys ?? 0, href.roots()],
    ['cards', s.counts?.cards ?? 0, href.cards()],
    ['trust files', s.counts?.trustFiles ?? 0, href.trust()],
  ];
  return (
    <Sec title="The folder holds" aside={<span className="font-mono"><T cap={60}>{s.folder?.path}</T></span>}>
      <ul className="grid grid-cols-2 border border-line bg-panel">
        {rows.map(([label, n, to], i) => (
          <li key={label} className={`${i % 2 === 1 ? 'border-l' : ''} ${i >= 2 ? 'border-t' : ''} border-line`}>
            <a href={to} className="flex min-h-14 items-baseline gap-2 px-4 py-3 text-ink no-underline hover:bg-sunk">
              <span className="font-mono text-2xl font-bold">{n}</span>
              <span className="text-sm text-dim">{label}</span>
            </a>
          </li>
        ))}
      </ul>
    </Sec>
  );
}

// ---- the screen ------------------------------------------------------------

function WhatIsWrong({ total }: { total: number }) {
  const findings = useFindings(Severity.ALERT);
  const all = useFindings();
  const goals = useGoalMap();
  return (
    <Sec
      id="wrong"
      title="What is wrong"
      aside={
        <a href={href.findings()} className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4">
          {total > 0 ? `All ${total} findings` : 'Findings'}
        </a>
      }
    >
      <Load res={findings} what="the findings" isEmpty={(d) => d.findings.length === 0} empty={<Empty title="Nothing urgent.">The lower findings can wait. See them under Findings.</Empty>}>
        {(d) => (
          <>
            <ul className="space-y-3">
              {[...d.findings]
                .sort((a, b) => b.severity - a.severity)
                .map((f) => (
                  <li key={f.id}>
                    <FindingCard f={f} goals={goals} showEvidence={false} />
                  </li>
                ))}
            </ul>
            {all.state === 'ready' && all.data.findings.length > d.findings.length ? (
              <p className="mt-3 text-sm text-dim">
                {all.data.findings.length - d.findings.length} lower findings can wait.{' '}
                <a className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4" href={href.findings()}>
                  Read them
                </a>
              </p>
            ) : null}
          </>
        )}
      </Load>
    </Sec>
  );
}

/** The words of this page, in one place a newcomer can open from the first screen. */
function Words() {
  const words: [string, string][] = [
    ['Root', 'The key that everything else is trusted from. It stays safe, and it is used rarely.'],
    ['Subkey', 'A key the primary key hands the daily work to: signing, logging in, encrypting. Its binding is renewed each year, and it is replaced only on an event, so the primary key can stay put.'],
    ['Delegated key', 'A key a root has handed a job to, for a requester (a system that asks for it). It works for a while and must be renewed.'],
    ['Ceremony', 'One sitting at the ceremony machine, where a plan is run and something about your keys changes.'],
    ['Ceremony machine', 'The offline computer where ceremonies are run, with your root cards plugged in. A plan is run there, and confirmed in its terminal.'],
    ['Ledger', 'The book of records. Each ceremony writes one record, and each names the one before it by digest, which is the chain.'],
    ['Trust files', 'The files your machines and users read to trust your roots: root list, CA bundle, revocation list. ritueel builds them; you publish them.'],
  ];
  return (
    <details className="border border-line bg-panel">
      <summary className="flex min-h-11 cursor-pointer items-center px-4 text-[0.9375rem] font-semibold text-accent">Words on this page</summary>
      <dl className="grid gap-x-6 gap-y-2 border-t border-line p-4 text-[0.9375rem] sm:grid-cols-[10rem_minmax(0,1fr)]">
        {words.map(([w, d]) => (
          <div key={w} className="contents">
            <dt className="font-bold">{w}</dt>
            <dd className="text-dim">{d}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function Body({ s }: { s: GetSummaryResponse }) {
  const total = s.findingCounts.reduce((n, c) => n + c.count, 0);
  if (isEmptyFolder(s)) {
    return (
      <div className="space-y-9">
        <Words />
        <Empty title="Your folder is empty. There is nothing to check yet.">
          <p>
            Nothing is wrong and nothing is due, because the folder holds no keys. That is not a problem: it is where everyone starts. The first step is to
            bring in the key you already have.
          </p>
          <p>
            <Button variant="contained" href={planHref(Intention.ADOPT_KEY)}>
              Make a plan to adopt a key
            </Button>
          </p>
        </Empty>
        <div className="grid gap-9 xl:grid-cols-2">
          <Steps steps={s.setupSteps} />
          <div className="space-y-9">
            <Sec title="The ledger">
              <Seal s={s} />
            </Sec>
            <Holds s={s} />
          </div>
        </div>
      </div>
    );
  }
  const due = [...s.due].sort((a, b) => (daysBetween(s.asOf, a.dueAt) ?? 0) - (daysBetween(s.asOf, b.dueAt) ?? 0));
  const months = Math.max(1, Math.ceil((daysBetween(s.asOf, due[due.length - 1]?.dueAt) ?? 0) / 30));
  return (
    <div className="space-y-9">
      <Verdict s={s} />
      <Words />
      <div className="grid gap-x-9 gap-y-9 xl:grid-cols-[minmax(0,1fr)_minmax(0,24rem)]">
        <div className="min-w-0 space-y-9">
          <WhatIsWrong total={total} />
          <Sec id="due" title="What is due" aside={due.length > 0 ? `${due.length} in the next ${plural(months, 'month')}` : undefined}>
            {due.length === 0 ? (
              <Empty title="Nothing is due.">No renewal or check falls in the coming months.</Empty>
            ) : (
              <>
                <Horizon s={s} />
                <ul className="space-y-3">
                  {due.map((d) => (
                    <DueRow key={d.id} d={d} asOf={s.asOf} />
                  ))}
                </ul>
                <RenewAll count={due.length} />
              </>
            )}
          </Sec>
        </div>
        <div className="min-w-0 space-y-9">
          <Sec title="The ledger">
            <Seal s={s} />
          </Sec>
          <Steps steps={s.setupSteps} />
          <Holds s={s} />
        </div>
      </div>
    </div>
  );
}

export function Start() {
  const summary = useSummary();
  return (
    <Page
      kicker="Start"
      title="What needs you"
      lede={
        <p>
          This is the folder where ritueel keeps the records of your keys. This page reads it and shows it. To change something, you make a plan here and run it in
          the terminal, on the ceremony machine.
        </p>
      }
    >
      <Load res={summary} what="the folder">
        {(s) => <Body s={s} />}
      </Load>
    </Page>
  );
}

