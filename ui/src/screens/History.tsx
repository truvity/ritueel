import { ChainState, RunPlace } from '../gen/ritueel/local/v1alpha1/common_pb';
import { CeremonyKind, CeremonyOutcome, type Ceremony } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { useBundleName, useCeremonies, useRoots } from '../api/hooks';
import { plural, rootRef, ymd } from '../lib/format';
import { href } from '../lib/route';
import { USUAL_STEPS } from '../lib/steps';
import { CEREMONY_KIND_WORD, OUTCOME_WORD, RAN_PLACE_VALUE, RAN_PLACE_WORD } from '../lib/words';
import { Fp } from '../ui/Fp';
import { Glyph } from '../ui/Glyph';
import { LearnLink, Page } from '../ui/Page';
import { Empty, Explain, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';
import type { HistoryStatus } from '../gen/ritueel/local/v1alpha1/common_pb';

const LINK = 'font-semibold text-accent underline underline-offset-4';

function Seal({ l }: { l: HistoryStatus | undefined }) {
  const ok = l?.chainState === ChainState.VERIFIED;
  const none = (l?.recordCount ?? 0) === 0;
  const broken = l?.chainState === ChainState.BROKEN;
  return (
    <div className={`border-2 bg-panel p-4 sm:p-5 ${broken ? 'border-critical' : 'border-rule'}`}>
      <div className="flex flex-wrap items-start gap-x-5 gap-y-3">
        <div className="flex items-center gap-3">
          <Glyph level={none ? 'info' : ok ? 'ok' : 'critical'} size={32} />
          <div className="leading-tight">
            <p className="font-mono text-4xl font-bold">{l?.recordCount ?? 0}</p>
            <p className="font-mono text-xs font-semibold tracking-wider uppercase">records</p>
          </div>
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-lg font-bold">{none ? 'The history has no records yet.' : ok ? 'The chain is verified.' : broken ? 'The chain is broken.' : 'The chain has not been checked.'}</p>
          <p className="mt-0.5 max-w-[65ch]">
            <T cap={240}>{l?.message}</T>
          </p>
          {l?.headRecordSha256 ? (
            <div className="mt-3">
              <p className="text-sm text-dim">Digest of the newest record (it stands for the whole chain):</p>
              <Fp kind="Digest" value={l.headRecordSha256} />
            </div>
          ) : null}
          {l?.checkedAt ? <p className="mt-2 text-sm text-dim">Checked {ymd(l.checkedAt)}.</p> : null}
        </div>
      </div>
    </div>
  );
}

function outcomeLevel(o: CeremonyOutcome): 'ok' | 'alert' | 'critical' {
  return o === CeremonyOutcome.DONE ? 'ok' : o === CeremonyOutcome.REFUSED ? 'critical' : 'alert';
}

function Entry({ c }: { c: Ceremony }) {
  return (
    <li className="grid gap-x-5 gap-y-1 border border-line bg-panel p-4 sm:grid-cols-[8rem_minmax(0,1fr)]">
      <div>
        <p className="font-mono text-sm font-bold">{ymd(c.completedAt)}</p>
        <p className="mt-1 text-sm text-dim">{CEREMONY_KIND_WORD[c.kind]}</p>
      </div>
      <div className="min-w-0">
        <h3 className="text-lg leading-snug font-bold">
          <a className="text-ink underline decoration-line underline-offset-4 hover:decoration-accent" href={href.history(c.id)}>
            <T cap={120}>{c.title}</T>
          </a>
        </h3>
        <p className="mt-1 max-w-[70ch]">
          <T cap={420}>{c.summary}</T>
        </p>
        <p className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-dim">
          <span className="inline-flex items-center gap-1.5 font-semibold text-ink">
            <Glyph level={outcomeLevel(c.outcome)} size={14} /> {OUTCOME_WORD[c.outcome]}
          </span>
          {c.trustSequence ? <span>trust sequence {c.trustSequence}</span> : null}
          {RAN_PLACE_WORD[c.runPlace] ? <span>{RAN_PLACE_WORD[c.runPlace]}</span> : null}
          {c.cardSerials.length > 0 ? (
            <span>
              cards{' '}
              {c.cardSerials.map((s, i) => (
                <span key={i}>
                  {i > 0 ? ', ' : ''}
                  <T cap={20}>{s}</T>
                </span>
              ))}
            </span>
          ) : null}
        </p>
      </div>
    </li>
  );
}

function List() {
  const res = useCeremonies();
  return (
    <Page
      kicker="History"
      title="The history, one record per ceremony"
      lede={<p>Every time something about your keys changed, a record was written. Here they are, newest first.</p>}
    >
      <Explain term="A ceremony">
        is one sitting at a terminal, where a plan is run and something about your keys changes. The history is the write-once part of your bundle: a sub-folder for each ceremony, with its plan, record and transcript. Every record
        names the one before it by digest, so a change to one record breaks the chain after it.
      </Explain>
      <Load res={res} what="the history" isEmpty={(d) => d.ceremonies.length === 0} empty={
        <>
          <Empty title="The history is empty. No ceremony has been recorded yet.">
            <p>The first ceremony writes the first record. Until then there is nothing to read here, and nothing is wrong.</p>
            <p>
              <a className={LINK} href={href.plan()}>
                Make a plan
              </a>
            </p>
          </Empty>
        </>
      }>
        {(d) => (
          <>
            <Seal l={d.history} />
            <Sec title="Ceremonies" aside={plural(d.ceremonies.length, 'ceremony', 'ceremonies')}>
              <ol className="space-y-3">
                {d.ceremonies.map((c) => (
                  <Entry key={c.id} c={c} />
                ))}
              </ol>
            </Sec>
          </>
        )}
      </Load>
    </Page>
  );
}

function Detail({ id }: { id: string }) {
  const res = useCeremonies();
  const roots = useRoots();
  const bundle = useBundleName();
  return (
    <Page kicker="History" title="One ceremony" aside={<a className={LINK} href={href.history()}>Back to the history</a>}>
      <Load res={res} what="the history">
        {(d) => {
          const at = d.ceremonies.findIndex((c) => c.id === id);
          const c = d.ceremonies[at];
          if (!c) {
            return (
              <Empty title="There is no record with that name.">
                <p>The history holds {plural(d.ceremonies.length, 'record')}, and none is called that. Go back and choose one.</p>
              </Empty>
            );
          }
          const prev = d.ceremonies.find((x) => x.id === c.previousId);
          const next = at > 0 ? d.ceremonies[at - 1] : undefined;
          const steps = USUAL_STEPS[c.kind as CeremonyKind] ?? [];
          const rootLabels = roots.state === 'ready' ? new Set(roots.data.roots.map((r) => r.label)) : new Set<string>();
          return (
            <>
              <div className="border-2 border-rule bg-panel">
                <header className="border-b-2 border-rule bg-sunk px-4 py-3">
                  <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">
                    {CEREMONY_KIND_WORD[c.kind]}, {ymd(c.completedAt)}
                  </p>
                  <h2 className="mt-1 text-2xl leading-tight font-bold">
                    <T cap={120}>{c.title}</T>
                  </h2>
                </header>
                <div className="space-y-3 p-4">
                  <p className="max-w-[70ch] text-[1.0625rem]">
                    <T cap={500}>{c.summary}</T>
                  </p>
                  <dl className="grid gap-x-8 gap-y-2 text-[0.9375rem] sm:grid-cols-2">
                    <div>
                      <dt className="text-sm text-dim">Outcome</dt>
                      <dd className="flex items-center gap-1.5 font-bold">
                        <Glyph level={outcomeLevel(c.outcome)} size={14} /> {OUTCOME_WORD[c.outcome]}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm text-dim">Completed</dt>
                      <dd className="font-mono">{ymd(c.completedAt)}</dd>
                    </div>
                    {RAN_PLACE_VALUE[c.runPlace] ? (
                      <div>
                        <dt className="text-sm text-dim">Where it ran</dt>
                        <dd>
                          <span className="font-bold">{RAN_PLACE_VALUE[c.runPlace]}</span>
                          {c.runPlace === RunPlace.WORKSTATION ? <span className="block text-sm text-dim">A key that cannot be copied, or a test root. The conditions of record 0005 applied: the count stated in the plan, no retry, a check on a second device.</span> : null}
                        </dd>
                      </div>
                    ) : null}
                    {c.subjectLabels.length > 0 ? (
                      <div>
                        <dt className="text-sm text-dim">About</dt>
                        <dd className="flex flex-wrap gap-x-3">
                          {c.subjectLabels.map((l) =>
                            rootLabels.has(l) ? (
                              <a key={l} className={LINK} href={href.key(l)}>
                                <T cap={60}>{rootRef(bundle, l)}</T>
                              </a>
                            ) : (
                              <span key={l} className="font-mono">
                                <T cap={40}>{l}</T>
                              </span>
                            ),
                          )}
                        </dd>
                      </div>
                    ) : null}
                    {c.cardSerials.length > 0 ? (
                      <div>
                        <dt className="text-sm text-dim">Cards present</dt>
                        <dd className="flex flex-wrap gap-x-3">
                          {c.cardSerials.map((s) => (
                            <a key={s} className={`${LINK} font-mono`} href={href.cards(s)}>
                              <T cap={20}>{s}</T>
                            </a>
                          ))}
                        </dd>
                      </div>
                    ) : null}
                    {c.trustSequence ? (
                      <div>
                        <dt className="text-sm text-dim">Trust files built</dt>
                        <dd>
                          <a className={LINK} href={href.trust()}>
                            Trust sequence {c.trustSequence}
                          </a>
                        </dd>
                      </div>
                    ) : null}
                  </dl>
                  {c.guidePath ? (
                    <p>
                      <LearnLink path={c.guidePath}>Read the guide for this kind of ceremony</LearnLink>
                    </p>
                  ) : null}
                </div>
              </div>

              {steps.length > 0 ? (
                <Sec title="Steps" aside="the usual steps of this kind of ceremony">
                  <ol className="border border-line bg-panel">
                    {steps.map((st, i) => (
                      <li key={st.title} className={`grid grid-cols-[2rem_minmax(0,1fr)] gap-3 p-4 ${i > 0 ? 'border-t border-line' : ''}`}>
                        <span className="flex h-7 w-7 items-center justify-center bg-ink font-mono text-sm font-bold text-bg">{i + 1}</span>
                        <div>
                          <p className="font-bold">{st.title}</p>
                          <p className="text-[0.9375rem] text-dim">{st.detail}</p>
                        </div>
                      </li>
                    ))}
                  </ol>
                  <p className="mt-2 max-w-[70ch] text-sm text-dim">
                    The demo has no plan file for these ceremonies, so these are the usual steps of this kind of ceremony. In the program, the steps come from the plan in the
                    ceremony's sub-folder of the history.
                  </p>
                </Sec>
              ) : null}

              <Sec title="Records" aside="how this record is chained">
                <dl className="space-y-4 border border-line bg-panel p-4">
                  <div>
                    <dt className="text-sm font-semibold">This record</dt>
                    <dd>
                      <p className="font-mono text-sm text-dim">
                        <T cap={80}>{c.id}</T>
                      </p>
                      <Fp kind="Digest" value={c.recordSha256} />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-sm font-semibold">The record before it</dt>
                    <dd>
                      {prev ? (
                        <p>
                          <a className={LINK} href={href.history(prev.id)}>
                            <T cap={100}>{prev.title}</T>
                          </a>
                        </p>
                      ) : (
                        <p className="text-dim">None: this is the first record.</p>
                      )}
                      {c.previousRecordSha256 ? <Fp kind="Digest" value={c.previousRecordSha256} /> : null}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-sm font-semibold">The record after it</dt>
                    <dd>
                      {next ? (
                        <a className={LINK} href={href.history(next.id)}>
                          <T cap={100}>{next.title}</T>
                        </a>
                      ) : (
                        <span className="text-dim">None yet: this is the newest record.</span>
                      )}
                    </dd>
                  </div>
                  {c.planDigest ? (
                    <div>
                      <dt className="text-sm font-semibold">Digest of the plan that was run</dt>
                      <dd>
                        <Fp kind="Digest" value={c.planDigest} />
                      </dd>
                    </div>
                  ) : null}
                </dl>
              </Sec>
            </>
          );
        }}
      </Load>
    </Page>
  );
}

export function History({ id }: { id?: string }) {
  return id ? <Detail id={id} /> : <List />;
}

