import { Store } from '../gen/ritueel/local/v1alpha1/common_pb';
import { RootKind, type DelegatedKey, type Root } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { combine, useFindings, useRoots, useSummary } from '../api/hooks';
import { daysBetween, inDays, plural, ymd } from '../lib/format';
import { href } from '../lib/route';
import { safeString } from '../lib/safe';
import { touching } from '../lib/touch';
import { DELEGATED_STATE_WORD, DELEGATED_WORD, ROOT_KEY_WORD, ROOT_STATE_WORD, STORE_SENTENCE, STORE_WORD } from '../lib/words';
import { Glyph } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Explain, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';
import type { Finding } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';

const STORES = [Store.SOFTWARE_FILE, Store.ROOT_CARDS, Store.CLOUD_KMS];

function RootCard({ r, findings }: { r: Root; findings: Finding[] | undefined }) {
  const n = findings ? touching(r, findings) : undefined;
  return (
    <article className="border-2 border-rule bg-panel" aria-label={safeString(r.name, 80)}>
      <header className="border-b border-line bg-sunk px-4 py-3">
        <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">
          {r.kind === RootKind.PERSONAL ? 'Personal root' : 'Company root'}, {ROOT_STATE_WORD[r.state]}
          {r.adopted ? ', adopted' : ''}
        </p>
        <h3 className="mt-0.5 text-xl leading-tight font-bold">
          <T cap={80}>{r.name}</T>
        </h3>
      </header>
      <div className="space-y-3 p-4">
        {r.note ? (
          <p>
            <T cap={400}>{r.note}</T>
          </p>
        ) : null}
        <ul className="space-y-1 text-sm">
          {r.keys.map((k) => (
            <li key={k.fingerprint} className="flex flex-wrap gap-x-2">
              <span className="font-semibold">
                {ROOT_KEY_WORD[k.kind]}
                {k.side ? `, side ${safeString(k.side, 12)}` : ''}
              </span>
              <span className="font-mono text-dim">
                <T cap={20}>{k.algorithm}</T>, {k.expiresAt ? `ends ${ymd(k.expiresAt)}` : 'no expiry'}
              </span>
            </li>
          ))}
        </ul>
        {r.store === Store.ROOT_CARDS ? (
          <p className="text-sm">
            On cards{' '}
            {r.cardSerials.map((s, i) => (
              <span key={s}>
                {i > 0 ? ' and ' : ''}
                <a className="font-mono font-semibold text-accent underline underline-offset-4" href={href.cards(s)}>
                  <T cap={20}>{s}</T>
                </a>
              </span>
            ))}
            , in row {r.cardRow}.
          </p>
        ) : null}
        {r.store === Store.SOFTWARE_FILE ? (
          <p className="text-sm">
            Stage {r.stage}. A later stage moves the key to two card-born primaries in row {r.cardRow} of the root cards.
          </p>
        ) : null}
        {r.cloudKey ? (
          <div className="text-sm">
            <p className="font-mono break-all">
              <T cap={120}>{r.cloudKey.alias}</T>
            </p>
            <p className="text-dim">
              <T cap={30}>{r.cloudKey.provider}</T>, <T cap={30}>{r.cloudKey.region}</T>, replica in <T cap={30}>{r.cloudKey.replicaRegion}</T>
            </p>
            <p className="mt-1 flex items-center gap-2 font-semibold">
              <Glyph level={r.cloudKey.policyOk ? 'ok' : 'critical'} size={14} />
              {r.cloudKey.policyOk ? 'The key policy meets the rules.' : 'The key policy breaks a rule.'}
            </p>
          </div>
        ) : null}
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-line pt-3">
          <a className="inline-flex min-h-11 items-center font-bold text-accent underline underline-offset-4" href={href.key(r.label)}>
            Open the key
          </a>
          <span className="text-sm text-dim">{n === undefined ? 'Findings: could not be read' : n.length === 0 ? 'No finding' : plural(n.length, 'finding')}</span>
        </div>
      </div>
    </article>
  );
}

function Delegated({ list, asOf }: { list: { d: DelegatedKey; root: Root }[]; asOf: Parameters<typeof daysBetween>[0] }) {
  return (
    <ul className="space-y-3">
      {list.map(({ d, root }) => {
        const days = daysBetween(asOf, d.expiresAt);
        return (
          <li key={d.fingerprint} className="border border-line bg-panel p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-x-4">
              <h3 className="font-mono text-lg font-bold">
                <T cap={60}>{d.name}</T>
              </h3>
              <span className="text-sm text-dim">
                {DELEGATED_WORD[d.kind]}, {DELEGATED_STATE_WORD[d.state]}
              </span>
            </div>
            <p className="mt-1 max-w-[68ch]">
              <T cap={260}>{d.detail}</T>
            </p>
            <p className="mt-2 text-sm text-dim">
              For the requester <strong className="text-ink">
                <T cap={60}>{d.requester}</T>
              </strong>
              . Kept in: {STORE_WORD[d.store]}. Certified under{' '}
              <a className="font-semibold text-accent underline underline-offset-4" href={href.key(root.label)}>
                <T cap={60}>{root.name}</T>
              </a>{' '}
              on {ymd(d.certifiedAt)}. Ends <strong className="text-ink">{ymd(d.expiresAt)}</strong> ({inDays(days)}).
            </p>
          </li>
        );
      })}
    </ul>
  );
}

export function Roots() {
  const roots = useRoots();
  const findings = useFindings();
  const summary = useSummary();
  return (
    <Page
      kicker="Roots"
      title="Your roots, and where each is kept"
      lede={<p>A root is a key that everything else is trusted from. Each root is kept in one of three ways, called its store.</p>}
    >
      <Explain term="A delegated key">
        is a key a root has handed a job to, for a requester: a system or a workflow that asks for it. It works for a while and must be renewed.
      </Explain>
      <Load
        res={combine(roots, summary)}
        what="the roots"
        isEmpty={([r]) => r.roots.length === 0}
        empty={
          <Empty title="No roots yet.">
            <p>A root is the first thing a bundle holds. Adopt the key you already have, or a cloud key, and it appears here with its store.</p>
            <p>
              <a className="font-semibold text-accent underline underline-offset-4" href={href.plan('adopt-key')}>
                Make a plan to adopt a key
              </a>
            </p>
          </Empty>
        }
      >
        {([r, s]) => {
          const f = findings.state === 'ready' ? findings.data.findings : undefined;
          const delegated = r.roots.flatMap((root) => root.delegatedKeys.map((d) => ({ d, root })));
          return (
            <>
              <div className="grid gap-6 lg:grid-cols-3">
                {STORES.map((store) => {
                  const here = r.roots.filter((x) => x.store === store);
                  return (
                    <section key={store} aria-label={STORE_WORD[store]} className="min-w-0 space-y-3">
                      <div className="border-b-[3px] border-double border-rule pb-2">
                        <h2 className="text-xl font-semibold">{STORE_WORD[store]}</h2>
                        <p className="mt-1 text-sm text-dim">{STORE_SENTENCE[store]}</p>
                      </div>
                      {here.length === 0 ? (
                        <p className="border border-dashed border-line p-3 text-sm text-dim">No root is kept this way.</p>
                      ) : (
                        here.map((x) => <RootCard key={x.label} r={x} findings={f} />)
                      )}
                    </section>
                  );
                })}
              </div>
              {delegated.length > 0 ? (
                <Sec title="Delegated keys" aside={`${delegated.length}`}>
                  <Delegated list={delegated} asOf={s.asOf} />
                </Sec>
              ) : null}
            </>
          );
        }}
      </Load>
    </Page>
  );
}
