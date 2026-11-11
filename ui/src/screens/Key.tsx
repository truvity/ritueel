import { useSyncExternalStore, type CSSProperties, type ReactNode } from 'react';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { SubjectKind } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  RootKind,
  SubkeyUsage,
  type Card,
  type DelegatedKey,
  type Finding,
  type Root,
  type RootKey,
  type Subkey,
  type SubkeySet,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { useBundleName, useCards, useFindings, useGoalMap, useRoots, useSummary } from '../api/hooks';
import { daysBetween, inDays, plural, rootRef, yearFraction, ymd } from '../lib/format';
import { href } from '../lib/route';
import { domId, safeString } from '../lib/safe';
import { touching } from '../lib/touch';
import { DELEGATED_STATE_WORD, DELEGATED_WORD, ORIGIN_WORD, ROOT_KEY_WORD, ROOT_STATE_WORD, STORE_WORD, USAGE_WORD } from '../lib/words';
import { FindingCard } from '../ui/FindingCard';
import { Fp } from '../ui/Fp';
import { Glyph, Sev, sevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Explain, Failed, Load, Sec } from '../ui/Sec';
import { MARK_WORD, MarkLegend, SubkeyMark, markOf, type Mark } from '../ui/Subkey';
import { T } from '../ui/T';

const LINK = 'font-semibold text-accent underline underline-offset-4';

// ---- small pieces ----------------------------------------------------------

function cardOf(serial: string, cards: Card[] | undefined): Card | undefined {
  return cards?.find((c) => c.serial === serial);
}

function Fact({ label, children, tone }: { label: string; children: ReactNode; tone?: 'alert' }) {
  return (
    <div className="min-w-0 border-t border-line px-4 py-3 first:border-t-0 sm:border-t-0 sm:border-l sm:first:border-l-0">
      <dt className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">{label}</dt>
      <dd className={`mt-1 text-base font-semibold ${tone === 'alert' ? 'text-alert' : ''}`}>{children}</dd>
    </div>
  );
}

// The picker has one column for each root, up to three (the class names are whole, so Tailwind finds them).
const PICKER_COLUMNS: Record<number, string> = { 1: 'sm:grid-cols-1', 2: 'sm:grid-cols-2' };

function RootPicker({ roots, current, bundle }: { roots: Root[]; current: string; bundle: string | undefined }) {
  return (
    <nav aria-label="Roots" className={`grid border-2 border-rule ${PICKER_COLUMNS[roots.length] ?? 'sm:grid-cols-3'}`}>
      {roots.map((r, i) => {
        const on = r.label === current;
        return (
          <a
            key={r.label}
            href={href.key(r.label)}
            aria-current={on ? 'page' : undefined}
            className={`min-h-14 min-w-0 px-3 py-2 no-underline ${i > 0 ? 'border-t-2 border-rule sm:border-t-0 sm:border-l-2' : ''} ${on ? 'bg-ink text-bg' : 'text-ink hover:bg-sunk'}`}
          >
            <span className="block text-base leading-tight font-bold">
              <T cap={60}>{rootRef(bundle, r.label)}</T>
            </span>
            <span className={`block text-sm leading-tight ${on ? 'text-bg opacity-90' : 'text-dim'}`}>{STORE_WORD[r.store]}</span>
          </a>
        );
      })}
    </nav>
  );
}

// ---- the certificate -------------------------------------------------------

function Certificate({ r, bundle }: { r: Root; bundle: string | undefined }) {
  const primary = r.certificate?.primary;
  const none = primary && !primary.expiresAt;
  return (
    <div className="border-2 border-rule bg-panel p-1.5">
      <div className="border border-rule">
        <div className="p-4 sm:p-6">
          <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">
            <span className="normal-case">
              <T cap={60}>{rootRef(bundle, r.label)}</T>
            </span>
            : OpenPGP certificate, {r.kind === RootKind.PERSONAL ? 'personal root' : 'company root'}, {ROOT_STATE_WORD[r.state]}
            {r.adopted ? `, adopted, stage ${r.stage}` : ''}
          </p>
          <h2 className="mt-1 text-2xl leading-tight font-bold sm:text-3xl">
            <T cap={80}>{r.name}</T>
          </h2>
          {primary ? (
            <div className="mt-4">
              <p className="mb-1 text-sm text-dim">
                Primary key of <T cap={60}>{rootRef(bundle, r.label)}</T>. This is its whole fingerprint: it is what names the key.
              </p>
              <Fp value={primary.fingerprint} className="text-base sm:text-lg" />
            </div>
          ) : null}
        </div>
        <dl className="grid border-t border-rule sm:grid-cols-4">
          <Fact label="Algorithm">
            <T cap={20}>{primary?.algorithm}</T>
          </Fact>
          <Fact label="Made">{ymd(primary?.createdAt ?? r.createdAt)}</Fact>
          <Fact label="Expires" tone={none ? 'alert' : undefined}>
            {primary?.expiresAt ? (
              ymd(primary.expiresAt)
            ) : (
              <span className="inline-flex items-center gap-1.5">
                <Glyph level="alert" size={16} /> Never. No expiry is set.
              </span>
            )}
          </Fact>
          <Fact label="Kept in">{STORE_WORD[r.store]}</Fact>
        </dl>
        {none ? (
          <p className="border-t border-rule bg-sunk px-4 py-2.5 text-[0.9375rem]">
            A key with no expiry stays valid for ever if you lose track of it. An expiry that you extend each year is a safety net.
          </p>
        ) : null}
        {r.note ? (
          <p className="border-t border-rule px-4 py-2.5">
            <T cap={400}>{r.note}</T>
          </p>
        ) : null}
      </div>
    </div>
  );
}

function UserIds({ r, findings }: { r: Root; findings: Finding[] | undefined }) {
  const flagged = (findings ?? []).filter((f) => f.subject?.kind === SubjectKind.USER_ID);
  const ids = r.certificate?.userIds ?? [];
  return (
    <ul className="border border-line bg-panel">
      {ids.map((u, i) => {
        const hit = flagged.find((f) => f.subject && u.text.startsWith(f.subject.label));
        return (
          <li key={i} className={`flex flex-col gap-x-4 gap-y-1 p-3 sm:flex-row sm:flex-wrap sm:items-center ${i > 0 ? 'border-t border-line' : ''}`}>
            <span className="min-w-0 font-mono text-sm [overflow-wrap:break-word] sm:flex-1">
              <T cap={160}>{u.text}</T>
            </span>
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-dim">
              {u.primary ? <span className="font-bold text-ink">Primary</span> : null}
              {u.revoked ? <span>Revoked</span> : null}
              <span>added {ymd(u.createdAt)}</span>
              {hit ? <Sev level={sevKey(hit.severity)} label="Misspelt" /> : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// ---- subkeys: the matrix, the chart, the register -----------------------------

const setId = (s: SubkeySet) => `set-${s.year}-${domId(s.cardSerial) || 'none'}`;

function jump(id: string) {
  const reg = document.getElementById('register');
  if (reg instanceof HTMLDetailsElement) reg.open = true;
  const el = document.getElementById(id);
  if (el) {
    if (el instanceof HTMLDetailsElement) el.open = true;
    el.scrollIntoView({ block: 'start' });
    el.focus({ preventScroll: true });
  }
}

function useNarrow(): boolean {
  return useSyncExternalStore(
    (cb) => {
      const m = window.matchMedia('(max-width: 639px)');
      m.addEventListener('change', cb);
      return () => m.removeEventListener('change', cb);
    },
    () => window.matchMedia('(max-width: 639px)').matches,
    () => false,
  );
}

function Matrix({ sets, cards }: { sets: SubkeySet[]; cards: Card[] | undefined }) {
  const serials = Array.from(new Set(sets.map((s) => s.cardSerial))).sort((a, b) => {
    const first = (x: string) => Math.min(...sets.filter((s) => s.cardSerial === x).map((s) => s.year));
    return first(a) - first(b) || a.localeCompare(b);
  });
  const min = Math.min(...sets.map((s) => s.year));
  const max = Math.max(...sets.map((s) => s.year));
  const years: number[] = [];
  for (let y = max; y >= min; y--) years.push(y);
  const narrow = useNarrow();
  const cols = `2.6rem repeat(${serials.length}, minmax(0, 1fr))`;
  return (
    <div className="border-2 border-rule bg-panel">
      <div className="grid border-b-2 border-rule bg-sunk" style={{ gridTemplateColumns: cols }}>
        <div className="p-1.5 text-xs font-semibold text-dim">Year</div>
        {serials.map((sn) => {
          const card = cardOf(sn, cards);
          const known = sets.find((s) => s.cardSerial === sn)?.cardInInventory;
          return (
            <div
              key={sn || 'none'}
              className={`min-w-0 border-l border-line px-1 py-1.5 ${known ? '' : 'bg-[repeating-linear-gradient(135deg,transparent_0_5px,color-mix(in_srgb,var(--mui-palette-severity-alert)_24%,transparent)_5px_7px)]'}`}
            >
              <p className="font-mono text-xs font-bold">
                {sn ? (
                  <a className="underline underline-offset-2" href={href.cards(sn)} aria-label={`Card ${safeString(sn, 20)}`}>
                    <span className="sm:hidden" aria-hidden>
                      <T cap={20}>{`..${sn.slice(-4)}`}</T>
                    </span>
                    <span className="hidden sm:inline" aria-hidden>
                      <T cap={20}>{sn}</T>
                    </span>
                  </a>
                ) : (
                  'No card'
                )}
              </p>
              <p className="mt-0.5 text-xs leading-tight">
                {known && card ? (
                  <T cap={30}>{card.name}</T>
                ) : known ? null : (
                  <span className="font-bold text-alert">
                    <Glyph level="alert" size={11} /> <span className="sm:hidden">not listed</span>
                    <span className="hidden sm:inline">not in inventory</span>
                  </span>
                )}
              </p>
            </div>
          );
        })}
      </div>
      {years.map((y) => {
        const here = sets.filter((s) => s.year === y);
        return (
          <div key={y} className="grid border-b border-line last:border-b-0" style={{ gridTemplateColumns: cols }}>
            <div className="flex items-center p-1.5 font-mono text-xs font-bold">{y}</div>
            {here.length === 0 ? (
              <div className="flex items-center px-2 py-2 text-xs text-dim" style={{ gridColumn: '2 / -1' }}>
                No subkey set made this year
              </div>
            ) : (
              serials.map((sn) => {
                const s = here.find((x) => x.cardSerial === sn);
                return (
                  <div key={sn || 'none'} className="flex min-w-0 items-center justify-center border-l border-line">
                    {s ? (
                      <button
                        type="button"
                        onClick={() => jump(setId(s))}
                        className="flex min-h-11 w-full cursor-pointer items-center justify-center gap-0.5 bg-transparent p-0 hover:bg-sunk sm:gap-1"
                        aria-label={`${y}, card ${safeString(sn, 20) || 'none'}: ${s.subkeys.map((k) => `${USAGE_WORD[k.usage]} ${MARK_WORD[markOf(k)]}`).join(', ')}. Show it in the list.`}
                      >
                        {s.subkeys.map((k) => (
                          <SubkeyMark key={k.fingerprint} k={k} size={narrow ? 19 : 24} />
                        ))}
                      </button>
                    ) : null}
                  </div>
                );
              })
            )}
          </div>
        );
      })}
    </div>
  );
}

const LANES: [SubkeyUsage, string][] = [
  [SubkeyUsage.SIGN, 'Sign'],
  [SubkeyUsage.AUTHENTICATE, 'Authenticate'],
  [SubkeyUsage.ENCRYPT, 'Encrypt'],
];

const HATCH = 'repeating-linear-gradient(135deg, transparent 0 4px, color-mix(in srgb, var(--mui-palette-background-paper) 55%, transparent) 4px 6px)';
const STRIKE_BAR =
  'linear-gradient(to top right, transparent calc(50% - 1px), var(--mui-palette-text-secondary) calc(50% - 1px) calc(50% + 1px), transparent calc(50% + 1px))';

function barStyle(m: Mark): { className: string; style?: CSSProperties } {
  switch (m) {
    case 'valid':
      return { className: 'bg-ink' };
    case 'replaced':
      return { className: 'bg-critical', style: { backgroundImage: HATCH } };
    case 'revoked':
      return { className: 'border border-dim', style: { backgroundImage: STRIKE_BAR } };
    default:
      return { className: 'border border-dashed border-dim' };
  }
}

/** When each subkey is valid: three lanes (sign, authenticate, encrypt), years across, a line for today. */
function ValidityChart({ sets, asOf }: { sets: SubkeySet[]; asOf: Timestamp | undefined }) {
  const all = sets.flatMap((s) => s.subkeys.map((k) => ({ k, s })));
  const starts = all.map((x) => yearFraction(x.k.createdAt) ?? 0);
  const ends = all.map((x) => yearFraction(x.k.expiresAt) ?? yearFraction(asOf) ?? 0);
  const x0 = Math.floor(Math.min(...starts));
  const x1 = Math.ceil(Math.max(...ends));
  const span = x1 - x0;
  const pct = (v: number) => ((v - x0) / span) * 100;
  const today = yearFraction(asOf);
  const replaced = all.filter((x) => markOf(x.k) === 'replaced').length;
  const ticks: number[] = [];
  for (let y = x0; y <= x1; y++) ticks.push(y);
  const ROW = 18;
  return (
    <figure className="border-2 border-rule bg-panel p-3 sm:p-4">
      <div
        role="img"
        aria-label={`Chart of when each of ${all.length} subkeys is valid, from ${x0} to ${x1}. ${replaced} signing subkeys are still valid though a newer key replaced them. The same facts are in the table of subkeys by year and by card.`}
        className="relative"
      >
        {LANES.map(([usage, label]) => {
          const items = all.filter((x) => x.k.usage === usage).sort((a, b) => (yearFraction(a.k.createdAt) ?? 0) - (yearFraction(b.k.createdAt) ?? 0));
          const rowEnd: number[] = [];
          const placed = items.map((x) => {
            const start = yearFraction(x.k.createdAt) ?? 0;
            const end = yearFraction(x.k.expiresAt) ?? today ?? start;
            let row = rowEnd.findIndex((e) => e <= start);
            if (row < 0) row = rowEnd.length;
            rowEnd[row] = end;
            return { k: x.k, card: x.s.cardSerial, start, end, row };
          });
          return (
            <div key={usage} className="mb-2">
              <p className="mb-1 font-mono text-xs font-bold">{label}</p>
              <div className="relative border-y border-line" style={{ height: rowEnd.length * ROW + 4 }}>
                {placed.map((p) => {
                  const m = markOf(p.k);
                  const b = barStyle(m);
                  return (
                    <span
                      key={p.k.fingerprint}
                      title={`${label}, ${MARK_WORD[m]}, ${ymd(p.k.createdAt)} to ${ymd(p.k.expiresAt)}${p.card ? `, card ${safeString(p.card, 20)}` : ''}`}
                      className={`absolute block h-3.5 ${b.className}`}
                      style={{ left: `${pct(p.start)}%`, width: `max(5px, ${pct(p.end) - pct(p.start)}%)`, top: 2 + p.row * ROW, ...b.style }}
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
        <div className="relative mt-1 h-5">
          {ticks.map((y, i) => (
            <span
              key={y}
              className={`absolute font-mono text-xs text-dim ${i % 2 === 1 ? 'hidden sm:block' : ''}`}
              style={{ left: `${pct(y)}%`, transform: i === 0 ? 'none' : i === ticks.length - 1 ? 'translateX(-100%)' : 'translateX(-50%)' }}
            >
              {y}
            </span>
          ))}
        </div>
        {today !== undefined ? <span aria-hidden className="absolute top-0 bottom-5 w-0.5 bg-accent" style={{ left: `${pct(today)}%` }} /> : null}
      </div>
      <figcaption className="mt-2 text-sm text-dim">
        An overview: the table above has the details, and the list below names every key. The blue line is today, {ymd(asOf)}. Red bars with stripes are signing keys that are still valid although a newer key replaced them ({replaced}).
      </figcaption>
    </figure>
  );
}

function SubkeyRow({ k }: { k: Subkey }) {
  const m = markOf(k);
  return (
    <li
      className={`grid gap-x-4 gap-y-1 border-t border-line p-3 sm:grid-cols-[8.5rem_12rem_minmax(0,1fr)] ${m === 'replaced' ? 'border-l-[6px] border-l-critical bg-[color-mix(in_srgb,var(--mui-palette-severity-critical)_8%,transparent)]' : 'border-l-[6px] border-l-transparent'}`}
    >
      <div className="flex items-center gap-2">
        <SubkeyMark k={k} size={20} />
        <span className="font-semibold">{USAGE_WORD[k.usage]}</span>
      </div>
      <div className="text-sm">
        <p className={`font-bold ${m === 'replaced' ? 'text-critical' : m === 'valid' ? 'text-ink' : 'text-dim'}`}>{MARK_WORD[m]}</p>
        <p className="font-mono whitespace-nowrap text-dim">
          {ymd(k.createdAt)} to {ymd(k.expiresAt)}
        </p>
      </div>
      <div className="min-w-0">
        <Fp value={k.fingerprint} />
        <p className="mt-0.5 text-sm text-dim">
          <T cap={20}>{k.algorithm}</T>, {ORIGIN_WORD[k.origin] ?? 'origin unknown'}
          {m === 'revoked' ? ', revoked as superseded' : ''}
        </p>
        {m === 'replaced' && k.replacedBy ? (
          <p className="mt-1 text-sm">
            Replaced by <Fp value={k.replacedBy} className="text-xs" />
          </p>
        ) : null}
      </div>
    </li>
  );
}

function SetBlock({ s, cards }: { s: SubkeySet; cards: Card[] | undefined }) {
  const card = cardOf(s.cardSerial, cards);
  const odd = s.subkeys.some((k) => markOf(k) === 'replaced');
  return (
    <li className="min-w-0">
      <details id={setId(s)} tabIndex={-1} open={odd} className="scroll-mt-20 border border-line bg-panel outline-none">
        <summary className="flex min-h-11 cursor-pointer flex-wrap items-center gap-x-4 gap-y-0.5 bg-sunk px-3 py-1.5">
          <span className="font-mono text-base font-bold">{s.year}</span>
          <span className="text-sm">
            {s.cardSerial ? <>Card <T cap={20}>{s.cardSerial}</T></> : 'Not on a card'}
            {s.cardSerial ? (
              s.cardInInventory && card ? (
                <span className="text-dim">
                  {' '}
                  (<T cap={30}>{card.name}</T>)
                </span>
              ) : s.cardInInventory ? null : (
                <span className="ml-2 inline-flex items-center gap-1 font-bold text-alert">
                  <Glyph level="alert" size={12} /> not in inventory
                </span>
              )
            ) : null}
          </span>
          <span className="ml-auto inline-flex items-center gap-1">
            {s.subkeys.map((k) => (
              <SubkeyMark key={k.fingerprint} k={k} size={18} />
            ))}
          </span>
        </summary>
        <ul>
          {s.subkeys.map((k) => (
            <SubkeyRow key={k.fingerprint} k={k} />
          ))}
        </ul>
      </details>
    </li>
  );
}

function Subkeys({ r, cards, asOf }: { r: Root; cards: Card[] | undefined; asOf: Timestamp | undefined }) {
  const sets = r.certificate?.subkeySets ?? [];
  const sorted = [...sets].sort((a, b) => b.year - a.year || a.cardSerial.localeCompare(b.cardSerial));
  const total = sets.reduce((n, s) => n + s.subkeys.length, 0);
  const cardCount = new Set(sets.map((s) => s.cardSerial)).size;
  const many = sets.length >= 3;
  return (
    <>
      <Sec title="Subkeys by year and by card" aside={`${plural(sets.length, 'set')} on ${plural(cardCount, 'card')}`}>
        <Explain term="A subkey set">
          is the group of subkeys made together on one card, one to sign and one to authenticate; the encryption subkey is made in software and loaded onto each card. The
          primary key stays safe, and the subkeys do the daily work. Their binding is renewed each year; a new set is made by ritueel only on an event, such as a lost card. The sets before 2025
          were made by hand, before the key was adopted.
        </Explain>
        {many ? (
          <>
            <MarkLegend />
            <Matrix sets={sets} cards={cards} />
            <div className="mt-5">
              <h3 className="mb-2 text-lg font-bold">When each subkey is valid</h3>
              <ValidityChart sets={sets} asOf={asOf} />
            </div>
          </>
        ) : null}
        <details id="register" className="mt-5 border-2 border-rule bg-panel" open={!many}>
          <summary className="flex min-h-12 cursor-pointer items-center px-3 py-2 text-lg font-bold">
            {many ? `All ${total} subkeys, with their full fingerprints` : `The ${plural(total, 'subkey')}, with full fingerprints`}
          </summary>
          <ol className="space-y-2 border-t-2 border-rule p-3">
            {sorted.map((s) => (
              <SetBlock key={setId(s)} s={s} cards={cards} />
            ))}
          </ol>
        </details>
      </Sec>
    </>
  );
}

// ---- other parts of a root ----------------------------------------------------

function KeysTable({ keys }: { keys: RootKey[] }) {
  return (
    <ul className="border border-line bg-panel">
      {keys.map((k) => (
        <li key={k.fingerprint} className="grid gap-x-4 gap-y-1 border-t border-line p-3 first:border-t-0 sm:grid-cols-[13rem_minmax(0,1fr)]">
          <p className="font-bold">{ROOT_KEY_WORD[k.kind]}</p>
          <div className="min-w-0">
            <Fp value={k.fingerprint} />
            <p className="mt-0.5 text-sm text-dim">
              <T cap={20}>{k.algorithm}</T>
              {k.cardSerial ? (
                <>
                  , card{' '}
                  <a className={LINK} href={href.cards(k.cardSerial)}>
                    <T cap={20}>{k.cardSerial}</T>
                  </a>
                  , slot <T cap={12}>{k.slot}</T>
                </>
              ) : null}
              , made {ymd(k.createdAt)}
              {k.expiresAt ? `, ends ${ymd(k.expiresAt)}` : ', no expiry'}
            </p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function Delegated({ list, asOf }: { list: DelegatedKey[]; asOf: Timestamp | undefined }) {
  return (
    <ul className="space-y-3">
      {list.map((d) => (
        <li key={d.fingerprint} className="border border-line bg-panel p-4">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
            <span className="font-mono text-lg font-bold">
              <T cap={60}>{d.name}</T>
            </span>
            <span className="text-sm text-dim">
              {DELEGATED_WORD[d.kind]}, {DELEGATED_STATE_WORD[d.state]}, for the requester <T cap={60}>{d.requester}</T>
            </span>
          </div>
          <div className="mt-2">
            <Fp value={d.fingerprint} />
          </div>
          <p className="mt-1.5 max-w-[68ch]">
            <T cap={260}>{d.detail}</T>
          </p>
          <p className="mt-1 text-sm text-dim">
            Kept in: {STORE_WORD[d.store]}. Certified {ymd(d.certifiedAt)}. Ends <strong className="text-ink">{ymd(d.expiresAt)}</strong> (
            {inDays(daysBetween(asOf, d.expiresAt))}).
          </p>
        </li>
      ))}
    </ul>
  );
}

function CloudFacts({ r }: { r: Root }) {
  const c = r.cloudKey;
  if (!c) return null;
  const rows: [string, string][] = [
    ['Alias', c.alias],
    ['Provider', c.provider],
    ['Region', c.region],
    ['Replica region', c.replicaRegion],
    ['Key', c.keyRef],
    ['Replica', c.replicaRef],
  ];
  return (
    <>
      <dl className="grid gap-px border border-line bg-line sm:grid-cols-2">
        {rows.map(([l, v]) => (
          <div key={l} className="min-w-0 bg-panel px-3 py-2">
            <dt className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">{l}</dt>
            <dd className="mt-0.5 font-mono text-sm [overflow-wrap:anywhere]">
              <T cap={200}>{v}</T>
            </dd>
          </div>
        ))}
      </dl>
      <ul className="mt-3 space-y-1">
        <li className="flex items-center gap-2 font-bold">
          <Glyph level={c.policyOk ? 'ok' : 'critical'} size={16} />
          {c.policyOk ? 'The key policy meets the rules.' : 'The key policy breaks a rule.'}
        </li>
        {c.policyNotes.map((n, i) => (
          <li key={i} className="pl-6 text-dim">
            <T cap={260}>{n}</T>
          </li>
        ))}
      </ul>
    </>
  );
}

// ---- the screen -----------------------------------------------------------------

function RootBody({ r, all, bundle }: { r: Root; all: Root[]; bundle: string | undefined }) {
  const findings = useFindings();
  const cards = useCards();
  const summary = useSummary();
  const goals = useGoalMap();
  const asOf = summary.state === 'ready' ? summary.data.asOf : undefined;
  const cardList = cards.state === 'ready' ? cards.data.cards : undefined;
  const cert = r.certificate;
  return (
    <div className="space-y-9">
      {cert ? (
        <Certificate r={r} bundle={bundle} />
      ) : (
        <div className="border-2 border-rule bg-panel p-4 sm:p-5">
          <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">
            <span className="normal-case">
              <T cap={60}>{rootRef(bundle, r.label)}</T>
            </span>
            : {r.kind === RootKind.PERSONAL ? 'personal root' : 'company root'}, {ROOT_STATE_WORD[r.state]}
            {r.adopted ? ', adopted' : ''}
          </p>
          <h2 className="mt-1 text-2xl font-bold">
            <T cap={80}>{r.name}</T>
          </h2>
          <p className="mt-2 text-dim">Kept in: {STORE_WORD[r.store]}. Made {ymd(r.createdAt)}.</p>
          {r.note ? (
            <p className="mt-2 max-w-[70ch]">
              <T cap={400}>{r.note}</T>
            </p>
          ) : null}
        </div>
      )}

      <Sec title="What touches this key">
        <Load res={findings} what="the findings" isEmpty={() => false}>
          {(d) => {
            const list = touching(r, d.findings);
            return list.length === 0 ? (
              <p className="flex items-center gap-2 border border-line bg-panel p-3">
                <Glyph level="ok" size={16} /> No finding touches this key.
              </p>
            ) : (
              <ul className="space-y-3">
                {list.map((f) => (
                  <li key={f.id}>
                    <FindingCard f={f} goals={goals} roots={all} showEvidence={false} compact />
                  </li>
                ))}
              </ul>
            );
          }}
        </Load>
      </Sec>

      {cert && cert.subkeySets.length > 0 ? (
        <>
          {cards.state === 'error' ? <Failed what="the card inventory" message={cards.message} retry={cards.retry} /> : null}
          <Subkeys r={r} cards={cardList} asOf={asOf} />
        </>
      ) : null}

      {cert ? (
        <Sec title="User IDs" aside={`${cert.userIds.length}`}>
          <UserIds r={r} findings={findings.state === 'ready' ? findings.data.findings : undefined} />
        </Sec>
      ) : null}

      {r.keys.length > 0 && r.kind !== RootKind.PERSONAL ? (
        <Sec
          title="Keys of this root"
          aside={
            r.cardRow && r.cardSerials.length > 0 ? (
              <>
                row {r.cardRow} of root card <T cap={20}>{r.cardSerials[0]}</T>
              </>
            ) : undefined
          }
        >
          <KeysTable keys={r.keys} />
        </Sec>
      ) : null}

      {r.delegatedKeys.length > 0 ? (
        <Sec title="Delegated keys" aside={`${r.delegatedKeys.length}`}>
          <Delegated list={r.delegatedKeys} asOf={asOf} />
        </Sec>
      ) : all.some((x) => x.delegatedKeys.length > 0) ? (
        <Sec title="Delegated keys" aside="0">
          <p className="border border-dashed border-line p-3">This root has certified no delegated key at the moment.</p>
        </Sec>
      ) : null}

      {r.cloudKey ? (
        <Sec title="Cloud key">
          <CloudFacts r={r} />
        </Sec>
      ) : null}
    </div>
  );
}

export function Key({ root }: { root: string }) {
  const roots = useRoots();
  const bundle = useBundleName();
  return (
    <Page
      kicker="Key"
      title="A root, its subkeys and its cards"
      lede={<p>A root is the key that everything else is trusted from. This page shows one root in full: its certificate, what is wrong with it, and which keys sit on which card.</p>}
    >
      <Load
        res={roots}
        what="the keys"
        isEmpty={(d) => d.roots.length === 0}
        empty={
          <Empty title="No key to show yet.">
            <p>The bundle holds no root, so there is no certificate to read. Adopt the key you already have, and it will appear here.</p>
            <p>
              <a className={LINK} href={href.plan('adopt-key')}>
                Make a plan to adopt a key
              </a>
            </p>
          </Empty>
        }
      >
        {(d) => {
          const known = d.roots.find((r) => r.label === root);
          if (!known) {
            return (
              <>
                <Empty title="There is no root with that label in this bundle.">
                  <p>
                    The bundle holds {plural(d.roots.length, 'root')}. Choose one below, or see <a className={LINK} href={href.roots()}>all roots</a>.
                  </p>
                </Empty>
                <RootPicker roots={d.roots} current="" bundle={bundle} />
              </>
            );
          }
          return (
            <>
              <RootPicker roots={d.roots} current={known.label} bundle={bundle} />
              <RootBody r={known} all={d.roots} bundle={bundle} />
            </>
          );
        }}
      </Load>
    </Page>
  );
}
