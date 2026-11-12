import { Fragment, type ReactNode } from 'react';
import { ObjectKind, Store, type CeremonyRef } from '../gen/ritueel/local/v1alpha1/common_pb';
import { KeyRole, type Card, type Certification, type Change, type Delegation, type Key, type Request, type Root, type UserId } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { isDemo } from '../api/client';
import { CAPS } from '../lib/caps';
import { daysBetween, plural, ymd } from '../lib/format';
import {
  changesOn,
  domKey,
  keyEndWord,
  keyOfObject,
  listedIn,
  lookup,
  type Found,
  type InvIndex,
  type ObjectId,
} from '../lib/inventory';
import { href, hrefForChange, hrefForObject, objectSlug, type InventoryView, type ObjectSlug } from '../lib/route';
import { isSerial, safeString } from '../lib/safe';
import {
  CARD_KIND_WORD,
  CEREMONY_COMMAND_WORD,
  CERTIFICATION_KIND_WORD,
  CHANGE_STATE_WORD,
  DELEGATED_KEY_WORD,
  DELEGATION_TYPE_WORD,
  KEY_STATE_WORD,
  OBJECT_KIND_WORD,
  REQUEST_OUTCOME_WORD,
  ROOT_KEY_WORD,
  ROOT_KIND_WORD,
  STORE_WORD,
} from '../lib/words';
import { Cmd } from './Cmd';
import { Fp } from './Fp';
import { PanelFrame, PanelSection } from './PanelFrame';
import { PathCopy } from './PathCopy';
import { SlotGrids } from './SlotGrid';
import { T } from './T';

// The panel of Inventory: one object, in the same sections for every kind.
//   Facts  Slots (a card)  Not applied yet  Wanted in / Request in
//   Ceremonies  If this key is lost or exposed / If this card is lost
// A section with nothing to say is left out. The frame (`PanelFrame`) owns the
// keyboard rules of the panel; this file owns what it says. It shows commands
// and paths as text with a Copy control and never acts.

const LINK = 'font-semibold text-accent underline underline-offset-4';

const Link = ({ to, children }: { to: string; children: ReactNode }) => (
  <a className={LINK} href={to}>
    {children}
  </a>
);

/** The button that moves the focus to the panel. Hidden until it has the focus, and only from 1440 px, where the panel stands beside the list. */
export function GoToPanel() {
  return (
    <button
      type="button"
      onClick={() => document.getElementById('panel-title')?.focus()}
      className="hidden min-[1440px]:block min-[1440px]:sr-only min-[1440px]:focus:not-sr-only min-[1440px]:focus:mb-2 min-[1440px]:focus:min-h-11 min-[1440px]:focus:px-3 font-semibold text-accent underline underline-offset-4"
    >
      Go to the panel
    </button>
  );
}

// ---- small parts ------------------------------------------------------------------

/** A fact is a label and a value. A `block` fact puts its value under the label, in the whole width: a fingerprint or a long reference. */
type Fact = [label: string, value: ReactNode, layout?: 'block'] | false | null | undefined;

function Facts({ rows, pairs = false }: { rows: Fact[]; pairs?: boolean }) {
  // `pairs`: from 1440 px to 1799 px two short facts stand side by side (the panel is 30rem wide); a block fact takes the whole width.
  // The facts of a key are short. The facts of the other objects hold long values and stay in one column.
  const two = pairs ? 'min-[1440px]:max-[1799px]:grid-cols-[auto_minmax(0,1fr)_auto_minmax(0,1fr)]' : '';
  const span = pairs ? 'min-[1440px]:max-[1799px]:col-span-4' : '';
  return (
    <dl className={`grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 ${two}`}>
      {rows.map((r, i) =>
        r ? (
          <Fragment key={i}>
            <dt className={`text-dim ${r[2] ? `col-span-2 mt-1 ${span}` : ''}`}>{r[0]}</dt>
            <dd className={`max-w-[60ch] min-w-0 [overflow-wrap:anywhere] ${r[2] ? `col-span-2 ${span}` : ''}`}>{r[1]}</dd>
          </Fragment>
        ) : null,
      )}
    </dl>
  );
}

/** A value of the data face that wraps anywhere, shown as plain safe text. It is not grouped by fours: a reference is shown as it is. */
function Mono({ children, cap }: { children: string; cap: number }) {
  return <span className="font-mono text-[0.8125rem] [overflow-wrap:anywhere]">{safeString(children, cap)}</span>;
}

const List = ({ children }: { children: ReactNode[] }) => (
  <ul className="m-0 list-none space-y-0.5 p-0">
    {children.map((c, i) => (
      <li key={i}>{c}</li>
    ))}
  </ul>
);

function daysFrom(ix: InvIndex, ts: Timestamp | undefined): number | undefined {
  return daysBetween(ix.inv.readAt, ts);
}

/** `2027-01-23, in 60 days`. A day in the past reads `2026-01-01, ended 3 days ago`. */
function DayAndCount({ ix, ts }: { ix: InvIndex; ts: Timestamp | undefined }) {
  const n = daysFrom(ix, ts);
  if (!ts) return <>-</>;
  const rel = n === undefined ? '' : n === 0 ? 'today' : n < 0 ? `ended ${plural(-n, 'day')} ago` : `in ${plural(n, 'day')}`;
  return (
    <>
      {ymd(ts)}
      {rel ? `, ${rel}` : ''}
    </>
  );
}

const yn = (b: boolean) => (b ? 'yes' : 'no');

function KeyLink({ ix, fingerprint }: { ix: InvIndex; fingerprint: string }) {
  const k = ix.keys.get(fingerprint);
  if (!k) return <>-</>;
  return <Link to={hrefForObject({ kind: ObjectKind.KEY, id: fingerprint })}>{keyTitle(k)}</Link>;
}

/** `key A of acme-tls` for a root key, `key of acme-ca` for a delegated key. */
function keyTitle(k: Key): ReactNode {
  return k.role === KeyRole.DELEGATED_KEY ? (
    <>
      key of <T cap={CAPS['Key.delegation']}>{k.delegation}</T>
    </>
  ) : (
    <>
      key <T cap={CAPS['Key.label']}>{k.label}</T> of <T cap={CAPS['Key.root']}>{k.root}</T>
    </>
  );
}

// ---- Facts, by kind -----------------------------------------------------------------

function CardFacts({ c }: { c: Card }) {
  return (
    <Facts pairs
      rows={[
        ['Serial', isSerial(c.serial) ? <span className="font-mono">{c.serial}</span> : <T cap={CAPS['Card.serial']}>{c.serial}</T>],
        ['Kind', CARD_KIND_WORD[c.kind]],
        ['Model', <T cap={CAPS['Card.model']}>{c.model}</T>],
        ['Firmware', <T cap={CAPS['Card.firmware']}>{c.firmware}</T>],
        !!c.holder && ['Holder', <T cap={CAPS['Card.holder']}>{c.holder}</T>],
        !!c.kept && ['Kept', <T cap={CAPS['Card.kept']}>{c.kept}</T>],
        !!c.lastCheckedAt && ['Last checked', ymd(c.lastCheckedAt)],
        ['One-time codes', c.oneTimeCodesOff ? 'off' : 'on'],
        c.changesSinceLastReading.length > 0 && [
          'Changed since the last reading',
          <List>
            {c.changesSinceLastReading.map((x, i) => (
              <T key={i} cap={CAPS['Card.changes_since_last_reading']}>
                {x}
              </T>
            ))}
          </List>,
          'block',
        ],
      ]}
    />
  );
}

function RootFacts({ ix, r }: { ix: InvIndex; r: Root }) {
  return (
    <Facts
      rows={[
        ['Kind', ROOT_KIND_WORD[r.kind]],
        [
          'Keys',
          <List>
            {r.keyIds.map((id) => (
              <KeyLink key={id} ix={ix} fingerprint={id} />
            ))}
          </List>,
        ],
        r.test && ['Test root', 'yes'],
        r.adopted && ['Adopted', 'yes'],
        !!r.createdAt && ['Made', ymd(r.createdAt)],
        !!r.note && ['Note', <T cap={CAPS['Root.note']}>{r.note}</T>],
      ]}
    />
  );
}

function PlaceFacts({ k }: { k: Key }): Fact[] {
  const p = k.place;
  if (!p) return [];
  const store: Fact = ['Store', STORE_WORD[p.store]];
  switch (p.store) {
    case Store.PIV:
    case Store.OPENPGP_CARD:
      return [
        store,
        [
          'Card',
          <>
            <Link to={hrefForObject({ kind: ObjectKind.CARD, id: p.card })}>
              <T cap={CAPS['Place.card']}>{p.card}</T>
            </Link>
            , slot <T cap={CAPS['Place.slot']}>{p.slot}</T>
          </>,
        ],
      ];
    case Store.AWS_KMS:
      return [
        store,
        ['Key reference', <Mono cap={CAPS['Place.key_ref']}>{p.keyRef}</Mono>, 'block'],
        ['Region', <T cap={CAPS['Place.region']}>{p.region}</T>],
        !!p.replicaRegion && ['Replica Region', <T cap={CAPS['Place.replica_region']}>{p.replicaRegion}</T>],
        !!p.replicaRef && ['Replica reference', <Mono cap={CAPS['Place.replica_ref']}>{p.replicaRef}</Mono>, 'block'],
      ];
    case Store.SOFTWARE:
      return [store, ['Key file', <Mono cap={CAPS['Place.path']}>{p.path}</Mono>, 'block']];
    default:
      return [store];
  }
}

function KeyFacts({ ix, k }: { ix: InvIndex; k: Key }) {
  const delegated = k.role === KeyRole.DELEGATED_KEY;
  return (
    <Facts pairs
      rows={[
        ['Fingerprint', <Fp value={k.fingerprint} />, 'block'],
        ['Kind', (delegated ? DELEGATED_KEY_WORD : ROOT_KEY_WORD)[k.kind]],
        ix.roots.has(k.root) ? ['Root', <Link to={hrefForObject({ kind: ObjectKind.ROOT, id: k.root })}><T cap={CAPS['Key.root']}>{k.root}</T></Link>] : ['Root', <T cap={CAPS['Key.root']}>{k.root}</T>],
        !!k.label && ['Label', <T cap={CAPS['Key.label']}>{k.label}</T>],
        ['State', KEY_STATE_WORD[k.state]],
        !!k.algorithm && ['Algorithm', <T cap={CAPS['Key.algorithm']}>{k.algorithm}</T>],
        ...PlaceFacts({ k }),
        !!k.createdAt && ['Made', ymd(k.createdAt)],
        ['Ends', k.expiresAt ? <DayAndCount ix={ix} ts={k.expiresAt} /> : keyEndWord(k)],
        !!k.retireAt && ['Retire on', ymd(k.retireAt)],
        !!k.delegation && [
          'Delegation',
          ix.delegations.has(k.delegation) ? (
            <Link to={hrefForObject({ kind: ObjectKind.DELEGATION, id: k.delegation })}>
              <T cap={CAPS['Key.delegation']}>{k.delegation}</T>
            </Link>
          ) : (
            <T cap={CAPS['Key.delegation']}>{k.delegation}</T>
          ),
        ],
      ]}
    />
  );
}

function UserIdFacts({ ix, u }: { ix: InvIndex; u: UserId }) {
  return (
    <Facts
      rows={[
        ['Text', <T cap={CAPS['UserId.text']}>{u.text}</T>],
        ['Key', <KeyLink ix={ix} fingerprint={u.key} />],
        ['Certified', yn(u.certified)],
        ['Revoked', yn(u.revoked)],
      ]}
    />
  );
}

function DelegationFacts({ ix, d }: { ix: InvIndex; d: Delegation }) {
  const requests = ix.inv.requests.filter((r) => r.delegation === d.name);
  return (
    <Facts
      rows={[
        ['Kind', DELEGATION_TYPE_WORD[d.type]],
        ['Root', ix.roots.has(d.root) ? <Link to={hrefForObject({ kind: ObjectKind.ROOT, id: d.root })}><T cap={CAPS['Root.name']}>{d.root}</T></Link> : <T cap={CAPS['Root.name']}>{d.root}</T>],
        !!d.requester && ['Requester', <T cap={CAPS['Delegation.requester']}>{d.requester}</T>],
        !!d.use && ['Use', <T cap={CAPS['Delegation.use']}>{d.use}</T>],
        d.limits.length > 0 && [
          'Limits',
          <List>
            {d.limits.map((l, i) => (
              <T key={i} cap={CAPS['Delegation.limits']}>
                {l}
              </T>
            ))}
          </List>,
        ],
        ['Key', d.key ? <KeyLink ix={ix} fingerprint={d.key} /> : 'no key certified yet'],
        !!d.certification && [
          'Certification',
          <Link to={hrefForObject({ kind: ObjectKind.CERTIFICATION, id: d.certification })}>{certTitle(ix.certs.get(d.certification))}</Link>,
        ],
        requests.length > 0 && [
          'Requests',
          <List>
            {requests.map((r) => (
              <Link key={r.stem} to={hrefForObject({ kind: ObjectKind.REQUEST, id: r.stem })}>
                <T cap={CAPS['Request.stem']}>{r.stem}</T>
              </Link>
            ))}
          </List>,
        ],
      ]}
    />
  );
}

/** What a certification is called in a link: its kind and its subject. */
function certTitle(c: Certification | undefined): ReactNode {
  if (!c) return '-';
  return (
    <>
      {CERTIFICATION_KIND_WORD[c.kind]} of <T cap={CAPS['ObjectRef.label']}>{c.subject?.label}</T>
    </>
  );
}

function CertificationFacts({ ix, c }: { ix: InvIndex; c: Certification }) {
  const issuer = ix.keys.get(c.issuer);
  return (
    <Facts
      rows={[
        ['Kind', CERTIFICATION_KIND_WORD[c.kind]],
        ['Issuer', issuer ? <KeyLink ix={ix} fingerprint={c.issuer} /> : '-'],
        c.subject && [
          'For',
          objectSlug(c.subject.kind) ? (
            <Link to={hrefForObject(c.subject)}>
              <T cap={CAPS['ObjectRef.label']}>{c.subject.label}</T>
            </Link>
          ) : (
            <T cap={CAPS['ObjectRef.label']}>{c.subject.label}</T>
          ),
        ],
        ['From', ymd(c.validFrom)],
        ['Until', <DayAndCount ix={ix} ts={c.validUntil} />],
        !!c.ceremonyId && ['Ceremony', <Link to={href.history(c.ceremonyId)}><T cap={CAPS['CeremonyRef.id']}>{c.ceremonyId}</T></Link>],
      ]}
    />
  );
}

function RequestFacts({ ix, r }: { ix: InvIndex; r: Request }) {
  return (
    <Facts
      rows={[
        ['Stem', <T cap={CAPS['Request.stem']}>{r.stem}</T>],
        [
          'Delegation',
          ix.delegations.has(r.delegation) ? (
            <Link to={hrefForObject({ kind: ObjectKind.DELEGATION, id: r.delegation })}>
              <T cap={CAPS['Delegation.name']}>{r.delegation}</T>
            </Link>
          ) : (
            <T cap={CAPS['Delegation.name']}>{r.delegation}</T>
          ),
        ],
        ['Kind', DELEGATION_TYPE_WORD[r.type]],
        !!r.key && ['Key of the requester', <Fp value={r.key} />, 'block'],
        ['Answer', REQUEST_OUTCOME_WORD[r.outcome]],
        !!r.code && ['Reason code', <T cap={CAPS['Request.code']}>{r.code}</T>],
        !!r.answeredAt && ['Answered on', ymd(r.answeredAt)],
        !!r.ceremonyId && ['Ceremony', <Link to={href.history(r.ceremonyId)}><T cap={CAPS['CeremonyRef.id']}>{r.ceremonyId}</T></Link>],
        !!r.answerPath && ['Answer in', <PathCopy path={r.answerPath} cap={CAPS['Request.answer_path']} />],
      ]}
    />
  );
}

// ---- the other sections --------------------------------------------------------------

function ChangesSection({ changes }: { changes: Change[] }) {
  if (changes.length === 0) return null;
  return (
    <PanelSection title={`Not applied yet (${changes.length})`}>
      <ul className="m-0 list-none space-y-1.5 p-0">
        {changes.map((c) => (
          <li key={c.id}>
            <Link to={hrefForChange(c)}>
              <T cap={CAPS['Change.text']}>{c.text}</T>
            </Link>{' '}
            <span className="text-dim">{CHANGE_STATE_WORD[c.state]}</span>
          </li>
        ))}
      </ul>
    </PanelSection>
  );
}

/** The most ceremonies the panel lists before it says "and N more". */
const TOUCHED_SHOWN = 5;

function CeremoniesSection({ touchedBy }: { touchedBy: CeremonyRef[] }) {
  if (touchedBy.length === 0) return null;
  const newest = [...touchedBy].sort((a, b) => Number((b.at?.seconds ?? 0n) - (a.at?.seconds ?? 0n)));
  const more = newest.length - TOUCHED_SHOWN;
  return (
    <PanelSection title={`Ceremonies (${newest.length})`}>
      <ul className="m-0 list-none space-y-0.5 p-0">
        {newest.slice(0, TOUCHED_SHOWN).map((c) => (
          <li key={c.id}>
            <Link to={href.history(c.id)}>
              {ymd(c.at)} {CEREMONY_COMMAND_WORD[c.command] ?? ''}
            </Link>
          </li>
        ))}
      </ul>
      {more > 0 ? (
        <p>
          <Link to={href.history()}>and {more} more</Link>
        </p>
      ) : null}
    </PanelSection>
  );
}

/** The one place a Cmd says that the command line is an example: the last command of the panel. */
function CommandNote() {
  return isDemo ? (
    <p className="text-sm text-dim" role="note">
      Example only. The ritueel command line is not built yet.
    </p>
  ) : null;
}

// ---- the panel -------------------------------------------------------------------------

interface Parts {
  kind: string;
  title: ReactNode;
  facts: ReactNode;
  slots?: ReactNode;
  changes: Change[];
  wanted?: ReactNode;
  touchedBy: CeremonyRef[];
  revoke?: ReactNode;
}

function partsOf(ix: InvIndex, found: Found): Parts {
  const key = keyOfObject({ kind: found.kind, id: idOf(found) });
  const changes = changesOn(ix, [key]);
  const none = { changes, touchedBy: [] as CeremonyRef[] };
  switch (found.kind) {
    case 'card': {
      const c = found.value;
      return {
        ...none,
        kind: CARD_KIND_WORD[c.kind] ?? 'card',
        title: <T cap={CAPS['Card.name']}>{c.name}</T>,
        facts: <CardFacts c={c} />,
        slots: <SlotGrids card={c} />,
        touchedBy: c.touchedBy,
        revoke: c.revokeCommand ? <RevokeSection command={c.revokeCommand} what="card" /> : undefined,
      };
    }
    case 'root': {
      const r = found.value;
      return {
        ...none,
        kind: ROOT_KIND_WORD[r.kind] ?? 'root',
        title: <T cap={CAPS['Root.name']}>{r.name}</T>,
        facts: <RootFacts ix={ix} r={r} />,
        touchedBy: r.touchedBy,
        wanted: r.wantedPath ? <WantedSection path={r.wantedPath} /> : undefined,
      };
    }
    case 'key': {
      const k = found.value;
      const root = ix.roots.get(k.root);
      const delegated = k.role === KeyRole.DELEGATED_KEY;
      return {
        ...none,
        kind: (delegated ? DELEGATED_KEY_WORD : ROOT_KEY_WORD)[k.kind] ?? 'key',
        title: keyTitle(k),
        facts: <KeyFacts ix={ix} k={k} />,
        touchedBy: k.touchedBy,
        wanted: !delegated && root?.wantedPath ? <KeyWantedSection path={root.wantedPath} /> : undefined,
        revoke: k.revokeCommand ? (
          <RevokeSection command={k.revokeCommand} what="key" rootKey={!delegated} ambiguous={ix.inv.keys.filter((o) => o.revokeCommand === k.revokeCommand).length > 1} />
        ) : undefined,
      };
    }
    case 'userid': {
      const u = found.value;
      const own = changes.find((c) => c.wantedPath)?.wantedPath;
      return {
        ...none,
        kind: OBJECT_KIND_WORD[ObjectKind.USER_ID],
        title: <T cap={CAPS['UserId.text']}>{u.text}</T>,
        facts: <UserIdFacts ix={ix} u={u} />,
        touchedBy: u.touchedBy,
        wanted: <WantedSection path={own || USER_ID_FILE} />,
      };
    }
    case 'delegation': {
      const d = found.value;
      return {
        ...none,
        kind: DELEGATION_TYPE_WORD[d.type] ?? 'delegation',
        title: <T cap={CAPS['Delegation.name']}>{d.name}</T>,
        facts: <DelegationFacts ix={ix} d={d} />,
        touchedBy: d.touchedBy,
        wanted: d.wantedPath ? <WantedSection path={d.wantedPath} /> : undefined,
      };
    }
    case 'certification': {
      const c = found.value;
      return {
        ...none,
        kind: OBJECT_KIND_WORD[ObjectKind.CERTIFICATION],
        title: certTitle(c),
        facts: <CertificationFacts ix={ix} c={c} />,
        touchedBy: c.touchedBy,
      };
    }
    case 'request': {
      const r = found.value;
      return {
        ...none,
        kind: OBJECT_KIND_WORD[ObjectKind.REQUEST],
        title: <T cap={CAPS['Request.stem']}>{r.stem}</T>,
        facts: <RequestFacts ix={ix} r={r} />,
        touchedBy: r.touchedBy,
        wanted: r.path ? (
          <PanelSection title="Request in">
            <PathCopy path={r.path} cap={CAPS['Request.path']} />
          </PanelSection>
        ) : undefined,
      };
    }
  }
}

/** The one file of user IDs in the contract (a wanted file of the bundle). */
const USER_ID_FILE = 'want/openpgp.yaml';

function idOf(f: Found): string {
  switch (f.kind) {
    case 'card':
      return f.value.name;
    case 'root':
      return f.value.name;
    case 'key':
      return f.value.fingerprint;
    case 'userid':
      return f.value.id;
    case 'delegation':
      return f.value.name;
    case 'certification':
      return f.value.id;
    case 'request':
      return f.value.stem;
  }
}

/**
 * The wanted file of a root, a delegation or a user ID, as a path to copy. The
 * page builds no command (proto/README.md, rule 7): the contract has no field
 * for a command that opens a wanted file, and two wanted files can share a
 * name (a root and a delegation, `acme-release`), so the panel shows the path.
 */
function WantedSection({ path }: { path: string }) {
  return (
    <PanelSection title="Wanted in">
      <PathCopy path={path} cap={CAPS['Root.wanted_path']} />
    </PanelSection>
  );
}

function KeyWantedSection({ path }: { path: string }) {
  return (
    <PanelSection title="Wanted in">
      <p>A key is a line in the file of its root:</p>
      <PathCopy path={path} cap={CAPS['Root.wanted_path']} />
    </PanelSection>
  );
}

function RevokeSection({ command, what, rootKey = false, ambiguous = false }: { command: string; what: 'key' | 'card'; rootKey?: boolean; ambiguous?: boolean }) {
  return (
    <PanelSection title={what === 'card' ? 'If this card is lost' : 'If this key is lost or exposed'}>
      <Cmd label="Show this in the terminal" note={false}>
        {command}
      </Cmd>
      {what === 'key' ? <p>The form of this command is proposed in the command reference.</p> : null}
      {ambiguous ? (
        <p>
          This command names more than one key of this bundle (issue 137). Check in the terminal which key it opens.
        </p>
      ) : null}
      {rootKey ? <p>What only this key certified is critical in ritueel status until a ceremony certifies it again.</p> : null}
      <CommandNote />
    </PanelSection>
  );
}

export function NotInBundle({ slug, view }: { slug: ObjectSlug; view: InventoryView }) {
  return (
    <PanelFrame kind={slugWord(slug)} title="Not in this bundle." backHref={href.inventory(view)}>
      <p>No object with this name is listed. It may belong to another example bundle.</p>
    </PanelFrame>
  );
}

const slugWord = (slug: ObjectSlug): string =>
  ({ card: 'card', root: 'root', key: 'key', userid: 'user ID', delegation: 'delegation', certification: 'certification', request: 'request' })[slug];

/**
 * The panel of one object of the inventory. `object` is the object the address
 * names, or the first object of the view when the screen is wide and the
 * address names none. The panel shows the same sections in every view; a line
 * that the view does not list says so.
 */
export function Panel({ ix, view, object }: { ix: InvIndex; view: InventoryView; object: ObjectId }) {
  const found = lookup(ix, object);
  if (!found) return <NotInBundle slug={object.kind} view={view} />;
  const p = partsOf(ix, found);
  const listed = listedIn(ix, view, object);
  return (
    <PanelFrame kind={p.kind} title={p.title} backHref={href.inventory(view)} rowId={domKey(keyOfObject(object))}>
      {listed ? null : <p className="text-sm text-dim">Not listed in this view.</p>}
      <PanelSection title="Facts">{p.facts}</PanelSection>
      {p.slots ? (
        <PanelSection title="Slots">{p.slots}</PanelSection>
      ) : null}
      <ChangesSection changes={p.changes} />
      {p.wanted}
      <CeremoniesSection touchedBy={p.touchedBy} />
      {p.revoke}
    </PanelFrame>
  );
}
