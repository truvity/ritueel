import type { ReactNode } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import useMediaQuery from '@mui/material/useMediaQuery';
import { ObjectKind, Store } from '../gen/ritueel/local/v1alpha1/common_pb';
import { KeyRole, type Change, type Key } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { combine, useInventory, useSummary } from '../api/hooks';
import { CAPS } from '../lib/caps';
import { daysBetween, ymd } from '../lib/format';
import {
  buildIndex,
  cardGroups,
  cardRollup,
  changeIds,
  changesOn,
  dateRows,
  domKey,
  endsIn,
  firstObject,
  inventoryHrefs,
  inventoryIsEmpty,
  keyEndWord,
  keyOfObject,
  objectKey,
  rootGroups,
  rootRollup,
  viewIsEmpty,
  type CardGroup,
  type CardLine,
  type DelegationLine,
  type InvIndex,
  type ObjectId,
  type RootGroup,
} from '../lib/inventory';
import { href, type InventoryView } from '../lib/route';
import { CARD_KIND_WORD, DELEGATED_KEY_WORD, DELEGATION_TYPE_WORD, KEY_STATE_WORD, REQUEST_OUTCOME_WORD, ROOT_KEY_WORD, ROOT_KIND_WORD, CERTIFICATION_KIND_WORD } from '../lib/words';
import { ChangeMark } from '../ui/ChangeMark';
import { DataTable, RowLink, type Column, type Group } from '../ui/DataTable';
import { Page } from '../ui/Page';
import { GoToPanel, Panel } from '../ui/Panel';
import { ReadTime } from '../ui/ReadTime';
import { Empty, Load } from '../ui/Sec';
import { SplitView } from '../ui/SplitView';
import { T } from '../ui/T';

// Inventory: where every key is, what it is for, and what ends when.
// One screen: three views of the same answer (by card, by root, by date) and
// one panel at the right. The panel shows the object the address names; when it
// names none and the screen is 1440 px or wider, the first object of the view.
// Below 1440 px nothing is implied: the list shows first, and a chosen line
// shows the panel in place of the list.
//
// A change not applied yet is marked on its object in every view that lists the
// object. The marks carry data attributes (`data-object`, `data-changes`, and
// `data-key-fp` on a key) so the tests can check the rule from the markup.

const WIDE = '(min-width:1440px)';

const dim = (text: ReactNode) => <span className="text-dim">{text}</span>;

// ---- the view switch ---------------------------------------------------------------

const VIEWS: { value: InventoryView; label: string }[] = [
  { value: 'cards', label: 'By card' },
  { value: 'roots', label: 'By root' },
  { value: 'dates', label: 'By date' },
];

/** The chosen object stays when the view changes: the panel does not depend on the view. */
function ViewSwitch({ view, object }: { view: InventoryView; object?: ObjectId }) {
  return (
    <div className="flex items-center gap-x-3">
      <span className="text-sm font-semibold" aria-hidden>
        View
      </span>
      <ToggleButtonGroup
        exclusive
        size="small"
        value={view}
        aria-label="View"
        onChange={(_e, next: InventoryView | null) => {
          if (next) window.location.hash = href.inventory(next, object);
        }}
        sx={{ '& .MuiToggleButton-root': { minHeight: { xs: 44, lg: 36 }, fontSize: '0.875rem' } }}
      >
        {VIEWS.map((v) => (
          <ToggleButton key={v.value} value={v.value}>
            {v.label}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
    </div>
  );
}

// ---- parts shared by the views -------------------------------------------------------

/** The attributes of a line that stands for an object: its name, and the changes that mark it. */
function objectAttrs(key: string, changes: Change[]) {
  return { 'data-object': domKey(key), 'data-changes': changeIds(changes) };
}

/** The Changes cell. Nothing is drawn for a line without a change. */
const marks = (changes: Change[]) => (changes.length > 0 ? <ChangeMark count={changes.length} /> : null);

/** A key as a table shows it: `key A` for a root key, the delegation's name for a delegated key. */
function KeyName({ k }: { k: Key }) {
  return k.role === KeyRole.DELEGATED_KEY ? <T cap={CAPS['Key.delegation']}>{k.delegation}</T> : <>key <T cap={CAPS['Key.label']}>{k.label}</T></>;
}

const keyKindWord = (k: Key) => (k.role === KeyRole.DELEGATED_KEY ? DELEGATED_KEY_WORD : ROOT_KEY_WORD)[k.kind];

/** Where a key is kept, in a few words. */
function placeWord(k: Key): ReactNode {
  const p = k.place;
  switch (p?.store) {
    case Store.PIV:
    case Store.OPENPGP_CARD:
      return (
        <>
          card <T cap={CAPS['Place.card']}>{p.card}</T> {'·'} <T cap={CAPS['Place.slot']}>{p.slot}</T>
        </>
      );
    case Store.AWS_KMS:
      return 'cloud key';
    case Store.SOFTWARE:
      return 'key file';
    default:
      return null;
  }
}

/** A line that stands for one key, with the attributes the three views share. */
function keyAttrs(ix: InvIndex, k: Key) {
  const key = objectKey({ kind: ObjectKind.KEY, id: k.fingerprint }) as string;
  return { ...objectAttrs(key, changesOn(ix, [key])), 'data-key-fp': domKey(k.fingerprint) };
}

// ---- By card ---------------------------------------------------------------------------

function CardsView({ ix, shown }: { ix: InvIndex; shown?: ObjectId }) {
  const to = inventoryHrefs('cards');
  const shownKey = shown ? keyOfObject(shown) : undefined;
  const groups = cardGroups(ix);
  const keyRowKey = (l: CardLine) => domKey(l.kind === 'key' ? `key/${l.key.fingerprint}` : `none/${l.card}`);

  const columns: Column<CardLine>[] = [
    {
      key: 'place',
      header: 'Place',
      width: 6,
      render: (l) => {
        if (l.kind !== 'key') return null;
        const p = l.key.place;
        if (p?.store === Store.AWS_KMS) return <T cap={CAPS['Place.region']}>{p.region}</T>;
        if (p?.store === Store.SOFTWARE) return dim('key file');
        return <T cap={CAPS['Place.slot']}>{p?.slot}</T>;
      },
    },
    {
      key: 'key',
      header: 'Key',
      width: 11,
      render: (l, { current }) =>
        l.kind === 'key' ? (
          <>
            <RowLink href={to.key(l.key.fingerprint)} current={current}>
              <KeyName k={l.key} />
            </RowLink>{' '}
            {dim(keyKindWord(l.key))}
          </>
        ) : (
          dim('No key on this card.')
        ),
    },
    { key: 'for', header: 'For', width: 9, render: (l) => (l.kind === 'key' ? <T cap={CAPS['Key.root']}>{l.key.root}</T> : null) },
    { key: 'state', header: 'State', width: 5.5, render: (l) => (l.kind === 'key' ? KEY_STATE_WORD[l.key.state] : null) },
    { key: 'changes', header: 'Changes', width: 5, render: (l) => (l.kind === 'key' ? marks(changesOn(ix, [objectKey({ kind: ObjectKind.KEY, id: l.key.fingerprint })])) : null) },
  ];

  const header = (g: CardGroup): ReactNode => {
    const rollup = cardRollup(ix, g);
    if (g.kind === 'card' && g.card) {
      const key = `card/${g.card.name}`;
      return (
        <span data-row-id={domKey(key)} {...objectAttrs(key, rollup)}>
          <RowLink href={to.card(g.card.name)} current={shownKey === key}>
            <T cap={CAPS['Card.name']}>{g.card.name}</T>
          </RowLink>{' '}
          <span className="font-normal text-dim">
            {CARD_KIND_WORD[g.card.kind]} {'·'} <T cap={CAPS['Card.serial']}>{g.card.serial}</T> {'·'} firmware <T cap={CAPS['Card.firmware']}>{g.card.firmware}</T>
          </span>
        </span>
      );
    }
    if (g.kind === 'unlisted') {
      return (
        <>
          Card <T cap={CAPS['Place.card']}>{g.name}</T> <span className="font-normal text-dim">is not in the inventory</span>
        </>
      );
    }
    return g.kind === 'cloud' ? 'Cloud keys' : 'Key files';
  };

  const rows: Group<CardLine>[] = groups.map((g) => ({
    key: g.id,
    span: 3,
    header: header(g),
    aside: asideMark(cardRollup(ix, g)),
    rows: g.lines,
  }));

  return (
    <>
      <DataTable
        caption="Keys by card and cloud key."
        groups={rows}
        rowKey={keyRowKey}
        selectedKey={shownKey ? domKey(shownKey) : undefined}
        rowAttrs={(l) => (l.kind === 'key' ? keyAttrs(ix, l.key) : {})}
        columns={columns}
      />
      {ix.inv.cards.length === 0 && ix.inv.keys.length > 0 ? <p className="mt-2 max-w-[62ch] text-sm text-dim">No card is listed. A cloud root needs none.</p> : null}
    </>
  );
}

/** The roll-up in the last column of a group header: State is empty, Changes holds the mark. */
function asideMark(changes: Change[]): ReactNode {
  return changes.length === 0 ? null : (
    <div className="grid grid-cols-[5.5fr_5fr]">
      <span />
      <span>{marks(changes)}</span>
    </div>
  );
}

// ---- By root ----------------------------------------------------------------------------

type RootRow =
  | { t: 'key'; key: Key }
  | { t: 'uid'; id: string; text: string; state: string }
  | { t: 'del'; line: DelegationLine }
  | { t: 'req'; stem: string; outcome: string; delegation: string };

function rootRows(g: RootGroup): RootRow[] {
  const rows: RootRow[] = g.keys.map((key) => ({ t: 'key' as const, key }));
  for (const u of g.userIds) rows.push({ t: 'uid', id: u.id, text: u.text, state: u.revoked ? 'revoked' : u.certified ? 'active' : 'not certified yet' });
  for (const line of g.delegations) {
    rows.push({ t: 'del', line });
    for (const r of line.requests) rows.push({ t: 'req', stem: r.stem, outcome: REQUEST_OUTCOME_WORD[r.outcome], delegation: line.delegation.name });
  }
  return rows;
}

const rootRowObject = (r: RootRow): string => {
  switch (r.t) {
    case 'key':
      return `key/${r.key.fingerprint}`;
    case 'uid':
      return `userid/${r.id}`;
    case 'del':
      return `delegation/${r.line.delegation.name}`;
    case 'req':
      return `request/${r.stem}`;
  }
};

function RootsView({ ix, shown }: { ix: InvIndex; shown?: ObjectId }) {
  const to = inventoryHrefs('roots');
  const shownKey = shown ? keyOfObject(shown) : undefined;
  const groups = rootGroups(ix);

  const columns: Column<RootRow>[] = [
    {
      key: 'name',
      header: 'Name',
      width: 14,
      render: (r, { current }) => {
        switch (r.t) {
          case 'key':
            return (
              <>
                <RowLink href={to.key(r.key.fingerprint)} current={current}>
                  <KeyName k={r.key} />
                </RowLink>{' '}
                {dim(keyKindWord(r.key))}
              </>
            );
          case 'uid':
            return (
              <>
                <RowLink href={to.userId(r.id)} current={current}>
                  <T cap={CAPS['UserId.text#cell']}>{r.text}</T>
                </RowLink>{' '}
                {dim('user ID')}
              </>
            );
          case 'del':
            return (
              <>
                <RowLink href={to.delegation(r.line.delegation.name)} current={current}>
                  <T cap={CAPS['Delegation.name']}>{r.line.delegation.name}</T>
                </RowLink>{' '}
                {dim(DELEGATION_TYPE_WORD[r.line.delegation.type])}
              </>
            );
          case 'req':
            return (
              <span className="pl-4">
                <RowLink href={to.request(r.stem)} current={current}>
                  <T cap={CAPS['Request.stem']}>{r.stem}</T>
                </RowLink>{' '}
                {dim('request')}
              </span>
            );
        }
      },
    },
    { key: 'place', header: 'Place', width: 10, render: (r) => (r.t === 'key' ? placeWord(r.key) : null) },
    {
      key: 'until',
      header: 'Until',
      width: 7,
      render: (r) => {
        if (r.t === 'key') return r.key.expiresAt ? ymd(r.key.expiresAt) : keyEndWord(r.key);
        if (r.t === 'del') return r.line.certification?.validUntil ? ymd(r.line.certification.validUntil) : null;
        return null;
      },
    },
    {
      key: 'state',
      header: 'State',
      width: 5,
      render: (r) => {
        switch (r.t) {
          case 'key':
            return KEY_STATE_WORD[r.key.state];
          case 'uid':
            return r.state;
          case 'del':
            return r.line.key ? KEY_STATE_WORD[r.line.key.state] : 'no key certified yet';
          case 'req':
            return r.outcome;
        }
      },
    },
    { key: 'changes', header: 'Changes', width: 4.5, render: (r) => marks(changesOn(ix, [rootRowObject(r)])) },
  ];

  const rows: Group<RootRow>[] = groups.map((g) => {
    const key = `root/${g.root.name}`;
    const rollup = rootRollup(ix, g);
    return {
      key,
      span: 4,
      header: (
        <span data-row-id={domKey(key)} {...objectAttrs(key, rollup)}>
          <RowLink href={to.root(g.root.name)} current={shownKey === key}>
            <T cap={CAPS['Root.name']}>{g.root.name}</T>
          </RowLink>{' '}
          <span className="font-normal text-dim">{ROOT_KIND_WORD[g.root.kind]}</span>
        </span>
      ),
      aside: rollup.length === 0 ? null : marks(rollup),
      rows: rootRows(g),
    };
  });

  return (
    <DataTable
      caption="Roots, their keys, user IDs, delegations and requests."
      groups={rows}
      rowKey={(r) => domKey(rootRowObject(r))}
      selectedKey={shownKey ? domKey(shownKey) : undefined}
      rowAttrs={(r) => {
        const attrs = objectAttrs(rootRowObject(r), changesOn(ix, [rootRowObject(r)]));
        if (r.t === 'key') return keyAttrs(ix, r.key);
        // A delegation stands for its key too: the line carries the fingerprint of the key it holds.
        if (r.t === 'del' && r.line.key) return { ...attrs, 'data-key-fp': domKey(r.line.key.fingerprint) };
        return attrs;
      }}
      columns={columns}
    />
  );
}

// ---- By date ------------------------------------------------------------------------------

function DatesView({ ix, shown }: { ix: InvIndex; shown?: ObjectId }) {
  const to = inventoryHrefs('dates');
  const shownKey = shown ? keyOfObject(shown) : undefined;
  const rows = dateRows(ix);
  const objectOf = (id: string) => `certification/${id}`;

  const columns: Column<(typeof rows)[number]>[] = [
    {
      key: 'ends',
      header: 'Ends',
      width: 7,
      render: (c, { current }) => (
        <RowLink href={to.certification(c.id)} current={current}>
          {ymd(c.validUntil)}
        </RowLink>
      ),
    },
    { key: 'in', header: 'In', width: 4, render: (c) => endsIn(daysBetween(ix.inv.readAt, c.validUntil)) },
    { key: 'kind', header: 'Kind', width: 8, render: (c) => CERTIFICATION_KIND_WORD[c.kind] },
    {
      key: 'issuer',
      header: 'Issuer',
      width: 7,
      render: (c) => {
        const k = ix.keys.get(c.issuer);
        if (!k) return null;
        return (
          <span data-key-fp={domKey(k.fingerprint)}>
            <KeyName k={k} />
            <span className="block text-dim">
              <T cap={CAPS['Key.root']}>{k.root}</T>
            </span>
          </span>
        );
      },
    },
    {
      key: 'for',
      header: 'For',
      width: 11,
      render: (c) => {
        const s = c.subject;
        if (!s) return null;
        const label = <T cap={CAPS['ObjectRef.label']}>{s.label}</T>;
        return s.kind === ObjectKind.KEY && ix.keys.has(s.id) ? <span data-key-fp={domKey(s.id)}>{label}</span> : label;
      },
    },
    { key: 'changes', header: 'Changes', width: 5, render: (c) => marks(changesOn(ix, [objectOf(c.id)])) },
  ];

  return (
    <DataTable
      caption="Certifications by end date, soonest first."
      rows={rows}
      rowKey={(c) => domKey(objectOf(c.id))}
      selectedKey={shownKey ? domKey(shownKey) : undefined}
      rowAttrs={(c) => objectAttrs(objectOf(c.id), changesOn(ix, [objectOf(c.id)]))}
      columns={columns}
    />
  );
}

// ---- empty views ----------------------------------------------------------------------------

const WANT_LIST = { text: 'ritueel want', label: 'List the wanted files in the terminal' };

function EmptyView({ view }: { view: InventoryView }) {
  switch (view) {
    case 'cards':
      return (
        <Empty title="No card is listed." command={WANT_LIST}>
          <p>The inventory lists the cards the wanted files name. This bundle names none yet.</p>
        </Empty>
      );
    case 'roots':
      return (
        <Empty title="No root yet." command={WANT_LIST}>
          <p>A root is a file in want/roots/. This bundle has none yet.</p>
        </Empty>
      );
    case 'dates':
      return (
        <Empty title="No certification yet." command={WANT_LIST}>
          <p>A certification appears when a ceremony has signed.</p>
        </Empty>
      );
  }
}

// ---- the screen ---------------------------------------------------------------------------------

export function Inventory({ view, object }: { view: InventoryView; object?: ObjectId }) {
  const summary = useSummary();
  const inventory = useInventory();
  const res = combine(summary, inventory);
  const wide = useMediaQuery(WIDE);
  const ready = res.state === 'ready' ? res.data : undefined;
  return (
    <Page
      title="Inventory"
      line={
        ready ? (
          <>
            <T cap={CAPS['Bundle.name']}>{ready[0].bundle?.name}</T> {'·'} <ReadTime ts={ready[1].readAt} />
          </>
        ) : undefined
      }
      aside={<ViewSwitch view={view} object={object} />}
    >
      <Load
        res={res}
        what="the inventory"
        isEmpty={([, inv]) => inventoryIsEmpty(inv)}
        empty={
          <Empty title="Nothing in the inventory yet." command={WANT_LIST}>
            <p>The inventory lists what the wanted files name. This bundle names nothing yet.</p>
          </Empty>
        }
      >
        {([, inv]) => {
          const ix = buildIndex(inv);
          // The panel shows the chosen object, or on a wide screen the first one of the view.
          const shown = object ?? (wide ? firstObject(ix, view) : undefined);
          const empty = viewIsEmpty(ix, view);
          const list = empty ? (
            <EmptyView view={view} />
          ) : (
            <>
              <GoToPanel />
              {view === 'cards' ? <CardsView ix={ix} shown={shown} /> : view === 'roots' ? <RootsView ix={ix} shown={shown} /> : <DatesView ix={ix} shown={shown} />}
            </>
          );
          return <SplitView list={list} right={shown ? <Panel ix={ix} view={view} object={shown} /> : null} panelOpen={object !== undefined} />;
        }}
      </Load>
    </Page>
  );
}
