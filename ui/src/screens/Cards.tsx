import { useState, type ReactNode } from 'react';
import Button from '@mui/material/Button';
import Popover from '@mui/material/Popover';
import {
  ApplicationUse,
  CardKind,
  CardState,
  SlotState,
  SlotUse,
  type Card,
  type PivRow,
  type Slot,
} from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { combine, useBundleName, useCards, useFindings, useRoots, useSummary } from '../api/hooks';
import { agoDays, daysBetween, plural, rootRef, ymd } from '../lib/format';
import { href } from '../lib/route';
import { isSerial, safeString } from '../lib/safe';
import { CARD_KIND_WORD, CARD_STATE_WORD, PIN_WORD, SLOT_STATE_WORD, SLOT_USE_TAG, TOUCH_WORD } from '../lib/words';
import { Cmd } from '../ui/Cmd';
import { Fp } from '../ui/Fp';
import { Glyph } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Explain, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';
import { CAPS } from '../lib/caps';

const LINK = 'font-semibold text-accent underline underline-offset-4';

// ---- one slot -----------------------------------------------------------------
// Drawn by state in four ways, so colour is never the only cue:
//   in use: solid   reserved: dashed   spare: dotted   empty: thin line

function slotClass(state: SlotState): string {
  switch (state) {
    case SlotState.USED:
      return 'bg-ink text-bg border-2 border-ink';
    case SlotState.RESERVED:
      return 'border-2 border-dashed border-ink text-ink bg-[color-mix(in_srgb,var(--mui-palette-primary-main)_16%,transparent)]';
    case SlotState.SPARE:
      return 'border-2 border-dotted border-dim text-dim bg-sunk';
    default:
      return 'border border-dim/70 text-dim';
  }
}

function slotLabel(slot: Slot, tag: string, group: string): string {
  return `${group} slot ${safeString(slot.id, 12)}: ${SLOT_STATE_WORD[slot.state] ?? ''}${tag ? `, ${safeString(tag, 20)}` : ''}${slot.purpose ? `. ${safeString(slot.purpose, 200)}` : ''}`;
}

function SlotInfo({ slot, group }: { slot: Slot; group: string }) {
  const bundle = useBundleName();
  return (
    <div className="max-w-[24rem] min-w-[16rem] space-y-2 p-4">
      <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">
        {group} slot <T cap={CAPS['Slot.id']}>{slot.id}</T>
      </p>
      <p className="text-lg leading-snug font-bold">
        <T cap={CAPS['Slot.purpose']}>{slot.purpose || SLOT_STATE_WORD[slot.state]}</T>
      </p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-dim">State</dt>
        <dd>{SLOT_STATE_WORD[slot.state]}</dd>
        {slot.rootLabel ? (
          <>
            <dt className="text-dim">Root</dt>
            <dd>
              <T cap={60}>{rootRef(bundle, slot.rootLabel)}</T>
            </dd>
          </>
        ) : null}
        {slot.algorithm ? (
          <>
            <dt className="text-dim">Algorithm</dt>
            <dd className="font-mono">
              <T cap={CAPS['Slot.algorithm']}>{slot.algorithm}</T>
            </dd>
          </>
        ) : null}
        <dt className="text-dim">PIN</dt>
        <dd>{PIN_WORD[slot.pinRule] ?? 'not set by the card'}</dd>
        <dt className="text-dim">Touch</dt>
        <dd>{TOUCH_WORD[slot.touchRule] ?? 'not set by the card'}</dd>
        {slot.bornAt ? (
          <>
            <dt className="text-dim">Made</dt>
            <dd>{ymd(slot.bornAt)}</dd>
          </>
        ) : null}
        {slot.use === SlotUse.OTHER_BUNDLE ? null : (
          <>
            <dt className="text-dim">Attested</dt>
            <dd>{slot.attested ? 'yes, the card vouches for it' : 'no'}</dd>
          </>
        )}
      </dl>
      {slot.use === SlotUse.OTHER_BUNDLE ? (
        <p className="text-sm">A row of another bundle of the holder, declared in this card&apos;s file. ritueel shows no key digest for it.</p>
      ) : null}
      {slot.publicKeySha256 ? (
        <div>
          <p className="text-sm text-dim">Fingerprint of the public key (SHA-256)</p>
          <Fp value={slot.publicKeySha256} className="text-xs" />
        </div>
      ) : null}
    </div>
  );
}

/** A slot that holds something is a button that opens its details. An empty or spare slot is only drawn. */
function SlotCell({ slot, group, tagFallback }: { slot: Slot; group: string; tagFallback?: string }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const tag = SLOT_USE_TAG[slot.use] ?? tagFallback ?? '';
  const label = slotLabel(slot, tag, group);
  const body = (
    <>
      <span className="text-xs leading-none font-bold">
        <T cap={CAPS['Slot.id']}>{slot.id}</T>
      </span>
      <span className="truncate text-xs leading-none font-bold">{tag ? <T cap={20}>{tag}</T> : ' '}</span>
    </>
  );
  const cls = `flex min-h-12 min-w-0 flex-col justify-between px-1.5 py-1.5 font-mono ${slotClass(slot.state)}`;
  if (slot.state !== SlotState.USED && slot.state !== SlotState.RESERVED) {
    return (
      <div role="img" aria-label={label} className={cls}>
        {body}
      </div>
    );
  }
  return (
    <>
      <button type="button" aria-label={`${label}. Show its details.`} aria-haspopup="dialog" aria-expanded={anchor ? 'true' : undefined} onClick={(e) => setAnchor(e.currentTarget)} className={`${cls} w-full cursor-pointer text-left`}>
        {body}
      </button>
      <Popover
        open={anchor !== null}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        slotProps={{ paper: { role: 'dialog', 'aria-label': `Slot ${safeString(slot.id, 12)}`, sx: { maxWidth: 'calc(100vw - 24px)' } } as object }}
      >
        <SlotInfo slot={slot} group={group} />
        <div className="border-t border-line p-2">
          <Button onClick={() => setAnchor(null)}>Close</Button>
        </div>
      </Popover>
    </>
  );
}

function Legend() {
  const items: [SlotState, string, string][] = [
    [SlotState.USED, 'In use', 'solid'],
    [SlotState.RESERVED, 'Reserved: planned, not born yet', 'dashed'],
    [SlotState.SPARE, 'Spare: no root owns the row yet', 'dotted'],
    [SlotState.EMPTY, 'Empty', 'thin line'],
  ];
  return (
    <ul className="flex flex-wrap gap-x-6 gap-y-2 text-sm" aria-label="How a slot is drawn">
      {items.map(([s, word, shape]) => (
        <li key={s} className="flex items-center gap-2">
          <span className={`inline-block h-5 w-8 ${slotClass(s)}`} aria-hidden />
          <span>
            <strong>{word}</strong> <span className="text-dim">({shape})</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

// ---- PIV, OpenPGP, passkeys ------------------------------------------------------

function RowLabel({ row }: { row: PivRow }) {
  const free = row.label === 'free';
  return (
    <div className="flex min-w-0 flex-col justify-center pr-1 leading-tight">
      <span className="text-xs text-dim">row {row.number}</span>
      <span className={`truncate text-xs font-bold ${free ? 'text-dim' : ''}`}>
        <T cap={CAPS['PivRow.label']}>{row.label}</T>
      </span>
    </div>
  );
}

function PivGrid({ card }: { card: Card }) {
  const rows = card.piv?.rows ?? [];
  return (
    <div className="grid gap-1" style={{ gridTemplateColumns: '3.4rem repeat(4, minmax(0, 1fr))' }}>
      {rows.map((row) => (
        <div key={row.number} className="contents">
          <RowLabel row={row} />
          {row.slots.map((s) => (
            <SlotCell key={s.id} slot={s} group="PIV" />
          ))}
        </div>
      ))}
    </div>
  );
}

function Piv({ card }: { card: Card }) {
  const rows = card.piv?.rows ?? [];
  const states = rows.flatMap((r) => r.slots.map((s) => s.state));
  const used = states.filter((s) => s === SlotState.USED).length;
  const reserved = states.filter((s) => s === SlotState.RESERVED).length;
  const inUse = card.piv?.use === ApplicationUse.IN_USE;
  return (
    <div className="min-w-0">
      <h3 className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 text-lg font-bold">
        <span>PIV, 24 slots in 6 rows</span>
        <span className="sr-only">: </span>
        <span className="text-sm font-normal text-dim">{inUse ? `${used} in use, ${reserved} reserved` : 'not used'}</span>
      </h3>
      {inUse ? (
        <PivGrid card={card} />
      ) : (
        <details className="border border-line">
          <summary className="min-h-11 cursor-pointer px-3 py-2.5 text-[0.9375rem]">PIV is not used on this card. All 24 slots are empty. Show them.</summary>
          <div className="border-t border-line p-2">
            <PivGrid card={card} />
          </div>
        </details>
      )}
    </div>
  );
}

function OpenPgp({ card }: { card: Card }) {
  const slots = card.openpgp?.slots ?? [];
  const inUse = card.openpgp?.use === ApplicationUse.IN_USE;
  return (
    <div className="min-w-0">
      <h3 className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 text-lg font-bold">
        <span>OpenPGP, 3 slots</span>
        <span className="sr-only">: </span>
        <span className="text-sm font-normal text-dim">{inUse ? 'in use' : 'not used'}</span>
      </h3>
      <div className="grid grid-cols-3 gap-1">
        {slots.map((s) => (
          <SlotCell key={s.id} slot={s} group="OpenPGP" tagFallback={s.id.toUpperCase()} />
        ))}
      </div>
    </div>
  );
}

function Passkeys({ card }: { card: Card }) {
  const keys = card.fido2?.passkeys ?? [];
  const inUse = card.fido2?.use === ApplicationUse.IN_USE;
  return (
    <div className="min-w-0">
      <h3 className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3 text-lg font-bold">
        <span>Passkeys (FIDO2)</span>
        <span className="sr-only">: </span>
        <span className="text-sm font-normal text-dim">{inUse ? `${keys.filter((k) => k.state === SlotState.USED).length} of ${keys.length}` : 'not used'}</span>
      </h3>
      {keys.length === 0 ? (
        <p className="border border-dashed border-line p-3 text-sm text-dim">No passkey is stored on this card.</p>
      ) : (
        <ul className="space-y-1">
          {keys.map((k) => (
            <li key={k.id}>
              <SlotCell slot={k} group="Passkey" tagFallback={`#${k.id}`} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Every slot's meaning, written out: nothing depends on opening a popover, on hover, or on touch. */
function WrittenOut({ card }: { card: Card }) {
  const piv = (card.piv?.rows ?? []).flatMap((r) => r.slots.filter((s) => s.purpose).map((s) => ({ s, group: 'PIV', row: r.number })));
  const pgp = (card.openpgp?.slots ?? []).filter((s) => s.purpose).map((s) => ({ s, group: 'OpenPGP', row: 0 }));
  const fido = (card.fido2?.passkeys ?? []).filter((s) => s.purpose).map((s) => ({ s, group: 'Passkey', row: 0 }));
  const all = [...piv, ...pgp, ...fido];
  if (all.length === 0) return <p className="text-dim">Nothing is stored on this card yet. Every slot is empty.</p>;
  return (
    <dl className="divide-y divide-line border border-line bg-panel">
      {all.map(({ s, group, row }) => (
        <div key={`${group}-${s.id}`} className="grid gap-x-4 gap-y-0.5 p-3 sm:grid-cols-[9rem_minmax(0,1fr)]">
          <dt className="font-mono text-sm font-bold">
            {group} <T cap={CAPS['Slot.id']}>{s.id}</T>
            {row ? <span className="font-normal text-dim"> (row {row})</span> : null}
          </dt>
          <dd>
            <T cap={CAPS['Slot.purpose']}>{s.purpose}</T>
            <span className="block text-sm text-dim">
              {SLOT_STATE_WORD[s.state]}
              {s.algorithm ? `, ${safeString(s.algorithm, 30)}` : ''}. PIN {PIN_WORD[s.pinRule] ?? 'not set'}. Touch {TOUCH_WORD[s.touchRule] ?? 'not set'}.
            </span>
          </dd>
        </div>
      ))}
    </dl>
  );
}

// ---- one card, opened --------------------------------------------------------------

function CardHead({ card, asOf }: { card: Card; asOf: Parameters<typeof daysBetween>[1] }) {
  const checked = daysBetween(card.lastCheckedAt, asOf);
  const ok = card.state === CardState.ACTIVE;
  return (
    <div className="border-2 border-rule bg-panel">
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b-2 border-rule bg-sunk px-4 py-3">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2">
            <span className={`px-2 py-0.5 font-mono text-xs font-bold tracking-wider uppercase ${card.kind === CardKind.ROOT ? 'bg-ink text-bg' : 'border border-ink'}`}>
              {CARD_KIND_WORD[card.kind] ?? 'Card'}
            </span>
            <span className="font-mono text-sm font-bold">
              <T cap={CAPS['Card.serial']}>{card.serial}</T>
            </span>
          </p>
          <h2 className="mt-1 text-2xl leading-tight font-bold">
            <T cap={CAPS['Card.name']}>{card.name}</T>
          </h2>
        </div>
        <div className="text-sm leading-snug text-dim sm:text-right">
          <p className="flex items-center gap-1.5 font-bold text-ink sm:justify-end">
            <Glyph level={ok ? 'ok' : 'critical'} size={14} /> {CARD_STATE_WORD[card.state] ?? 'unknown'}
          </p>
          <p>
            <T cap={CAPS['Card.model']}>{card.model}</T>, firmware <T cap={CAPS['Card.firmware']}>{card.firmware}</T>
          </p>
        </div>
      </header>
      <div className="space-y-3 p-4">
        <p className="max-w-[70ch]">
          <T cap={CAPS['Card.role_summary']}>{card.roleSummary}</T>
        </p>
        <p className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-dim">
          <span>
            Kept: <span className="text-ink"><T cap={CAPS['Card.kept']}>{card.kept}</T></span>
          </span>
          <span>
            Last read: <span className="text-ink">{ymd(card.lastCheckedAt)}</span> ({agoDays(checked)})
          </span>
          <span>One-time codes: {card.oneTimeCodesOff ? 'off' : <strong className="text-alert">on</strong>}</span>
        </p>
        <ChangedBanner card={card} />
      </div>
    </div>
  );
}

function ChangedBanner({ card }: { card: Card }) {
  if (card.changesSinceLastReading.length === 0) return null;
  return (
    <div role="note" className="flex gap-2.5 border-2 border-alert p-3">
      <Glyph level="alert" size={18} />
      <div>
        <p className="font-mono text-xs font-bold tracking-wider text-alert uppercase">Changed since the last reading</p>
        {card.changesSinceLastReading.map((c, i) => (
          <p key={i}>
            <T cap={CAPS['Card.changes_since_last_reading']}>{c}</T>
          </p>
        ))}
      </div>
    </div>
  );
}

function CardPage({ serial }: { serial: string }) {
  const cards = useCards();
  const summary = useSummary();
  const roots = useRoots();
  const findings = useFindings();
  return (
    <Page kicker="Cards" title={`Card ${safeString(serial, 40)}`} aside={<a className={LINK} href={href.cards()}>Back to the inventory</a>}>
      <Load res={combine(cards, summary)} what="the card">
        {([c, s]) => {
          const card = c.cards.find((x) => x.serial === serial);
          if (!card) {
            const sets = roots.state === 'ready' ? roots.data.roots.flatMap((r) => (r.certificate?.subkeySets ?? []).filter((x) => x.cardSerial === serial)) : [];
            const fix = findings.state === 'ready' ? findings.data.findings.find((f) => f.subject?.identifier === serial)?.fixCommand : undefined;
            // The page builds a command only for a serial that is digits: a serial from the address bar is data too.
            const cmd = fix || (isSerial(serial) ? `ritueel card adopt --card ${serial} --plan-only` : undefined);
            return (
              <Empty title={`Card ${safeString(serial, 40)} is not in your inventory.`} command={sets.length > 0 && cmd ? { text: cmd, label: 'Add the card to the inventory' } : undefined}>
                <p>
                  {sets.length > 0 ? (
                    <>
                      ritueel knows this card only because subkeys of your key sit on it: the sets of {sets.map((x) => x.year).join(', ')}. You cannot revoke or replace what you cannot find, so a card that holds keys should be in the inventory.
                    </>
                  ) : (
                    'No card with this serial is in the inventory, and no key is known to sit on it.'
                  )}
                </p>
              </Empty>
            );
          }
          return (
            <>
              <CardHead card={card} asOf={s.asOf} />
              <div className="grid gap-x-8 gap-y-8 lg:grid-cols-[minmax(0,1.45fr)_minmax(0,1fr)]">
                <Piv card={card} />
                <div className="min-w-0 space-y-8">
                  <OpenPgp card={card} />
                  <Passkeys card={card} />
                </div>
              </div>
              <Sec title="What every slot is for">
                <WrittenOut card={card} />
              </Sec>
            </>
          );
        }}
      </Load>
    </Page>
  );
}

// ---- the inventory -------------------------------------------------------------------

function MiniGrid({ card }: { card: Card }) {
  const rows = card.piv?.rows ?? [];
  return (
    <div aria-hidden className="grid shrink-0 grid-cols-4 content-start gap-[3px] self-start">
      {rows.flatMap((r) => r.slots).map((s) => (
        <span key={s.id} className={`block h-2.5 w-2.5 ${slotClass(s.state)} ${s.state === SlotState.EMPTY ? '' : ''}`} style={{ borderWidth: s.state === SlotState.EMPTY ? 1 : 1.5 }} />
      ))}
    </div>
  );
}

function CardTile({ card }: { card: Card }) {
  const slots = (card.piv?.rows ?? []).flatMap((r) => r.slots);
  const used = slots.filter((s) => s.state === SlotState.USED).length + (card.openpgp?.slots ?? []).filter((s) => s.state === SlotState.USED).length;
  return (
    <li className="flex gap-4 border-2 border-rule bg-panel p-4">
      <MiniGrid card={card} />
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-2">
          <span className={`px-2 py-0.5 font-mono text-xs font-bold tracking-wider uppercase ${card.kind === CardKind.ROOT ? 'bg-ink text-bg' : 'border border-ink'}`}>{CARD_KIND_WORD[card.kind]}</span>
          <span className="font-mono text-sm font-bold">
            <T cap={CAPS['Card.serial']}>{card.serial}</T>
          </span>
        </p>
        <h3 className="mt-1 text-xl leading-tight font-bold">
          <T cap={CAPS['Card.name']}>{card.name}</T>
        </h3>
        <p className="mt-1 text-[0.9375rem] text-dim">
          <T cap={CAPS['Card.role_summary']}>{card.roleSummary}</T>
        </p>
        <p className="mt-2 text-sm text-dim">
          {used} slots in use, kept: <T cap={CAPS['Card.kept#compact']}>{card.kept}</T>
        </p>
        {card.changesSinceLastReading.length > 0 ? (
          <p className="mt-2 inline-flex items-center gap-1.5 text-sm font-bold text-alert">
            <Glyph level="alert" size={14} /> Changed since the last reading
          </p>
        ) : null}
        <p className="mt-3">
          <a className={`${LINK} inline-flex min-h-11 items-center`} href={href.cards(card.serial)}>
            Open the card
          </a>
        </p>
      </div>
    </li>
  );
}

/** Cards that hold keys of a root but have no place in the inventory. Read from the roots. */
function Unlisted() {
  const roots = useRoots();
  const findings = useFindings();
  return (
    <Load res={roots} what="the keys that sit on cards">
      {(d) => {
        const sets = d.roots.flatMap((r) => (r.certificate?.subkeySets ?? []).filter((s) => s.cardSerial && !s.cardInInventory));
        const serials = Array.from(new Set(sets.map((s) => s.cardSerial))).sort();
        if (serials.length === 0) return null;
        return (
          <Sec title="Cards that hold keys but are not in the inventory" aside={plural(serials.length, 'card')}>
            <ul className="space-y-3">
              {serials.map((sn) => {
                const years = sets.filter((s) => s.cardSerial === sn).map((s) => s.year);
                const fix = findings.state === 'ready' ? findings.data.findings.find((f) => f.subject?.identifier === sn)?.fixCommand : undefined;
                return (
                  <li key={sn} className="border-2 border-dashed border-alert bg-panel p-4">
                    <p className="flex items-center gap-2 font-bold">
                      <Glyph level="alert" size={16} /> Card{' '}
                      <span className="font-mono">
                        <T cap={CAPS['Card.serial']}>{sn}</T>
                      </span>
                    </p>
                    <p className="mt-1 text-[0.9375rem]">
                      Subkey sets of {years.join(', ')} sit on it. ritueel cannot read it: it is not registered.{' '}
                      <a className={LINK} href={href.cards(sn)}>
                        More about this card
                      </a>
                    </p>
                    <div className="mt-3 max-w-[40rem]">
                      {fix || isSerial(sn) ? <Cmd label={`Add card ${safeString(sn, 20)} to the inventory`}>{fix || `ritueel card adopt --card ${sn} --plan-only`}</Cmd> : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          </Sec>
        );
      }}
    </Load>
  );
}

function Inventory() {
  const cards = useCards();
  return (
    <Page
      kicker="Cards"
      title="Your cards, slot by slot"
      lede={<p>The inventory lists every card ritueel knows, and what each of its slots is used for.</p>}
    >
      <Load
        res={cards}
        what="the cards"
        isEmpty={(d) => d.cards.length === 0}
        empty={
          <Empty title="No cards in the inventory yet.">
            <p>ritueel learns about a card when you add it. Until then it cannot tell you what a card holds, and it cannot plan a ceremony that needs one. A bundle whose roots are all in the cloud needs no card.</p>
            <p>
              <a className={LINK} href={href.plan('add-card')}>
                Make a plan to add a card
              </a>
            </p>
          </Empty>
        }
      >
        {(d) => {
          const list = d.cards;
          const by = (k: CardKind) => list.filter((c) => c.kind === k).length;
          const changed = list.filter((c) => c.changesSinceLastReading.length > 0).length;
          return (
            <>
              <div className="flex flex-wrap items-center justify-between gap-x-8 gap-y-2 border border-line bg-panel px-4 py-3">
                <p>
                  <strong>{plural(list.length, 'card')}:</strong> {by(CardKind.ROOT)} root, {by(CardKind.DAY_TO_DAY)} day-to-day, {by(CardKind.SERVER) > 0 ? `${by(CardKind.SERVER)} server, ` : ''}{by(CardKind.REHEARSAL)} rehearsal.{' '}
                  {changed > 0 ? (
                    <span className="inline-flex items-center gap-1.5 font-bold text-alert">
                      <Glyph level="alert" size={14} /> {changed} changed since the last reading.
                    </span>
                  ) : null}
                </p>
                <p className="text-sm text-dim">Inventory written {ymd(d.inventoryWrittenAt)}</p>
              </div>
              <Sec title="How to read a card">
                <Explain term="A slot">
                  is one place on a card that can hold one key. A card has six rows of four PIV slots: row 1 is the card&apos;s own jobs, and each row below belongs to one root, of this bundle or of another bundle of the
                  same holder that shares the pair (X.509 root, OpenPGP primary, SSH CA, one empty). The OpenPGP keys and the passkeys sit beside the grid. A row of another bundle of the
                  same holder is declared in this card&apos;s file and drawn as OTHER, with no key digest. An occupied row that nobody declared is a finding. Proposed: the shape
                  &quot;use: other-bundle&quot; is proposed in record 0003 (issue 11).
                </Explain>
                <Legend />
                <p className="mt-2 text-sm text-dim">Each tile below shows its 24 PIV slots in miniature. Open a card to see every slot and what it is for.</p>
              </Sec>
              <Sec title="The inventory">
                <ul className="grid gap-4 lg:grid-cols-2">
                  {list.map((c) => (
                    <CardTile key={c.serial} card={c} />
                  ))}
                </ul>
              </Sec>
              <Unlisted />
            </>
          );
        }}
      </Load>
    </Page>
  );
}

export function Cards({ serial }: { serial?: string }): ReactNode {
  return serial ? <CardPage serial={serial} /> : <Inventory />;
}

