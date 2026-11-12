import { useState } from 'react';
import Button from '@mui/material/Button';
import Popover from '@mui/material/Popover';
import { ApplicationUse, SlotState, SlotUse, type Card, type PivRow, type Slot } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { CAPS } from '../lib/caps';
import { Day } from './ReadTime';
import { safeString } from '../lib/safe';
import { PIN_WORD, SLOT_STATE_WORD, SLOT_USE_TAG, TOUCH_WORD } from '../lib/words';
import { Fp } from './Fp';
import { T } from './T';

// The slot grid of a card. Moved from the old Cards screen; the behaviour is the
// same: every slot that holds something is a button, Enter opens its details in
// a pop-up (`role="dialog"`, name starting "Slot"), Escape closes it and the
// focus goes back to the slot. An empty or spare slot is only drawn.

// ---- one slot -----------------------------------------------------------------
// Drawn by state in four ways, so colour is never the only cue:
//   in use: solid   reserved: dashed   spare: dotted   empty: thin line

export function slotClass(state: SlotState): string {
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

export function SlotInfo({ slot, group }: { slot: Slot; group: string }) {
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
        {slot.keyLabel ? (
          <>
            <dt className="text-dim">Key</dt>
            <dd>
              key <T cap={CAPS['Key.label']}>{slot.keyLabel}</T>
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
            <dd><Day ts={slot.bornAt} /></dd>
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
export function SlotCell({ slot, group, tagFallback }: { slot: Slot; group: string; tagFallback?: string }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const tag = SLOT_USE_TAG[slot.use] ?? tagFallback ?? '';
  const label = slotLabel(slot, tag, group);
  const body = (
    <>
      <span className="text-xs leading-none font-bold">
        <T cap={CAPS['Slot.id']}>{slot.id}</T>
      </span>
      <span className="truncate text-xs leading-none font-bold">{tag ? <T cap={20}>{tag}</T> : ' '}</span>
    </>
  );
  const cls = `flex min-h-11 min-w-0 flex-col justify-between px-1.5 py-1.5 font-mono ${slotClass(slot.state)}`;
  if (slot.state !== SlotState.USED && slot.state !== SlotState.RESERVED) {
    return (
      <div role="img" aria-label={label} className={cls}>
        {body}
      </div>
    );
  }
  return (
    <>
      <button
        type="button"
        aria-label={`${label}. Show its details.`}
        aria-haspopup="dialog"
        aria-expanded={anchor ? 'true' : undefined}
        onClick={(e) => setAnchor(e.currentTarget)}
        className={`${cls} w-full cursor-pointer text-left`}
      >
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

/** What each way of drawing a slot means. `spare` is listed only when the card has a spare slot. */
export function Legend({ spare = false }: { spare?: boolean }) {
  const items: [SlotState, string, string][] = [
    [SlotState.USED, 'in use', 'solid'],
    [SlotState.RESERVED, 'reserved', 'dashed'],
    ...(spare ? ([[SlotState.SPARE, 'spare', 'dotted']] as [SlotState, string, string][]) : []),
    [SlotState.EMPTY, 'empty', 'thin line'],
  ];
  return (
    <ul className="m-0 flex list-none flex-wrap gap-x-5 gap-y-1.5 p-0 text-sm" aria-label="How a slot is drawn">
      {items.map(([s, word, shape]) => (
        <li key={s} className="flex items-center gap-2">
          <span className={`inline-block h-4 w-7 ${slotClass(s)}`} aria-hidden />
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

export function PivGrid({ card }: { card: Card }) {
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

/** The 24 PIV slots in miniature. Drawn for a card in a list that has room for a picture only. */
export function MiniGrid({ card }: { card: Card }) {
  const rows = card.piv?.rows ?? [];
  return (
    <div aria-hidden className="grid shrink-0 grid-cols-4 content-start gap-[3px] self-start">
      {rows
        .flatMap((r) => r.slots)
        .map((s) => (
          <span key={s.id} className={`block h-2.5 w-2.5 ${slotClass(s.state)}`} style={{ borderWidth: s.state === SlotState.EMPTY ? 1 : 1.5 }} />
        ))}
    </div>
  );
}

function GroupTitle({ title, note }: { title: string; note: string }) {
  return (
    <h4 className="mb-1.5 flex flex-wrap items-baseline justify-between gap-x-3 text-[0.9375rem] font-bold">
      <span>{title}</span>
      <span className="sr-only">: </span>
      <span className="text-sm font-normal text-dim">{note}</span>
    </h4>
  );
}

function Piv({ card }: { card: Card }) {
  const states = (card.piv?.rows ?? []).flatMap((r) => r.slots.map((s) => s.state));
  const used = states.filter((s) => s === SlotState.USED).length;
  const reserved = states.filter((s) => s === SlotState.RESERVED).length;
  const inUse = card.piv?.use === ApplicationUse.IN_USE;
  return (
    <div className="min-w-0">
      <GroupTitle title="PIV, 24 slots in 6 rows" note={inUse ? `${used} in use, ${reserved} reserved` : 'not used'} />
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
  return (
    <div className="min-w-0">
      <GroupTitle title="OpenPGP, 3 slots" note="in use" />
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
  return (
    <div className="min-w-0">
      <GroupTitle title="Passkeys (FIDO2)" note={`${keys.filter((k) => k.state === SlotState.USED).length} of ${keys.length}`} />
      <ul className="m-0 list-none space-y-1 p-0">
        {keys.map((k) => (
          <li key={k.id}>
            <SlotCell slot={k} group="Passkey" tagFallback={`#${k.id}`} />
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The slots of one card for the panel: the PIV grid, the OpenPGP slots when the
 * card uses that application, the passkeys when it holds any, the legend and the
 * line that says a slot opens its details.
 */
export function SlotGrids({ card }: { card: Card }) {
  const all = [...(card.piv?.rows ?? []).flatMap((r) => r.slots), ...(card.openpgp?.slots ?? []), ...(card.fido2?.passkeys ?? [])];
  const spare = all.some((s) => s.state === SlotState.SPARE);
  return (
    <div className="space-y-3">
      <Piv card={card} />
      {card.openpgp?.use === ApplicationUse.IN_USE ? <OpenPgp card={card} /> : null}
      {(card.fido2?.passkeys ?? []).length > 0 ? <Passkeys card={card} /> : null}
      <Legend spare={spare} />
      <p className="text-sm text-dim">A slot opens its details.</p>
    </div>
  );
}
