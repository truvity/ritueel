import { SubkeyState, type Subkey } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { USAGE_LETTER } from '../lib/words';

// How a subkey is drawn, in the matrix, in the chart and in the register.
// Four marks, each a different shape, and always with a word somewhere near:
//   valid                solid
//   valid, replaced      notched corner, in the colour of the critical finding
//   expired              dashed outline
//   revoked              outline with a line through it

export type Mark = 'valid' | 'replaced' | 'expired' | 'revoked';

export function markOf(k: Subkey): Mark {
  if (k.state === SubkeyState.REVOKED) return 'revoked';
  if (k.state === SubkeyState.EXPIRED) return 'expired';
  return k.replacedBy ? 'replaced' : 'valid';
}

export const MARK_WORD: Record<Mark, string> = {
  valid: 'valid',
  replaced: 'valid, though replaced',
  expired: 'expired',
  revoked: 'revoked',
};

export const MARK_SHAPE: Record<Mark, string> = {
  valid: 'solid',
  replaced: 'notched corner',
  expired: 'dashed',
  revoked: 'struck through',
};

const STRIKE =
  'linear-gradient(to top right, transparent calc(50% - 1px), var(--mui-palette-text-secondary) calc(50% - 1px) calc(50% + 1px), transparent calc(50% + 1px))';

export function MarkBox({ mark, letter, size = 20 }: { mark: Mark; letter: string; size?: number }) {
  const base = 'inline-flex shrink-0 items-center justify-center font-mono text-xs font-bold leading-none';
  const style = { width: size, height: size };
  switch (mark) {
    case 'valid':
      return (
        <span aria-hidden className={`${base} bg-ink text-bg`} style={style}>
          {letter}
        </span>
      );
    case 'replaced':
      return (
        <span aria-hidden className={`${base} bg-critical text-bg`} style={{ ...style, clipPath: 'polygon(0 0, 62% 0, 100% 38%, 100% 100%, 0 100%)' }}>
          {letter}
        </span>
      );
    case 'revoked':
      return (
        <span aria-hidden className={`${base} border border-dim text-dim`} style={{ ...style, backgroundImage: STRIKE }}>
          {letter}
        </span>
      );
    default:
      return (
        <span aria-hidden className={`${base} border border-dashed border-dim text-dim`} style={style}>
          {letter}
        </span>
      );
  }
}

export function SubkeyMark({ k, size }: { k: Subkey; size?: number }) {
  return <MarkBox mark={markOf(k)} letter={USAGE_LETTER[k.usage] ?? '?'} size={size} />;
}

export function MarkLegend() {
  const items: Mark[] = ['valid', 'replaced', 'expired', 'revoked'];
  return (
    <ul className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm" aria-label="How a subkey is drawn">
      {items.map((m) => (
        <li key={m} className="inline-flex items-center gap-2">
          <MarkBox mark={m} letter="S" size={20} />
          <span>
            <strong>{MARK_WORD[m]}</strong> <span className="text-dim">({MARK_SHAPE[m]})</span>
          </span>
        </li>
      ))}
      <li className="text-dim">S sign, A authenticate, E encrypt</li>
    </ul>
  );
}
