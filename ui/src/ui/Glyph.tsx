import { Severity } from '../gen/ritueel/local/v1alpha1/common_pb';

export type SevKey = 'critical' | 'alert' | 'notice' | 'info' | 'ok';

export function sevKey(s: Severity): SevKey {
  switch (s) {
    case Severity.CRITICAL:
      return 'critical';
    case Severity.ALERT:
      return 'alert';
    case Severity.NOTICE:
      return 'notice';
    default:
      return 'info';
  }
}

export const SEV_WORD: Record<SevKey, string> = {
  critical: 'Critical',
  alert: 'Alert',
  notice: 'Notice',
  info: 'Info',
  ok: 'OK',
};

export const SEV_ORDER: Severity[] = [Severity.CRITICAL, Severity.ALERT, Severity.NOTICE];

/** Classes by level, written out so Tailwind sees them. */
export const SEV_TEXT: Record<SevKey, string> = {
  critical: 'text-critical',
  alert: 'text-alert',
  notice: 'text-notice',
  info: 'text-info',
  ok: 'text-ok',
};

export const SEV_EDGE: Record<SevKey, string> = {
  critical: 'border-l-critical',
  alert: 'border-l-alert',
  notice: 'border-l-notice',
  info: 'border-l-info',
  ok: 'border-l-ok',
};

const COLOR: Record<SevKey, string> = {
  critical: 'var(--mui-palette-severity-critical)',
  alert: 'var(--mui-palette-severity-alert)',
  notice: 'var(--mui-palette-severity-notice)',
  info: 'var(--mui-palette-severity-info)',
  ok: 'var(--mui-palette-severity-ok)',
};

const KNOCKOUT = 'var(--mui-palette-background-paper)';

/**
 * One shape per level, so that a level can be told without colour:
 * diamond = critical, triangle = alert, disc = notice, ring = info, tick = ok.
 * It is always printed with the word (see Sev).
 */
export function Glyph({ level, size = 16 }: { level: SevKey; size?: number }) {
  const c = COLOR[level];
  const common = { width: size, height: size, viewBox: '0 0 16 16', 'aria-hidden': true, focusable: false, className: 'shrink-0' } as const;
  switch (level) {
    case 'critical':
      return (
        <svg {...common}>
          <path d="M8 .8 15.2 8 8 15.2.8 8Z" fill={c} />
          <path d="M8 4.2v5M8 11v1.4" stroke={KNOCKOUT} strokeWidth="1.8" />
        </svg>
      );
    case 'alert':
      return (
        <svg {...common}>
          <path d="M8 1.4 15.2 14H.8Z" fill={c} />
          <path d="M8 6v4M8 11.4v1.2" stroke={KNOCKOUT} strokeWidth="1.7" />
        </svg>
      );
    case 'notice':
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="7" fill={c} />
          <path d="M8 7v4.4M8 4.4v1.2" stroke={KNOCKOUT} strokeWidth="1.8" />
        </svg>
      );
    case 'info':
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.2" fill="none" stroke={c} strokeWidth="1.8" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <rect x="1" y="1" width="14" height="14" rx="1" fill={c} />
          <path d="m4.2 8.2 2.5 2.5 5-5.2" fill="none" stroke={KNOCKOUT} strokeWidth="1.8" />
        </svg>
      );
  }
}

/** Glyph and word together: the level is never colour alone. */
export function Sev({ level, label }: { level: SevKey; label?: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs font-bold tracking-wider uppercase ${SEV_TEXT[level]}`}>
      <Glyph level={level} size={14} />
      {label ?? SEV_WORD[level]}
    </span>
  );
}
