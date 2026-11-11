import { groupFingerprint } from '../lib/safe';

/**
 * A key is its full fingerprint. Shown in groups of four, never shortened.
 * It wraps only between groups, so a line never ends inside a group. An
 * OpenPGP fingerprint (ten groups) has a wider gap in the middle, as it is
 * read in two halves. A value that is not hexadecimal is not a fingerprint
 * and is shown as safe text in one piece.
 */
export function Fp({ value, className = '' }: { value: string; className?: string }) {
  const groups = groupFingerprint(value);
  const half = groups.length === 10 ? 5 : -1;
  return (
    <span className={`font-mono text-sm leading-relaxed ${className}`} aria-label={`Fingerprint ${groups.join(' ')}`}>
      {groups.map((g, i) => (
        <span key={i} aria-hidden="true" className={`${i === 0 ? 'font-bold text-ink' : 'text-ink'} ${i + 1 === half ? 'mr-[1.1ch]' : ''}`}>
          {g}
          {i < groups.length - 1 ? ' ' : ''}
        </span>
      ))}
    </span>
  );
}
