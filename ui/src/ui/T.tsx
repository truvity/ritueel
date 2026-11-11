import { groupFingerprint, safeParts, splitHexRuns } from '../lib/safe';

/**
 * Every string that comes from the bundle goes through here. It is written
 * as text by React; anything outside plain printable ASCII shows as a
 * visible U+XXXX escape, and the length is capped. A long run of hexadecimal
 * inside a sentence (a fingerprint, a digest) is set in the data face in
 * groups of four, as the Fp component does, and wraps between groups, so it
 * never pushes the page sideways and never breaks inside a group.
 */
export function T({ children, cap }: { children: string | undefined | null; cap?: number }) {
  const parts = safeParts(children, cap);
  return (
    <>
      {parts.map((p, i) =>
        p.escaped ? (
          <span
            key={i}
            title="A character that is not plain ASCII, shown as its code"
            className="mx-px rounded-xs border border-critical px-1 font-mono text-critical"
          >
            {p.text}
          </span>
        ) : (
          splitHexRuns(p.text).map((s, j) =>
            s.hex ? (
              <span key={`${i}.${j}`} className="font-mono">
                {groupFingerprint(s.text).join(' ')}
              </span>
            ) : (
              <span key={`${i}.${j}`}>{s.text}</span>
            ),
          )
        ),
      )}
    </>
  );
}
