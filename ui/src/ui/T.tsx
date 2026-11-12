import { groupFingerprint, safeParts, splitHexRuns } from '../lib/safe';

const DATE = /\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}(?::\d{2})?(?: UTC)?)?/g;

function splitDates(text: string): { text: string; date: boolean }[] {
  const out: { text: string; date: boolean }[] = [];
  let at = 0;
  for (const m of text.matchAll(DATE)) {
    if (m.index > at) out.push({ text: text.slice(at, m.index), date: false });
    out.push({ text: m[0], date: true });
    at = m.index + m[0].length;
  }
  if (at < text.length || out.length === 0) out.push({ text: text.slice(at), date: false });
  return out;
}

/**
 * Every string that comes from the bundle goes through here. It is written
 * as text by React; anything outside plain printable ASCII shows as a
 * visible U+XXXX escape, and the length is capped. A long run of hexadecimal
 * inside a sentence (a fingerprint, a digest) is set in the data face in
 * groups of four, as the Fp component does, and wraps between groups, so it
 * never pushes the page sideways and never breaks inside a group. A date
 * (2026-11-24) or a date with a time (2026-11-24 11:10 UTC) in a sentence
 * stays on one line.
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
              <span key={`${i}.${j}`}>
                {splitDates(s.text).map((d, k) =>
                  d.date ? (
                    <span key={k} className="whitespace-nowrap">
                      {d.text}
                    </span>
                  ) : (
                    d.text
                  ),
                )}
              </span>
            ),
          )
        ),
      )}
    </>
  );
}
