import { useState } from 'react';
import Button from '@mui/material/Button';
import { isDemo } from '../api/client';
import { COMMAND_CAP, copyable, safeParts, safeString } from '../lib/safe';
import { useToast } from './Toast';

/**
 * A command as the program gave it. It is shown and can be copied; the page
 * never runs it and never reads it apart. It wraps at spaces only: each word
 * (an option such as --expires-in, a fingerprint) is one unit that does not
 * break, unless it is longer than the line. On a phone the copy button sits
 * on its own line.
 *
 * The copy button writes exactly what the screen shows. A command that holds a
 * character the page would escape (a newline, a bidirectional override), or is
 * longer than the page shows, is not copied: the button is off and says why.
 */
export function Cmd({ children, label = 'Run this in a terminal' }: { children: string; label?: string }) {
  const [done, setDone] = useState(false);
  const toast = useToast();
  const canCopy = copyable(children);
  const copy = async () => {
    if (!copyable(children)) return;
    try {
      await navigator.clipboard.writeText(children);
      setDone(true);
      window.setTimeout(() => setDone(false), 1600);
      toast(isDemo ? 'Copied. This is a demo: the ritueel command line is not built yet, so this command is an example.' : 'Copied.');
    } catch {
      setDone(false);
      toast('Could not copy. Select the command and copy it by hand.');
    }
  };
  return (
    <div>
      <div className="flex min-w-0 flex-col border border-rule bg-sunk sm:flex-row sm:items-stretch" role="group" aria-label={safeString(label, 120)}>
        <div className="flex min-w-0 flex-1 items-start">
          <span aria-hidden className="self-stretch bg-ink px-2.5 py-2 font-mono text-sm font-bold text-bg">
            $
          </span>
          <code className="min-w-0 flex-1 px-3 py-2 font-mono text-[0.8125rem] leading-relaxed select-all">
            <Words text={children} />
          </code>
        </div>
        <Button
          onClick={copy}
          disabled={!canCopy}
          aria-label={`Copy the command: ${safeString(children, 200)}`}
          sx={{ borderRadius: 0, color: 'text.primary', minWidth: 96 }}
          className="border-t border-line sm:border-t-0 sm:border-l"
        >
          {done ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {isDemo ? (
        <p className="mt-1 text-sm text-dim" role="note">
          Example only. The ritueel command line is not built yet.
        </p>
      ) : null}
      {canCopy ? null : (
        <p className="mt-1 text-sm text-dim" role="note">
          This command holds characters, or is longer than {COMMAND_CAP} characters, so the page will not copy it. Read it in the terminal.
        </p>
      )}
    </div>
  );
}

/** The command in words. A word never breaks inside, except one that is longer than the line (a fingerprint). */
function Words({ text }: { text: string }) {
  const parts = safeParts(text, COMMAND_CAP);
  return (
    <>
      {parts.map((p, i) =>
        p.escaped ? (
          <span key={i} className="mx-px rounded-xs border border-critical px-1 text-critical" title="A character that is not plain ASCII, shown as its code">
            {p.text}
          </span>
        ) : (
          p.text.split(/( +)/).map((w, j) =>
            w.trim() === '' ? (
              <span key={`${i}.${j}`}>{w}</span>
            ) : (
              <span key={`${i}.${j}`} className={w.length > 30 ? 'inline-block max-w-full [overflow-wrap:anywhere]' : 'inline-block whitespace-nowrap'}>
                {w}
              </span>
            )
          )
        ),
      )}
    </>
  );
}
