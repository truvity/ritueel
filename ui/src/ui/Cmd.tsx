import { useId, useState } from 'react';
import Button from '@mui/material/Button';
import { isDemo } from '../api/client';
import { COMMAND_CAP, copyable, safeParts, safeString } from '../lib/safe';
import { useToast } from './Toast';

/**
 * The Copy control of a text the page shows (a command or a path). It writes
 * exactly what the screen shows: text that holds a character the page would
 * escape (a newline, a bidirectional override), or is longer than the page
 * shows, is not copied, and the control is off. The page never runs a command.
 * Used by `Cmd` and by `PathCopy`.
 */
export function useCopy(text: string): { canCopy: boolean; done: boolean; copy: () => Promise<void> } {
  const [done, setDone] = useState(false);
  const toast = useToast();
  const canCopy = copyable(text);
  const copy = async () => {
    if (!copyable(text)) return;
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      window.setTimeout(() => setDone(false), 1600);
      toast(isDemo ? 'Copied. This is a demo: the ritueel command line is not built yet, so a command is an example.' : 'Copied.');
    } catch {
      setDone(false);
      toast('Could not copy. Select the text and copy it by hand.');
    }
  };
  return { canCopy, done, copy };
}

/** The look of the Copy control, shared by `Cmd` and `PathCopy`. */
export const COPY_BUTTON_SX = { borderRadius: 0, color: 'text.primary', minWidth: 96 } as const;

/** The placeholders that a command holds (proto/README.md, rule 7). The page tells the reader to replace each one. */
const PLACEHOLDERS = ['REASON', 'TEXT'] as const;
export const placeholdersOf = (command: string): string[] => PLACEHOLDERS.filter((w) => new RegExp(`(^| )${w}( |$)`).test(command));

/**
 * A command as the program gave it. It is shown and can be copied; the page
 * never runs it and never reads it apart. It wraps at spaces only: each word
 * (an option such as --expires-in, a fingerprint) is one unit that does not
 * break, unless it is longer than the line. On a phone the Copy control sits
 * on its own line.
 *
 * The Copy control is named "Copy". The command is its description, never its
 * name, so no control of the page is named after an act (apply, sign, run,
 * confirm, revoke, publish). The group takes its name from `label`.
 *
 * A command that holds a placeholder (REASON or TEXT) is followed by the sentence
 * that names it and tells the reader to replace it.
 *
 * `note` draws, in the demo, the sentence that the command line is not built
 * yet. A table of commands passes `note={false}` and says it once after the
 * table.
 */
export function Cmd({ children, label = 'Type this in the terminal', note = true }: { children: string; label?: string; note?: boolean }) {
  const id = useId();
  const { canCopy, done, copy } = useCopy(children);
  return (
    <div className="max-w-[56ch]">
      <div className="flex min-w-0 flex-col border border-rule bg-sunk sm:flex-row sm:items-stretch" role="group" aria-label={safeString(label, 120)}>
        <div className="flex min-w-0 flex-1 items-start">
          <span aria-hidden className="self-stretch bg-ink px-2.5 py-2 font-mono text-sm font-bold text-bg">
            $
          </span>
          <code id={id} className="min-w-0 flex-1 px-3 py-2 font-mono text-[0.8125rem] leading-relaxed select-all">
            <Words text={children} />
          </code>
        </div>
        <Button
          onClick={copy}
          disabled={!canCopy}
          aria-label="Copy the command"
          aria-describedby={id}
          sx={COPY_BUTTON_SX}
          className="border-t border-line sm:border-t-0 sm:border-l"
        >
          {done ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {isDemo && note ? (
        <p className="mt-1 text-sm text-dim" role="note">
          Example only. The ritueel command line is not built yet.
        </p>
      ) : null}
      {placeholdersOf(children).map((word) => (
        <p key={word} className="mt-1 text-sm text-dim" role="note">
          Replace {word} before you use it. This page only shows the command.
        </p>
      ))}
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
