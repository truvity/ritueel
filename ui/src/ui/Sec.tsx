import { useEffect, useState, type ReactNode } from 'react';
import Button from '@mui/material/Button';
import Skeleton from '@mui/material/Skeleton';
import Typography from '@mui/material/Typography';
import type { Loaded } from '../api/hooks';
import { Glyph } from './Glyph';
import { T } from './T';
import { Cmd } from './Cmd';

/** A labelled section: a heading on a double rule, then the body. */
export function Sec({ title, aside, children, id }: { title: string; aside?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <section aria-labelledby={id ? `${id}-h` : undefined} id={id} className="min-w-0">
      <header className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b-[3px] border-double border-rule pb-1.5">
        <Typography variant="h2" component="h2" id={id ? `${id}-h` : undefined}>
          {title}
        </Typography>
        {aside ? <div className="text-sm text-dim">{aside}</div> : null}
      </header>
      {children}
    </section>
  );
}

/** A short plain sentence that says what a thing is, set where it first appears. */
export function Explain({ term, children }: { term: string; children: ReactNode }) {
  return (
    <p className="mb-3 max-w-[70ch] border-l-4 border-accent bg-sunk px-3 py-2 text-[0.9375rem]">
      <strong>{term}</strong> {children}
    </p>
  );
}

// ---- the four states of a read ---------------------------------------------

function useAfter(ms: number): boolean {
  const [late, setLate] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => setLate(true), ms);
    return () => window.clearTimeout(t);
  }, [ms]);
  return late;
}

/** Waiting: ritueel has not answered yet. Nothing is shown as empty and nothing as failed. */
export function Waiting({ what }: { what: string }) {
  const late = useAfter(3500);
  return (
    <div role="status" aria-live="polite" aria-busy="true" className="space-y-3">
      <p className="text-dim">Reading {what} ...</p>
      <Skeleton variant="rectangular" height={64} sx={{ borderRadius: '2px' }} />
      <Skeleton variant="rectangular" height={64} sx={{ borderRadius: '2px' }} />
      {late ? <p className="text-sm text-dim">Still waiting for ritueel. It has not answered yet. This page shows nothing as empty or as failed until it does.</p> : null}
    </div>
  );
}

/** Failed: the read did not work. This is never drawn as empty, because the page does not know what is there. */
export function Failed({ what, message, retry }: { what: string; message: string; retry?: () => void }) {
  return (
    <div role="alert" className="border-2 border-critical bg-panel p-4">
      <p className="flex items-center gap-2 font-bold text-critical">
        <Glyph level="critical" size={18} /> Could not read {what}
      </p>
      <p className="mt-2 max-w-[70ch]">
        This is not the same as empty. ritueel could not read it, so this page cannot say what is there. Nothing was changed.
      </p>
      <p className="mt-2 max-w-[70ch] text-sm text-dim">
        What ritueel said: <T cap={300}>{message}</T>
      </p>
      <div className="mt-3 max-w-[40rem] space-y-3">
        <p className="text-sm">In a terminal, this reads the same bundle and prints the reason:</p>
        <Cmd label="Read the bundle in a terminal">ritueel status</Cmd>
        {retry ? (
          <Button variant="outlined" onClick={retry}>
            Try again
          </Button>
        ) : null}
      </div>
    </div>
  );
}

/** Empty: the read worked and there is nothing in it. It says what that means and what comes next. */
export function Empty({ title, children, command }: { title: string; children?: ReactNode; command?: { text: string; label?: string } }) {
  return (
    <div className="border-2 border-dashed border-rule bg-panel p-4">
      <p className="flex items-center gap-2 font-bold">
        <Glyph level="info" size={18} /> {title}
      </p>
      {children ? <div className="mt-2 max-w-[70ch] space-y-2">{children}</div> : null}
      {command ? (
        <div className="mt-3 max-w-[40rem]">
          <Cmd label={command.label}>{command.text}</Cmd>
        </div>
      ) : null}
    </div>
  );
}

/**
 * Draws a read in its four states. loaded: children. empty: `empty` when
 * `isEmpty` says the answer holds nothing. failed: the message and a retry.
 * waiting: a status line and placeholders.
 */
export function Load<T>({
  res,
  what,
  isEmpty,
  empty,
  children,
}: {
  res: Loaded<T>;
  what: string;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (res.state === 'loading') return <Waiting what={what} />;
  if (res.state === 'error') return <Failed what={what} message={res.message} retry={res.retry} />;
  if (isEmpty && empty && isEmpty(res.data)) return <>{empty}</>;
  return <>{children(res.data)}</>;
}
