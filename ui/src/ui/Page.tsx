import type { ReactNode } from 'react';
import Typography from '@mui/material/Typography';
import { learnPathOk, learnUrl } from '../lib/finding';

/** The head of a screen. The heading takes focus when the screen changes. */
export function Page({ kicker, title, lede, aside, children }: { kicker: string; title: string; lede?: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <>
      <header className="mb-7 flex flex-wrap items-end justify-between gap-x-8 gap-y-3">
        <div className="min-w-0 max-w-[48rem]">
          <Typography variant="overline" component="p" color="text.secondary">
            {kicker}
          </Typography>
          <Typography variant="h1" component="h1" id="page-title" tabIndex={-1} className="mt-1 outline-none">
            {title}
          </Typography>
          {lede ? <div className="mt-3 text-[1.0625rem] text-dim">{lede}</div> : null}
        </div>
        {aside ? <div className="text-sm text-dim">{aside}</div> : null}
      </header>
      <div className="space-y-9">{children}</div>
    </>
  );
}

/** A link to a guide on the site. It says where it goes and opens a new tab. */
export function LearnLink({ path, children = 'Read why' }: { path: string; children?: ReactNode }) {
  // A path that is not a plain site path is not a link: it is shown as no guide at all.
  if (!learnPathOk(path)) return null;
  return (
    <a className="inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4" href={learnUrl(path)} target="_blank" rel="noopener noreferrer">
      {children} <span aria-hidden>{'↗'}</span>
      <span className="sr-only"> (a guide on ritueel.id, opens in a new tab)</span>
    </a>
  );
}
