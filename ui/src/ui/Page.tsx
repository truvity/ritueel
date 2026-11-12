import type { ReactNode } from 'react';
import Typography from '@mui/material/Typography';
import { learnPathOk, learnUrl } from '../lib/finding';

/**
 * The head of a screen: the title, and one line under it (the bundle and the
 * time of the read). The head is compact, so a screen keeps its height for the
 * list. The heading takes focus when the screen changes. A `lede` (the demo's
 * first words) stands at the right of the title from 1440 px, so it costs no row.
 */
export function Page({ title, line, aside, lede, children }: { title: string; line?: ReactNode; aside?: ReactNode; lede?: ReactNode; children: ReactNode }) {
  return (
    <>
      <header className="mb-2 flex flex-wrap items-end justify-between gap-x-8 gap-y-2">
        <div className="min-w-0">
          <Typography variant="h1" component="h1" id="page-title" tabIndex={-1} className="outline-none" sx={{ fontSize: { xs: '1.75rem', lg: '2rem' } }}>
            {title}
          </Typography>
          {line ? <p className="mt-0.5 max-w-[58ch] text-[0.9375rem] text-dim">{line}</p> : null}
        </div>
        {lede ? <div className="min-w-0 flex-1 basis-[40rem]">{lede}</div> : null}
        {aside ? <div className="text-sm text-dim">{aside}</div> : null}
      </header>
      <div className="space-y-4">{children}</div>
    </>
  );
}

/** A link to a guide on the site. It says where it goes and opens a new tab. */
export function LearnLink({ path, children = 'Read why' }: { path: string; children?: ReactNode }) {
  // A path that is not a plain site path is not a link: it is shown as no guide at all.
  if (!learnPathOk(path)) return null;
  return (
    <a className="inline-flex min-h-11 items-center lg:min-h-8 font-semibold text-accent underline underline-offset-4" href={learnUrl(path)} target="_blank" rel="noopener noreferrer">
      {children} <span aria-hidden>{'↗'}</span>
      <span className="sr-only"> (a guide on ritueel.id, opens in a new tab)</span>
    </a>
  );
}
