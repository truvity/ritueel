import { learnUrl } from '../lib/finding';

// Demo build only: what a first visitor needs before the first screen makes
// sense. The real program shows none of it (the screens draw this behind
// isDemo, so the real build drops this file). Nothing here asks for a secret or
// acts. The two paragraphs stand side by side from 1440 px, so the lede is at
// most four lines and no line is longer than 70 characters.

/** The lede of To do in the demo. */
export function DemoLede() {
  return (
    <div className="grid gap-x-6 gap-y-1 text-[0.9375rem] min-[1440px]:grid-cols-2">
      <p className="max-w-[70ch]">
        ritueel helps you keep a root, the key that everything else trusts. This page only shows what is not applied yet. You write what you want in files, and you apply
        it in the terminal.
      </p>
      <p className="max-w-[70ch]">
        Use the bar above: change the example bundle, step through the five scenes of acme, or change the page state. The words are in the{' '}
        <a className="font-semibold text-accent underline underline-offset-4" href={learnUrl('/glossary/')} target="_blank" rel="noopener noreferrer">
          glossary
          <span className="sr-only"> (on ritueel.id, opens in a new tab)</span>
        </a>
        .
      </p>
    </div>
  );
}
