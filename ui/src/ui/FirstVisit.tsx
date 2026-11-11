import { href } from '../lib/route';
import { LearnLink } from './Page';

// Demo build only: what a first visitor needs before the first screen makes sense. The real
// program shows none of it (Start.tsx draws these behind isDemo, so the real build drops this
// file). The words stay plain and the sizes stay at 14 px or more. Nothing here asks for a
// secret or acts: the links go to other screens of the page, or to the site.

const LINK = 'inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4';

/** The lede of the Start screen in the demo: what ritueel is, in one sentence that fits the first screen of a phone. */
export function DemoLede() {
  return (
    <p>
      ritueel helps you keep a root (the key that everything else trusts) safe: it shows what is due, builds a plan for each ceremony (one sitting at a terminal where the
      root is used), and keeps a history (the write-once record of every ceremony).
    </p>
  );
}

/** A short path through the demo. It needs no data, so it is drawn in every page state. */
export function StartHere() {
  const steps: { to: string; name: string; what: string }[] = [
    { to: href.roots(), name: 'Roots', what: 'your keys.' },
    { to: href.findings(), name: 'Findings', what: 'what is wrong.' },
    { to: href.plan(), name: 'Make a plan', what: 'the steps and an example command.' },
  ];
  // The three links come first and the notes after them: on a phone (390x844) the links must lie above the fixed bottom bar on the
  // first load, and the notes can be read below them. Each line of the path is short enough to stay on one line on a phone (the
  // link is 44 px high, a wrapped note would add a second line to each), so what the plan does and does not do sits in the notes.
  return (
    <section aria-labelledby="start-here-h" className="max-w-[70ch] border-l-4 border-accent bg-sunk px-4 py-3">
      <h2 id="start-here-h" className="text-base font-bold">
        Start here
      </h2>
      <p className="mt-2 text-[0.9375rem]">Try these three, in order:</p>
      <ol className="mt-1 list-decimal pl-6 text-[0.9375rem]">
        {steps.map((s) => (
          <li key={s.to}>
            <a className={LINK} href={s.to}>
              {s.name}
            </a>
            : {s.what}
          </li>
        ))}
      </ol>
      <p className="mt-2 text-[0.9375rem]">Everything on this page is made up. Nothing runs here, and the ritueel command line is not built yet.</p>
      <p className="mt-1 text-[0.9375rem]">
        The bar above has two demo switches. Example bundle changes the made-up keys (a bundle is the directory that holds everything ritueel knows about one set of
        keys). Page state shows each screen when the bundle is empty, cannot be read, or has not answered yet.
      </p>
      <p className="mt-1 flex flex-wrap gap-x-6">
        <LearnLink path="/learn/what-is-a-root/">Read what a root is</LearnLink>
        <LearnLink path="/glossary/">All the words</LearnLink>
      </p>
    </section>
  );
}
