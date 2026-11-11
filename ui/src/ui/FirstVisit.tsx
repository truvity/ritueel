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
      root is used), and keeps a history (the record of every ceremony).
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
  // The defect was one of height: on a low window (a 360x740 phone) the third link lay behind the fixed bottom bar. So the fix keys on
  // the height, the query the bottom bar itself uses (it gets lower under 760 px). Under 760 px high the three links stand in one wrapping
  // row, without number markers (the row must stay on one line even in a wide fallback serif such as DejaVu Serif, whose width was estimated
  // from font metrics, not measured), and the note after each is hidden from the eye but kept for screen readers (sr-only, never display:none).
  // The sentence above still says "in order", and the links keep their text and order. On a window that is high enough, at any width, the notes stay as they were.
  return (
    <section aria-labelledby="start-here-h" className="max-w-[70ch] border-l-4 border-accent bg-sunk px-4 py-3">
      <h2 id="start-here-h" className="text-base font-bold">
        Start here
      </h2>
      <p className="mt-2 text-[0.9375rem]">Try these three, in order:</p>
      <ol className="mt-1 list-decimal pl-6 text-[0.9375rem] [@media(max-height:760px)]:flex [@media(max-height:760px)]:list-none [@media(max-height:760px)]:flex-wrap [@media(max-height:760px)]:gap-x-4 [@media(max-height:760px)]:pl-0">
        {steps.map((s) => (
          <li key={s.to}>
            <a className={LINK} href={s.to}>
              {s.name}
            </a>
            <span className="[@media(max-height:760px)]:sr-only">: {s.what}</span>
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
