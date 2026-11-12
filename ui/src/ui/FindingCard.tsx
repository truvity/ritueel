import type { Finding } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { CAPS } from '../lib/caps';
import { hrefForObject } from '../lib/route';
import { OBJECT_KIND_WORD, SEVERITY_WORD } from '../lib/words';
import { safeString } from '../lib/safe';
import { Cmd } from './Cmd';
import { SEV_EDGE, Sev, sevKey } from './Glyph';
import { LearnLink } from './Page';
import { T } from './T';

/**
 * One finding: the level (glyph and word), what is wrong, why it matters, what
 * ritueel saw, the object it is about, a guide, and the command that deals with
 * it. The page shows the command and copies it; the terminal runs it.
 */
/** `commandNote` is false when a list of findings says once, after the list, that its commands are examples. */
export function FindingCard({ f, commandNote = true }: { f: Finding; commandNote?: boolean }) {
  const k = sevKey(f.severity);
  return (
    <article
      aria-label={safeString(f.title, CAPS['Finding.title'])}
      className={`max-w-[62ch] border border-line border-l-[6px] bg-panel px-4 py-3 ${SEV_EDGE[k]} ${k === 'critical' ? 'border-y-2 border-r-2 border-y-critical border-r-critical' : ''}`}
    >
      <Sev level={k} label={SEVERITY_WORD[f.severity] ?? 'finding'} />
      <h3 className="mt-1.5 text-lg leading-snug font-bold">
        <T cap={CAPS['Finding.title']}>{f.title}</T>
      </h3>
      <p className="mt-1.5">
        <T cap={CAPS['Finding.reason']}>{f.reason}</T>
      </p>
      {f.evidence.length > 0 ? (
        <ul aria-label="What ritueel saw" className="mt-1.5 list-disc space-y-0.5 pl-5 text-sm">
          {f.evidence.map((e, i) => (
            <li key={i}>
              <T cap={CAPS['Finding.evidence']}>{e}</T>
            </li>
          ))}
        </ul>
      ) : null}
      {f.object || f.learnPath ? (
        <p className="mt-1 flex flex-wrap items-center gap-x-5 gap-y-0 text-sm">
          {f.object ? (
            <span className="inline-flex min-h-11 items-center gap-1.5 lg:min-h-8">
              <span className="text-dim">About:</span>
              <span className="text-dim">{OBJECT_KIND_WORD[f.object.kind]}</span>
              <a className="font-semibold text-accent underline underline-offset-4" href={hrefForObject(f.object)}>
                <T cap={CAPS['ObjectRef.label']}>{f.object.label}</T>
              </a>
            </span>
          ) : null}
          {f.learnPath ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="text-dim">Why:</span>
              <LearnLink path={f.learnPath}>A guide on ritueel.id</LearnLink>
            </span>
          ) : null}
        </p>
      ) : null}
      {f.fixCommand ? (
        <div className="mt-2">
          <Cmd label={`Fix for: ${safeString(f.title, CAPS['Finding.title#fix'])}`} note={commandNote}>{f.fixCommand}</Cmd>
        </div>
      ) : null}
    </article>
  );
}
