import Button from '@mui/material/Button';
import { Intention } from '../gen/ritueel/local/v1alpha1/common_pb';
import type { Finding, Root } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import type { IntentionOption } from '../gen/ritueel/local/v1alpha1/plan_service_pb';
import { planHref, subjectHref } from '../lib/finding';
import { safeString } from '../lib/safe';
import { Cmd } from './Cmd';
import { SEV_EDGE, Sev, sevKey } from './Glyph';
import { LearnLink } from './Page';
import { T } from './T';
import { CAPS } from '../lib/caps';

const ACTION_LINK = 'inline-flex min-h-11 items-center font-semibold text-accent underline underline-offset-4';

/**
 * One finding: what is wrong, why it matters and who can do what until when
 * (the reason), the command that fixes it, and one next step. Used on Start,
 * on Findings and on the Key view, so a finding reads the same everywhere.
 */
export function FindingCard({
  f,
  goals,
  roots,
  showEvidence = true,
  compact = false,
}: {
  f: Finding;
  goals?: Map<Intention, IntentionOption>;
  /** The roots of the bundle, so "Open the key" opens the right one. */
  roots?: Root[];
  showEvidence?: boolean;
  /** The command and the next step fold away, except on a critical finding. */
  compact?: boolean;
}) {
  const k = sevKey(f.severity);
  const where = subjectHref(f.subject, roots);
  const goal = f.fixIntention !== Intention.UNSPECIFIED ? goals?.get(f.fixIntention) : undefined;
  const blocked = goal && !goal.applicable;

  const fix = (
    <>
      {f.fixCommand ? (
        <div className="mt-3">
          <p className="mb-1 text-sm font-semibold">The command that fixes it</p>
          <Cmd label={`Fix for: ${safeString(f.title, CAPS['Finding.title#fix'])}`}>{f.fixCommand}</Cmd>
        </div>
      ) : null}
      <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-0">
        {goal && blocked ? (
          <p className="my-1 max-w-[60ch] border-l-4 border-line pl-3 text-sm">
            <strong>No plan for this yet.</strong> <T cap={CAPS['IntentionOption.not_applicable_reason']}>{goal.notApplicableReason}</T>
          </p>
        ) : f.fixIntention !== Intention.UNSPECIFIED ? (
          <span className="my-1">
            <Button variant={k === 'critical' ? 'contained' : 'outlined'} href={planHref(f.fixIntention)}>
              Make a plan
            </Button>
          </span>
        ) : (
          <p className="my-1 text-sm text-dim">You run this one by hand: copy the command above.</p>
        )}
        {where ? (
          <a className={ACTION_LINK} href={where.href}>
            {where.label}
          </a>
        ) : null}
        {f.learnPath ? <LearnLink path={f.learnPath} /> : null}
      </div>
    </>
  );

  return (
    <article
      aria-label={safeString(f.title, 160)}
      className={`border border-line border-l-[6px] bg-panel ${SEV_EDGE[k]} ${k === 'critical' ? 'border-y-2 border-r-2 border-y-critical border-r-critical' : ''}`}
    >
      <div className={compact ? 'px-4 pt-4 pb-1' : 'p-4'}>
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <Sev level={k} />
          <span className="text-sm text-dim">
            About <T cap={CAPS['Subject.label']}>{f.subject?.label}</T>
            {f.visibleFromPublicKey ? <span className="ml-2 border border-line px-1.5 text-xs">seen from the public key alone</span> : null}
          </span>
        </div>
        <h3 className="mt-2 text-lg leading-snug font-bold">
          <T cap={CAPS['Finding.title']}>{f.title}</T>
        </h3>
        <p className="mt-1.5 max-w-[68ch] text-[1rem]">
          <T cap={CAPS['Finding.reason']}>{f.reason}</T>
        </p>
        {showEvidence && f.evidence.length > 0 ? (
          <details open={k === 'critical'} className="mt-1 max-w-[68ch]">
            <summary className="flex min-h-11 cursor-pointer items-center text-sm font-semibold text-accent">What ritueel saw ({f.evidence.length})</summary>
            <ul className="mt-1.5 list-disc space-y-1 pl-5 text-sm">
              {f.evidence.map((e, i) => (
                <li key={i}>
                  <T cap={CAPS['Finding.evidence']}>{e}</T>
                </li>
              ))}
            </ul>
          </details>
        ) : null}
        {compact ? (
          <details open={k === 'critical'} className="mt-1">
            <summary className="flex min-h-11 cursor-pointer items-center text-sm font-semibold text-accent">The command and the next step</summary>
            <div className="pb-3">{fix}</div>
          </details>
        ) : (
          fix
        )}
      </div>
    </article>
  );
}
