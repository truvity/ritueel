import { useEffect, useRef, useState, type ReactNode } from 'react';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import FormControl from '@mui/material/FormControl';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormLabel from '@mui/material/FormLabel';
import Radio from '@mui/material/Radio';
import RadioGroup from '@mui/material/RadioGroup';
import type { Intention } from '../gen/ritueel/local/v1alpha1/common_pb';
import {
  QuestionKind,
  type Answer,
  type Plan as PlanMessage,
  type PlanStep,
  type Question,
  RunPlace,
  type SavePlanResponse,
} from '../gen/ritueel/local/v1alpha1/plan_service_pb';
import { isDemo, plans } from '../api/client';
import { messageOf, useCall, useGoalMap, useIntentions } from '../api/hooks';
import { intentionFromSlug, INTENTION_SLUG } from '../lib/finding';
import { ymd } from '../lib/format';
import { href } from '../lib/route';
import { safeString } from '../lib/safe';
import { BUNDLE_ACTION_WORD, REQUIREMENT_WORD, onPlace } from '../lib/words';
import { Cmd } from '../ui/Cmd';
import { Fp } from '../ui/Fp';
import { Glyph } from '../ui/Glyph';
import { LearnLink, Page } from '../ui/Page';
import { Empty, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';
import { useToast } from '../ui/Toast';

const LINK = 'font-semibold text-accent underline underline-offset-4';

// The wizard: goal, choices, plan, save. It builds a plan in memory, shows its
// steps, its digest and the exact command to run in the terminal, and can save
// the plan file. It never confirms anything and never asks for a secret: the
// only answers are choices from a fixed list.

function Stepper({ current }: { current: 1 | 2 | 3 | 4 }) {
  const names = ['Goal', 'Choices', 'Plan', 'Save'];
  return (
    <ol aria-label="Where you are in the wizard" className="mb-6 flex flex-wrap gap-x-1 gap-y-1">
      {names.map((n, i) => {
        const at = i + 1;
        const state = at < current ? 'done' : at === current ? 'now' : 'next';
        return (
          <li
            key={n}
            aria-current={state === 'now' ? 'step' : undefined}
            className={`flex min-h-9 items-center gap-1.5 border px-3 text-sm ${state === 'now' ? 'border-ink bg-ink font-bold text-bg' : state === 'done' ? 'border-rule' : 'border-line text-dim'}`}
          >
            {state === 'done' ? <Glyph level="ok" size={14} /> : <span className="font-mono">{at}</span>}
            <span>{n}</span>
            <span className="sr-only">{state === 'done' ? ' (done)' : state === 'now' ? ' (you are here)' : ' (next)'}</span>
          </li>
        );
      })}
    </ol>
  );
}

// ---- 1. the goals ---------------------------------------------------------------

function Goals() {
  const res = useIntentions();
  return (
    <Page
      kicker="Make a plan"
      title="What do you want to do?"
      lede={
        <p>
          A plan is a list of steps, built here and run later in a terminal: on the offline system for a root on cards or in a key file, on your workstation for a cloud
          root. Making a plan changes nothing. It ends with a preview of the steps, a digest, and the exact command you run there.
        </p>
      }
    >
      <Stepper current={1} />
      <Load res={res} what="the goals" isEmpty={(d) => d.options.length === 0} empty={<Empty title="No goal is available.">ritueel offered no goal for this bundle.</Empty>}>
        {(d) => (
          <ul className="grid gap-4 lg:grid-cols-2">
            {[...d.options]
              .sort((a, b) => Number(b.applicable) - Number(a.applicable) || Number(b.recommended) - Number(a.recommended))
              .map((o) => (
                <li
                  key={o.intention}
                  className={`flex flex-col border-2 bg-panel p-4 ${o.applicable ? 'border-rule' : 'border-dashed border-line'}`}
                  aria-disabled={!o.applicable || undefined}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className={`text-xl leading-tight font-bold ${o.applicable ? '' : 'text-dim'}`}>
                      <T cap={80}>{o.title}</T>
                    </h2>
                    {o.recommended ? <span className="border border-accent bg-sunk px-1.5 font-mono text-xs font-bold tracking-wider text-accent uppercase">Suggested</span> : null}
                  </div>
                  <p className={`mt-1 ${o.applicable ? '' : 'text-dim'}`}>
                    <T cap={240}>{o.sentence}</T>
                  </p>
                  <p className="mt-1 text-sm text-dim">
                    Usually <T cap={40}>{o.typicalTime}</T>.
                  </p>
                  {o.recommended && o.recommendedReason ? (
                    <p className="mt-2 text-[0.9375rem]">
                      <strong>Why now:</strong> <T cap={200}>{o.recommendedReason}</T>
                    </p>
                  ) : null}
                  <div className="mt-auto pt-3">
                    {o.applicable ? (
                      <Button variant={o.recommended ? 'contained' : 'outlined'} href={href.plan(INTENTION_SLUG[o.intention])}>
                        Choose this
                      </Button>
                    ) : (
                      <p className="flex gap-2 border-l-4 border-line pl-3 text-[0.9375rem]">
                        <span>
                          <strong>Not now.</strong> <T cap={240}>{o.notApplicableReason}</T>
                        </span>
                      </p>
                    )}
                  </div>
                </li>
              ))}
          </ul>
        )}
      </Load>
    </Page>
  );
}

// ---- 2. the choices -----------------------------------------------------------------

export function Questions({ questions, onSubmit }: { questions: Question[]; onSubmit: (a: Answer[]) => void }) {
  const [picked, setPicked] = useState<Record<string, string[]>>(() => Object.fromEntries(questions.map((q) => [q.id, [...q.defaultOptionIds]])));
  const [missing, setMissing] = useState<string[]>([]);
  const submit = () => {
    const none = questions.filter((q) => (picked[q.id] ?? []).length === 0).map((q) => q.id);
    setMissing(none);
    if (none.length === 0) onSubmit(questions.map((q) => ({ questionId: q.id, optionIds: picked[q.id] }) as Answer));
  };
  return (
    <form
      className="space-y-7"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      noValidate
    >
      <h2 className="sr-only">Your choices for this plan</h2>
      {questions.map((q) => {
        const multiple = q.kind === QuestionKind.MULTIPLE_CHOICE;
        const err = missing.includes(q.id);
        return (
          <FormControl key={q.id} component="fieldset" error={err} className="w-full border-2 border-line bg-panel p-4">
            <FormLabel component="legend" sx={{ color: 'text.primary', fontWeight: 700, fontSize: '1.125rem', '&.Mui-focused': { color: 'text.primary' } }}>
              <T cap={160}>{q.prompt}</T>
            </FormLabel>
            {q.help ? (
              <p className="mt-1 max-w-[68ch] text-[0.9375rem] text-dim">
                <T cap={300}>{q.help}</T>
              </p>
            ) : null}
            {multiple ? (
              <div className="mt-2 flex flex-col">
                {q.options.map((o) => (
                  <FormControlLabel
                    key={o.id}
                    control={
                      <Checkbox
                        checked={(picked[q.id] ?? []).includes(o.id)}
                        onChange={(e) =>
                          setPicked((p) => ({ ...p, [q.id]: e.target.checked ? [...(p[q.id] ?? []), o.id] : (p[q.id] ?? []).filter((x) => x !== o.id) }))
                        }
                      />
                    }
                    label={<Option label={o.label} description={o.description} />}
                  />
                ))}
              </div>
            ) : (
              // The value in the markup is the place of the option in the list, never the id from the data; the id stays in the state.
              <RadioGroup
                className="mt-2"
                value={String(q.options.findIndex((o) => o.id === (picked[q.id] ?? [])[0]))}
                onChange={(e) => {
                  const chosen = q.options[Number(e.target.value)];
                  if (chosen) setPicked((p) => ({ ...p, [q.id]: [chosen.id] }));
                }}
              >
                {q.options.map((o, i) => (
                  <FormControlLabel key={o.id} value={String(i)} control={<Radio />} label={<Option label={o.label} description={o.description} />} />
                ))}
              </RadioGroup>
            )}
            {err ? (
              <p role="alert" className="mt-1 font-bold text-critical">
                Choose at least one.
              </p>
            ) : null}
          </FormControl>
        );
      })}
      <p className="max-w-[68ch] text-sm text-dim">These are choices from a list. There is nowhere to type a PIN or a passphrase, here or on any other screen.</p>
      <div className="flex flex-wrap gap-3">
        <Button type="submit" variant="contained">
          Show me the plan
        </Button>
        <Button variant="outlined" href={href.plan()}>
          Choose another goal
        </Button>
      </div>
    </form>
  );
}

function Option({ label, description }: { label: string; description: string }) {
  return (
    <span className="block">
      <span className="block font-semibold">
        <T cap={160}>{label}</T>
      </span>
      {description ? (
        <span className="block text-[0.9375rem] text-dim">
          <T cap={200}>{description}</T>
        </span>
      ) : null}
    </span>
  );
}

// ---- 3. the plan ------------------------------------------------------------------------

function Needs({ step, place }: { step: PlanStep; place: RunPlace }) {
  if (step.requirements.length === 0 && step.cardSerials.length === 0) return null;
  const where = onPlace(place);
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-sm">
      <span className="text-dim">{where.charAt(0).toUpperCase() + where.slice(1)}:</span>
      {step.requirements.map((r) => (
        <span key={r} className="border border-ink px-1.5 py-0.5 font-semibold">
          {REQUIREMENT_WORD[r]}
        </span>
      ))}
      {step.cardSerials.map((s) => (
        <a key={s} className="border border-line px-1.5 py-0.5 font-mono underline underline-offset-2" href={href.cards(s)}>
          card <T cap={20}>{s}</T>
        </a>
      ))}
    </div>
  );
}

export function PlanView({ plan }: { plan: PlanMessage }) {
  return (
    <div className="space-y-9">
      <div className="border-2 border-rule bg-panel p-4 sm:p-5">
        <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">The plan, built {ymd(plan.builtAt)}, in memory</p>
        <h2 className="mt-1 text-2xl leading-tight font-bold">
          <T cap={100}>{plan.title}</T>
        </h2>
        <p className="mt-2 max-w-[70ch] text-[1.0625rem]">
          <T cap={400}>{plan.summary}</T>
        </p>
        <div className="mt-4 border-t border-line pt-3">
          <p className="text-sm font-semibold">Its digest</p>
          <Fp kind="Digest" value={plan.digest} />
          <p className="mt-1 max-w-[70ch] text-sm text-dim">
            The digest is a hash of the whole plan. If a single step changes, the digest changes. You check it in the terminal where you run the plan. This page never
            asks you to type it, and it cannot confirm the plan.
          </p>
        </div>
        {isDemo ? (
          <p className="mt-3 border-l-4 border-accent bg-sunk px-3 py-2 text-sm">
            Demo: this plan is the same whatever you chose. The real program builds it from your answers.
          </p>
        ) : null}
      </div>

      <Sec title="Steps, in order" aside={`${plan.steps.length} steps`}>
        <ol className="border border-line bg-panel">
          {plan.steps.map((st, i) => (
            <li key={st.ordinal} className={`grid grid-cols-[2.25rem_minmax(0,1fr)] gap-3 p-4 ${i > 0 ? 'border-t border-line' : ''}`}>
              <span className="flex h-8 w-8 items-center justify-center bg-ink font-mono text-sm font-bold text-bg">{st.ordinal}</span>
              <div className="min-w-0">
                <h3 className="text-lg leading-snug font-bold">
                  <T cap={100}>{st.title}</T>
                </h3>
                <p className="mt-0.5 max-w-[70ch]">
                  <T cap={400}>{st.detail}</T>
                </p>
                <p className="mt-1 text-sm">
                  <span className="text-dim">What changes:</span> <strong><T cap={120}>{st.whatChanges}</T></strong>
                </p>
                <Needs step={st} place={plan.runPlace} />
                {st.learnPath ? (
                  <p className="mt-1 text-sm">
                    <LearnLink path={st.learnPath}>Read about this step</LearnLink>
                  </p>
                ) : null}
              </div>
            </li>
          ))}
        </ol>
      </Sec>

      {plan.bundleChanges.length > 0 ? (
        <Sec title="What changes in the bundle">
          <ul className="border border-line bg-panel">
            {plan.bundleChanges.map((c, i) => (
              <li key={c.path} className={`grid gap-x-4 gap-y-0.5 p-3 sm:grid-cols-[6rem_minmax(0,1fr)] ${i > 0 ? 'border-t border-line' : ''}`}>
                <span className="font-mono text-xs font-bold tracking-wider uppercase">{BUNDLE_ACTION_WORD[c.action]}</span>
                <span className="min-w-0">
                  <span className="block font-mono text-sm [overflow-wrap:anywhere]">
                    <T cap={120}>{c.path}</T>
                  </span>
                  <span className="block text-[0.9375rem] text-dim">
                    <T cap={240}>{c.description}</T>
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </Sec>
      ) : null}

      <Sec title="The commands">
        <div className="space-y-5">
          <div>
            <p className="mb-1 font-bold">To run it, {onPlace(plan.runPlace)}</p>
            <p className="mb-2 max-w-[70ch] text-sm text-dim">
              You type this in {plan.runPlace === RunPlace.OFFLINE_SYSTEM ? 'the terminal there' : 'a terminal ' + (plan.runPlace === RunPlace.WORKSTATION ? 'on your workstation' : 'where you run it')}, after you save the plan
              {plan.runPlace === RunPlace.OFFLINE_SYSTEM ? ' and carry it over' : ''}. <span className="font-mono">--dir</span> names the bundle{plan.runPlace === RunPlace.OFFLINE_SYSTEM ? ': there, give the place where you copied it' : ''}. The terminal asks for what the
              ceremony needs, such as a PIN and a touch on a card. This page never does.
            </p>
            <Cmd label={`Run the plan ${onPlace(plan.runPlace)}`}>{plan.runCommand}</Cmd>
          </div>
          <div>
            <p className="mb-1 font-bold">To build this same plan in a terminal instead</p>
            <Cmd label="Build the same plan in a terminal">{plan.equivalentCommand}</Cmd>
          </div>
        </div>
      </Sec>

      <SavePlan plan={plan} />
    </div>
  );
}

// ---- 4. save ---------------------------------------------------------------------------------

type Save = { state: 'idle' } | { state: 'saving' } | { state: 'error'; message: string } | { state: 'done'; data: SavePlanResponse };

function SavePlan({ plan }: { plan: PlanMessage }) {
  const [save, setSave] = useState<Save>({ state: 'idle' });
  const toast = useToast();
  const run = async () => {
    setSave({ state: 'saving' });
    try {
      const data = await plans.savePlan({ planId: plan.id, digest: plan.digest });
      setSave({ state: 'done', data });
      toast(data.written ? 'The plan was saved.' : 'This is a demo. Nothing was written.');
    } catch (e) {
      setSave({ state: 'error', message: messageOf(e) });
    }
  };
  return (
    <Sec title="Save the plan" id="save">
      {save.state !== 'done' ? (
        <div className="border border-line bg-panel p-4">
          <p className="max-w-[70ch]">
            Saving writes one file, the plan, to{' '}
            <span className="font-mono [overflow-wrap:anywhere]">
              <T cap={120}>{plan.savePath}</T>
            </span>{' '}
            in your bundle. The file is canonical JSON. It only describes the steps: it holds no key and no
            secret, and nothing runs until you run it {onPlace(plan.runPlace)}.
          </p>
          {isDemo ? <p className="mt-2 text-sm font-semibold">In this demo, saving writes nothing. It shows what it would write.</p> : null}
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button variant="contained" onClick={run} disabled={save.state === 'saving'}>
              {save.state === 'saving' ? 'Saving ...' : 'Save the plan'}
            </Button>
            <Button variant="outlined" href={href.plan()}>
              Start again
            </Button>
          </div>
          {save.state === 'saving' ? (
            <p role="status" className="mt-3 text-sm text-dim">
              Waiting for ritueel to answer. Nothing is shown as saved until it does.
            </p>
          ) : null}
          {save.state === 'error' ? (
            <div role="alert" className="mt-3 border-2 border-critical p-3">
              <p className="flex items-center gap-2 font-bold text-critical">
                <Glyph level="critical" size={16} /> The plan was not saved
              </p>
              <p className="mt-1 text-sm">
                What ritueel said: <T cap={300}>{save.message}</T>
              </p>
              <p className="mt-1 text-sm">Nothing was written. Try again, or build the plan in a terminal with the command above.</p>
            </div>
          ) : null}
        </div>
      ) : (
        <Saved data={save.data} place={plan.runPlace} />
      )}
    </Sec>
  );
}

function Lines({ text }: { text: string }) {
  const lines = text.split('\n');
  return (
    <pre className="border border-rule bg-sunk p-3 font-mono text-[0.8125rem] leading-relaxed [overflow-wrap:anywhere] whitespace-pre-wrap">
      {lines.map((l, i) => (
        <span key={i}>
          <T cap={200}>{l}</T>
          {i < lines.length - 1 ? '\n' : ''}
        </span>
      ))}
    </pre>
  );
}

/** What the page says about the stick. It follows where the plan says it runs, never a guess from the list of files. */
function stickSentence(place: RunPlace | undefined, stick: boolean): string {
  if (place === RunPlace.WORKSTATION) return 'This plan runs on your workstation, the computer this page is open on. No stick is needed.';
  if (place === RunPlace.OFFLINE_SYSTEM) {
    return stick
      ? 'The offline system is the computer where the ceremony runs. A USB stick carries the plan, in your bundle, from this computer to it.'
      : 'The offline system is the computer where the ceremony runs. The plan lists nothing to copy to it.';
  }
  return 'The plan does not say where it runs. Run it in the terminal where you run ritueel.';
}

export function Saved({ data, place }: { data: SavePlanResponse; place?: RunPlace }) {
  const written = data.written;
  const stick = data.copyToStick.length > 0;
  const box = useRef<HTMLDivElement>(null);
  // The button that was pressed has left the page: put the focus on the result, so a keyboard or screen-reader user is not dropped at the top.
  useEffect(() => {
    box.current?.scrollIntoView({ block: 'start' });
    box.current?.focus({ preventScroll: true });
  }, []);
  return (
    <div className="space-y-6">
      <div ref={box} id="saved-result" tabIndex={-1} role="status" className={`scroll-mt-20 border-2 p-4 outline-none ${written ? 'border-ok' : 'border-accent'} bg-panel`}>
        <p className="flex items-center gap-2 text-lg font-bold">
          <Glyph level={written ? 'ok' : 'notice'} size={18} /> {written ? 'The plan was saved.' : 'Nothing was written.'}
        </p>
        <p className="mt-1 max-w-[70ch]">
          <T cap={300}>{data.notice}</T>
        </p>
      </div>
      <dl className="grid gap-x-8 gap-y-2 border border-line bg-panel p-4 sm:grid-cols-[auto_1fr]">
        <dt className="text-dim">{written ? 'Written to' : 'Would be written to'}</dt>
        <dd className="font-mono [overflow-wrap:anywhere]">
          <T cap={120}>{data.bundlePath}</T>/<T cap={120}>{data.path}</T>
        </dd>
        <dt className="text-dim">Size</dt>
        <dd className="font-mono">{String(data.sizeBytes)} bytes</dd>
        <dt className="text-dim">Digest</dt>
        <dd>
          <Fp kind="Digest" value={data.digest} />
        </dd>
      </dl>
      <div>
        <h3 className="mb-2 text-lg font-bold">{written ? 'What the file holds' : 'What saving would write'}</h3>
        <Lines text={data.planFilePreview} />
        <p className="mt-2 max-w-[70ch] text-sm text-dim">
          The file is canonical JSON on one line. The excerpt above is laid out for reading; the SHA-256 of the file is the digest.
        </p>
      </div>
      <p className="max-w-[70ch] text-sm text-dim">
        {stickSentence(place, stick)}
      </p>
      <div className={`grid gap-6 ${stick ? 'lg:grid-cols-2' : ''}`}>
        <HandOver title="Copy to the offline system" items={data.copyToStick} />
        <HandOver title="Bring with you" items={data.bring} />
      </div>
      {data.whenBack ? (
        <p className="max-w-[70ch]">
          <strong>When you are back.</strong> <T cap={300}>{data.whenBack}</T>
        </p>
      ) : null}
      <div>
        <p className="mb-1 font-bold">Then, {onPlace(place)}</p>
        <Cmd label={`Run the plan ${onPlace(place)}`}>{data.runCommand}</Cmd>
      </div>
      <div className="flex flex-wrap gap-3">
        <Button variant="outlined" href={href.start()}>
          Back to Start
        </Button>
        <Button variant="outlined" href={href.plan()}>
          Make another plan
        </Button>
      </div>
    </div>
  );
}

function HandOver({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="border border-line bg-panel p-4">
      <h3 className="mb-2 text-lg font-bold">{title}</h3>
      <ul className="list-disc space-y-1.5 pl-5">
        {items.map((x, i) => (
          <li key={i}>
            <T cap={260}>{x}</T>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---- the wizard ------------------------------------------------------------------------------

function Refusal({ text }: { text: string }) {
  return (
    <Empty title="This goal cannot be planned now.">
      <p>
        <T cap={300}>{text}</T>
      </p>
      <p>
        <a className={LINK} href={href.plan()}>
          Choose another goal
        </a>
      </p>
    </Empty>
  );
}

function Build({ intention, answers }: { intention: Intention; answers: Answer[] }) {
  const res = useCall(`plan-build:${intention}:${JSON.stringify(answers.map((a) => [a.questionId, a.optionIds]))}`, () => plans.startPlan({ intention, answers }));
  return (
    <Load res={res} what="the plan">
      {(r) =>
        r.plan ? (
          <PlanView plan={r.plan} />
        ) : r.refusal ? (
          <Refusal text={r.refusal} />
        ) : (
          <Empty title="ritueel answered with no plan and no reason.">This should not happen. Nothing was changed. Go back and try again.</Empty>
        )
      }
    </Load>
  );
}

function Wizard({ intention, slug }: { intention: Intention; slug: string }) {
  const first = useCall(`plan-start:${slug}`, () => plans.startPlan({ intention }));
  const goals = useGoalMap();
  const goalTitle = goals?.get(intention)?.title;
  const [answers, setAnswers] = useState<Answer[] | null>(null);
  // The route stays the same between the choices and the plan, so a step change moves the focus itself: to the heading, at the top.
  const step = answers !== null ? 'plan' : 'choices';
  const seen = useRef(step);
  useEffect(() => {
    if (seen.current === step) return;
    seen.current = step;
    window.scrollTo(0, 0);
    document.getElementById('page-title')?.focus({ preventScroll: true });
  }, [step]);
  const stage: 1 | 2 | 3 | 4 = answers !== null ? 3 : first.state === 'ready' && first.data.plan ? 3 : 2;
  let body: ReactNode;
  if (answers !== null) body = <Build intention={intention} answers={answers} />;
  else
    body = (
      <Load res={first} what="the plan">
        {(r) => {
          if (r.refusal) return <Refusal text={r.refusal} />;
          if (r.plan) return <PlanView plan={r.plan} />;
          return <Questions questions={r.questions} onSubmit={setAnswers} />;
        }}
      </Load>
    );
  return (
    <Page
      kicker={goalTitle ? `Make a plan: ${safeString(goalTitle, 80)}` : 'Make a plan'}
      title={answers !== null || (first.state === 'ready' && first.data.plan) ? 'Your plan' : 'A few choices'}
      lede={
        answers !== null || (first.state === 'ready' && first.data.plan) ? (
          <p>This is a preview. Nothing has happened and nothing will until you run the plan in a terminal, where the plan says.</p>
        ) : (
          <p>ritueel needs a few choices from you to build the plan. You can change them and look again as often as you like.</p>
        )
      }
      aside={
        answers !== null ? (
          <button type="button" className={`${LINK} min-h-11 cursor-pointer bg-transparent`} onClick={() => setAnswers(null)}>
            Change my choices
          </button>
        ) : undefined
      }
    >
      <div>
        <Stepper current={stage} />
        {body}
      </div>
    </Page>
  );
}

export function Plan({ goal }: { goal?: string }) {
  if (!goal) return <Goals />;
  const intention = intentionFromSlug(goal);
  if (intention === undefined) {
    return (
      <Page kicker="Make a plan" title="That goal is not known">
        <Empty title="This page has no goal called that.">
          <p>
            <a className={LINK} href={href.plan()}>
              See the goals
            </a>
          </p>
        </Empty>
      </Page>
    );
  }
  return <Wizard key={goal} intention={intention} slug={goal} />;
}

