import { useState } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { Severity } from '../gen/ritueel/local/v1alpha1/common_pb';
import { combine, useFindings, useGoalMap, useRoots, useSummary } from '../api/hooks';
import { plural } from '../lib/format';
import { href } from '../lib/route';
import { FindingCard } from '../ui/FindingCard';
import { Glyph, SEV_ORDER, SEV_WORD, sevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Load, Sec } from '../ui/Sec';

const LEVELS: { value: Severity; label: string }[] = [
  { value: Severity.UNSPECIFIED, label: 'All' },
  { value: Severity.NOTICE, label: 'Notice and above' },
  { value: Severity.ALERT, label: 'Alert and above' },
  { value: Severity.CRITICAL, label: 'Critical only' },
];

export function Findings() {
  const [min, setMin] = useState<Severity>(Severity.UNSPECIFIED);
  const findings = useFindings(min);
  const summary = useSummary();
  const goals = useGoalMap();
  const roots = useRoots();
  const rootList = roots.state === 'ready' ? roots.data.roots : undefined;
  const both = combine(findings, summary);
  return (
    <Page
      kicker="Findings"
      title="What is wrong or weak"
      lede={
        <p>
          A finding is something ritueel can see in your keys that you may want to fix. Each one says why it matters, and shows the command that fixes it. Some can be
          seen from the public key alone.
        </p>
      }
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span id="level-label" className="text-sm font-semibold">
          Show
        </span>
        <ToggleButtonGroup exclusive size="small" value={min} aria-labelledby="level-label" onChange={(_e, v: Severity | null) => v !== null && setMin(v)} sx={{ flexWrap: 'wrap' }}>
          {LEVELS.map((l) => (
            <ToggleButton key={l.value} value={l.value}>
              {l.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      </div>
      <Load
        res={both}
        what="the findings"
        isEmpty={([f, s]) => f.findings.length === 0 && min === Severity.UNSPECIFIED && (s.counts?.roots ?? 0) === 0}
        empty={
          <Empty title="Nothing to check yet, because the bundle holds no keys.">
            <p>A finding needs a key to be about. Bring in the key you already have, and ritueel will read it and tell you what it sees.</p>
            <p>
              <a className="font-semibold text-accent underline underline-offset-4" href={href.plan('adopt-key')}>
                Make a plan to adopt a key
              </a>
            </p>
          </Empty>
        }
      >
        {([f, s]) => {
          const counts = SEV_ORDER.map((sev) => ({ sev, n: f.findings.filter((x) => x.severity === sev).length }));
          return (
            <>
              <div className="flex flex-wrap items-center gap-x-5 gap-y-1" aria-label="Count by level">
                {counts.map(({ sev, n }) => (
                  <span key={sev} className="inline-flex items-center gap-1.5 text-sm">
                    <Glyph level={sevKey(sev)} size={16} />
                    <strong className="font-mono">{n}</strong> {SEV_WORD[sevKey(sev)].toLowerCase()}
                  </span>
                ))}
              </div>
              {f.findings.length === 0 ? (
                <Empty title={min === Severity.UNSPECIFIED ? 'No findings. Everything ritueel can check is in order.' : 'No finding at this level.'}>
                  <p>
                    ritueel read {plural(s.counts?.roots ?? 0, 'root')}, {plural(s.counts?.delegatedKeys ?? 0, 'delegated key')} and {plural(s.counts?.cards ?? 0, 'card')}.
                    {min !== Severity.UNSPECIFIED ? ' Choose All to see the lower ones.' : ''}
                  </p>
                </Empty>
              ) : (
                <Sec title={`${plural(f.findings.length, 'finding')}, worst first`}>
                  <ul className="space-y-4">
                    {[...f.findings]
                      .sort((a, b) => b.severity - a.severity)
                      .map((x) => (
                        <li key={x.id}>
                          <FindingCard f={x} goals={goals} roots={rootList} />
                        </li>
                      ))}
                  </ul>
                </Sec>
              )}
            </>
          );
        }}
      </Load>
    </Page>
  );
}
