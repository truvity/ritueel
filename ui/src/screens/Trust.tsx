import type { ReactNode } from 'react';
import { TrustCheckResult, type ListTrustFilesResponse, type TrustFile } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { isDemo } from '../api/client';
import { useTrustFiles } from '../api/hooks';
import { CAPS } from '../lib/caps';
import { daysBetween, inDays, ymd } from '../lib/format';
import { href } from '../lib/route';
import { safeString } from '../lib/safe';
import { TRUST_CHECK_WORD, TRUST_KIND_WORD } from '../lib/words';
import { Cmd } from '../ui/Cmd';
import { DataTable, type Column } from '../ui/DataTable';
import { Glyph, type SevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { ReadTime } from '../ui/ReadTime';
import { Empty, Load } from '../ui/Sec';
import { T } from '../ui/T';

// Trust set: what outsiders install now, the check of each file and the
// command that verifies it. One table, one line for each file of the newest
// trust set, with the detail of its check under its name and its command in the
// last column. Above the table, in one strip, the facts of the set. The page only shows: every
// command is text with a Copy control, and the page checks nothing itself.

function levelOf(r: TrustCheckResult): SevKey {
  switch (r) {
    case TrustCheckResult.PASSED:
      return 'ok';
    case TrustCheckResult.PASSED_WITH_WARNING:
      return 'alert';
    case TrustCheckResult.FAILED:
      return 'critical';
    default:
      return 'info';
  }
}

function makeColumns(d: ListTrustFilesResponse): Column<TrustFile>[] {
  return [
    {
      key: 'file',
      header: 'File',
      width: 22,
      render: (f) => (
        <>
          <span className="font-mono font-semibold [overflow-wrap:anywhere]">
            <T cap={CAPS['TrustFile.name']}>{f.name}</T>
          </span>
          <span className="block font-mono text-[0.8125rem] text-dim [overflow-wrap:anywhere]">
            <T cap={CAPS['TrustFile.path']}>{f.path}</T>
          </span>
          {f.checkDetail ? (
            <span className="mt-1 block max-w-[56ch] text-dim">
              <T cap={CAPS['TrustFile.check_detail']}>{f.checkDetail}</T>
            </span>
          ) : null}
        </>
      ),
    },
    { key: 'kind', header: 'Kind', width: 7, render: (f) => TRUST_KIND_WORD[f.kind] },
    {
      key: 'ends',
      header: 'Ends',
      width: 7,
      render: (f) =>
        f.validUntil ? (
          <>
            {ymd(f.validUntil)}
            <span className="block text-dim">{inDays(daysBetween(d.readAt, f.validUntil))}</span>
          </>
        ) : (
          <span className="text-dim">-</span>
        ),
    },
    {
      key: 'check',
      header: 'Check',
      width: 7,
      render: (f) => (
        <span className="inline-flex items-start gap-1.5">
          <span className="mt-[3px]">
            <Glyph level={levelOf(f.checkResult)} size={14} />
          </span>
          <span>{TRUST_CHECK_WORD[f.checkResult]}</span>
        </span>
      ),
    },
    {
      key: 'verify',
      header: 'Verify',
      width: 38,
      render: (f) =>
        f.verifyCommand ? (
          <Cmd label={`Check this file in the terminal: ${safeString(f.name, CAPS['TrustFile.name#cmd'])}`} note={false} wide>
            {f.verifyCommand}
          </Cmd>
        ) : (
          <span className="block max-w-[56ch] text-dim">No command: a personal bundle has no root list to check this file against.</span>
        ),
    },
  ];
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 gap-x-2">
      <dt className="text-dim">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

/** The facts of the newest set, in one strip above the table. */
function Facts({ d }: { d: ListTrustFilesResponse }) {
  const passed = d.files.filter((f) => f.checkResult === TrustCheckResult.PASSED).length;
  const warned = d.files.filter((f) => f.checkResult === TrustCheckResult.PASSED_WITH_WARNING).length;
  return (
    <section aria-label="Facts of the trust set" className="mb-4 min-w-0 gap-x-8 border border-rule bg-panel px-4 py-3 lg:flex lg:justify-between">
      <dl className="flex min-w-0 flex-wrap content-start gap-x-8 gap-y-1 text-[0.9375rem]">
        <Fact label="Number">{d.trustSequence}</Fact>
        <Fact label="Name">
          <T cap={CAPS['ListTrustFilesResponse.set_name']}>{d.setName}</T>
        </Fact>
        <Fact label="Written">{ymd(d.writtenAt)}</Fact>
        {d.ceremonyId ? (
          <Fact label="By ceremony">
            <a className="font-semibold text-accent underline underline-offset-4" href={href.history(d.ceremonyId)}>
              <T cap={CAPS['Ceremony.id']}>{d.ceremonyId}</T>
            </a>
          </Fact>
        ) : null}
        <Fact label="Files listed">{d.files.length}</Fact>
        <Fact label="Checks passed">
          {passed} of {d.files.length}
          {warned > 0 ? `, ${warned} with a warning` : ''}
        </Fact>
      </dl>
      <p className="mt-2 max-w-[56ch] shrink-0 text-[0.9375rem] lg:mt-0 lg:basis-[28rem]">Hosts and relying parties check these files with ritueel verify. The table lists the files that a person checks.</p>
    </section>
  );
}

export function Trust() {
  const res = useTrustFiles();
  const d = res.state === 'ready' ? res.data : undefined;
  return (
    <Page
      title="Trust set"
      line={
        d ? (
          <>
            {d.trustSequence > 0 ? (
              <>
                Set <T cap={CAPS['ListTrustFilesResponse.set_name']}>{d.setName}</T> {'·'} written {ymd(d.writtenAt)} {'·'}{' '}
              </>
            ) : null}
            <ReadTime ts={d.readAt} />
          </>
        ) : undefined
      }
    >
      <Load
        res={res}
        what="the trust set"
        isEmpty={(r) => r.files.length === 0}
        empty={
          <Empty title="No trust set yet.">
            <p>The first ceremony writes set 1.</p>
          </Empty>
        }
      >
        {(r) => (
          <div className="min-w-0">
            <Facts d={r} />
            <div className="min-w-0">
              <DataTable
                caption="Files of the newest trust set."
                rows={r.files}
                rowKey={(f) => f.path}
                columns={makeColumns(r)}
              />
              {isDemo && r.files.some((f) => f.verifyCommand) ? (
                <p className="mt-2 max-w-[56ch] text-sm text-dim">Example only. The ritueel command line is not built yet.</p>
              ) : null}
            </div>
          </div>
        )}
      </Load>
    </Page>
  );
}
