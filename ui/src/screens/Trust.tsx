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
import { SPLIT_COLUMNS } from '../ui/SplitView';
import { T } from '../ui/T';

// Trust set: what outsiders install now, the check of each file and the
// command that verifies it. One table, one line for each file of the newest
// trust set, and under each line the detail of its check and its command. At
// the right (from 1440 px) the facts of the set. The page only shows: every
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
      render: (f) => (
        <>
          <span className="font-mono font-semibold [overflow-wrap:anywhere]">
            <T cap={CAPS['TrustFile.name']}>{f.name}</T>
          </span>
          <span className="block font-mono text-[0.8125rem] text-dim [overflow-wrap:anywhere]">
            <T cap={CAPS['TrustFile.path']}>{f.path}</T>
          </span>
        </>
      ),
    },
    { key: 'kind', header: 'Kind', width: 8, render: (f) => TRUST_KIND_WORD[f.kind] },
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
  ];
}

/** Under a line: what the check found, then the command that checks the file again. */
function FileDetail({ f }: { f: TrustFile }) {
  return (
    <div className="max-w-[70ch] space-y-1.5">
      {f.checkDetail ? (
        <p className="text-dim">
          <T cap={CAPS['TrustFile.check_detail']}>{f.checkDetail}</T>
        </p>
      ) : null}
      {f.verifyCommand ? (
        <Cmd label={`Check this file in the terminal: ${safeString(f.name, CAPS['TrustFile.name#cmd'])}`} note={false}>
          {f.verifyCommand}
        </Cmd>
      ) : (
        <p className="text-dim">No command: a personal bundle has no root list to check this file against.</p>
      )}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-dim">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

/** The facts of the newest set. */
function Facts({ d }: { d: ListTrustFilesResponse }) {
  const passed = d.files.filter((f) => f.checkResult === TrustCheckResult.PASSED).length;
  const warned = d.files.filter((f) => f.checkResult === TrustCheckResult.PASSED_WITH_WARNING).length;
  return (
    <aside aria-label="Facts of the trust set" className="min-w-0 border border-rule bg-panel p-4">
      <h2 className="mb-2 border-b border-line pb-1 text-base font-bold">The set</h2>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-[0.9375rem]">
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
        <Fact label="Files">{d.files.length}</Fact>
        <Fact label="Checks passed">
          {passed} of {d.files.length}
          {warned > 0 ? `, ${warned} with a warning` : ''}
        </Fact>
      </dl>
      <p className="mt-3 max-w-[70ch] text-[0.9375rem]">Hosts and relying parties check these files with ritueel verify. The commands are in the table.</p>
    </aside>
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
          <div className={`grid gap-6 ${SPLIT_COLUMNS}`}>
            <div className="min-w-0">
              <DataTable
                caption="Files of the newest trust set."
                rows={r.files}
                rowKey={(f) => f.path}
                columns={makeColumns(r)}
                detail={(f) => <FileDetail f={f} />}
              />
              {isDemo && r.files.some((f) => f.verifyCommand) ? (
                <p className="mt-2 max-w-[70ch] text-sm text-dim">Example only. The ritueel command line is not built yet.</p>
              ) : null}
            </div>
            <Facts d={r} />
          </div>
        )}
      </Load>
    </Page>
  );
}
