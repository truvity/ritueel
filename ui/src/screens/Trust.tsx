import { TrustCheckResult, type TrustFile } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { combine, useSummary, useTrustFiles } from '../api/hooks';
import { daysBetween, inDays, plural, ymd } from '../lib/format';
import { href } from '../lib/route';
import { safeString } from '../lib/safe';
import { TRUST_CHECK_WORD, TRUST_KIND_WORD } from '../lib/words';
import { Cmd } from '../ui/Cmd';
import { Fp } from '../ui/Fp';
import { Glyph, type SevKey } from '../ui/Glyph';
import { Page } from '../ui/Page';
import { Empty, Explain, Load, Sec } from '../ui/Sec';
import { T } from '../ui/T';
import { CAPS } from '../lib/caps';

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

function File({ f, asOf }: { f: TrustFile; asOf: Parameters<typeof daysBetween>[0] }) {
  const lvl = levelOf(f.checkResult);
  const built = f.checkResult !== TrustCheckResult.NOT_RUN;
  const days = daysBetween(asOf, f.validUntil);
  return (
    <li className={`border-2 bg-panel ${built ? 'border-rule' : 'border-dashed border-rule'}`}>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1 border-b border-line bg-sunk px-4 py-2.5">
        <div className="min-w-0">
          <p className="font-mono text-xs font-semibold tracking-wider text-dim uppercase">{TRUST_KIND_WORD[f.kind]}</p>
          <h3 className="font-mono text-lg font-bold [overflow-wrap:anywhere]">
            <T cap={CAPS['TrustFile.name']}>{f.name}</T>
          </h3>
        </div>
        <p className="flex items-center gap-1.5 font-bold">
          <Glyph level={lvl} size={16} /> {TRUST_CHECK_WORD[f.checkResult]}
        </p>
      </div>
      <div className="space-y-3 p-4">
        <p className="max-w-[70ch]">
          <T cap={CAPS['TrustFile.check_detail']}>{f.checkDetail}</T>
        </p>
        <dl className="grid gap-x-8 gap-y-1 text-sm sm:grid-cols-2">
          <div className="flex gap-2">
            <dt className="text-dim">Path</dt>
            <dd className="font-mono [overflow-wrap:anywhere]">
              <T cap={CAPS['TrustFile.path']}>{f.path}</T>
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-dim">Trust sequence</dt>
            <dd className="font-mono">{f.trustSequence}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-dim">Built</dt>
            <dd className="font-mono">{ymd(f.builtAt)}</dd>
          </div>
          {f.validUntil ? (
            <div className="flex gap-2">
              <dt className="text-dim">Valid until</dt>
              <dd>
                <span className="font-mono">{ymd(f.validUntil)}</span> ({inDays(days)})
              </dd>
            </div>
          ) : null}
          {built ? (
            <div className="flex gap-2">
              <dt className="text-dim">Size</dt>
              <dd className="font-mono">{String(f.sizeBytes)} {f.sizeBytes === 1n ? 'byte' : 'bytes'}</dd>
            </div>
          ) : null}
        </dl>
        {built && f.sha256 ? (
          <div>
            <p className="text-sm text-dim">Digest of the file (SHA-256)</p>
            <Fp kind="Digest" value={f.sha256} className="text-xs" />
          </div>
        ) : null}
        <div className="grid gap-3 lg:grid-cols-2">
          {f.verifyCommand && built ? (
            <div className="min-w-0">
              <p className="mb-1 text-sm font-semibold">Check it again</p>
              <Cmd label={`Check ${safeString(f.name, CAPS['TrustFile.name#cmd'])}`}>{f.verifyCommand}</Cmd>
            </div>
          ) : null}
          {f.rebuildCommand ? (
            <div className="min-w-0">
              <p className="mb-1 text-sm font-semibold">{built ? 'Build it again' : 'Build it'}</p>
              <Cmd label={`Build ${safeString(f.name, CAPS['TrustFile.name#cmd'])}`}>{f.rebuildCommand}</Cmd>
            </div>
          ) : null}
        </div>
      </div>
    </li>
  );
}

export function Trust() {
  const files = useTrustFiles();
  const summary = useSummary();
  return (
    <Page
      kicker="Trust files"
      title="What other machines read to trust your roots"
      lede={<p>ritueel builds these files from your roots at a ceremony. You publish them where your machines and your users can read them. ritueel does not publish them for you.</p>}
    >
      <Explain term="Trust files">
        are the files outsiders read to decide whom to trust: the root list, the CA bundle, the revocation lists (CRLs), the SSH CA key list and the public OpenPGP keyring
        (the public certificates of the roots and their subkeys). They sit in numbered sets, trust/&lt;number&gt;/; the number is the trust sequence, and every change writes the next set
        beside the old one. A personal bundle has the person's public certificate only. ritueel makes the files; you publish them, and your release pipeline packages the keyring.
      </Explain>
      <Load
        res={combine(files, summary)}
        what="the trust files"
        isEmpty={([f]) => f.files.length === 0}
        empty={
          <Empty title="No trust files have been built yet.">
            <p>They are built at a ceremony, after a root exists. Until then there is nothing to publish, and nothing is wrong.</p>
            <p>
              <a className="font-semibold text-accent underline underline-offset-4" href={href.plan()}>
                Make a plan
              </a>
            </p>
          </Empty>
        }
      >
        {([f, s]) => {
          const notBuilt = f.files.filter((x) => x.checkResult === TrustCheckResult.NOT_RUN).length;
          return (
            <Sec title={`Trust sequence ${f.trustSequence}`} aside={`trust/${f.trustSequence}/, ${plural(f.files.length, 'file')}${notBuilt > 0 ? `, ${notBuilt} not built` : ''}`}>
              <ul className="space-y-4">
                {f.files.map((x) => (
                  <File key={x.path} f={x} asOf={s.asOf} />
                ))}
              </ul>
            </Sec>
          );
        }}
      </Load>
    </Page>
  );
}
